"""Configuration, path classification, counters and responses — no database."""
from __future__ import annotations

import pytest
from django.test import override_settings

from django_bouncer import policy
from django_bouncer.middleware import _helpers as H
from django_bouncer.middleware.rate_limit import burst_limit_for, match_rule

from .conftest import ATTACKER, CLIENT, rf


class TestTrusted:
    def test_loopback_always_trusted(self):
        assert H.is_trusted_ip("127.0.0.1")
        assert H.is_trusted_ip("::1")
        assert not H.is_trusted_ip(CLIENT)

    @override_settings(BOUNCER_TRUSTED_IPS="88.230.0.0/16, 5.5.5.5")
    def test_settings_trusted_cidr(self):
        assert H.is_trusted_ip(CLIENT)
        assert H.is_trusted_ip("5.5.5.5")
        assert not H.is_trusted_ip(ATTACKER)

    def test_trusted_cache_tracks_the_current_value(self):
        with override_settings(BOUNCER_TRUSTED_IPS=[ATTACKER]):
            assert H.is_trusted_ip(ATTACKER)
        with override_settings(BOUNCER_TRUSTED_IPS=[]):
            assert not H.is_trusted_ip(ATTACKER)

    @override_settings(BOUNCER_TRUSTED_IPS="not-an-address")
    def test_invalid_entry_is_ignored_not_fatal(self):
        assert not H.is_trusted_ip(CLIENT)


class TestPaths:
    @pytest.mark.parametrize(
        "path",
        [
            "/.well-known/security.txt",
            "/robots.txt",
            "/sitemap.xml",
            "/sitemap-products.xml",
            "/sw.js",
            "/manifest.json",
            "/ads.txt",
        ],
    )
    def test_default_exempt(self, path):
        assert policy.is_exempt_path(path)

    @override_settings(BOUNCER_EXEMPT_PATHS="/callback,/payments/webhook/")
    def test_project_exempt_paths(self):
        assert policy.is_exempt_path("/callback")
        assert policy.is_exempt_path("/callback/")
        assert policy.is_exempt_path("/payments/webhook/stripe/")
        assert policy.is_exempt_path("/en/payments/webhook/stripe/")

    @pytest.mark.parametrize(
        "path", ["/", "/products/x/", "/api/products/", "/accounts/login/"]
    )
    def test_not_exempt(self, path):
        assert not policy.is_exempt_path(path)

    def test_login_paths_with_lang_prefix(self):
        assert policy.is_login_path("/accounts/login/")   # from settings.LOGIN_URL
        assert policy.is_login_path("/en/accounts/login/")
        assert policy.is_login_path("/admin/login/")
        assert policy.is_login_path("/tr/accounts/login")
        assert not policy.is_login_path("/accounts/")
        assert not policy.is_login_path("/")

    @override_settings(BOUNCER_LOGIN_PATHS="/enter/")
    def test_login_paths_can_be_declared(self):
        assert policy.is_login_path("/enter/")
        assert not policy.is_login_path("/admin/login/")

    def test_strip_lang_prefix(self):
        assert policy.strip_lang_prefix("/en/accounts/x/") == "/accounts/x/"
        assert policy.strip_lang_prefix("/tr/") == "/"
        assert policy.strip_lang_prefix("/en") == "/"
        assert policy.strip_lang_prefix("/english/") == "/english/"
        assert policy.strip_lang_prefix("/products/") == "/products/"

    def test_static(self):
        assert H.is_static_path("/static/x.css")     # STATIC_URL
        assert H.is_static_path("/media/upload.png")  # MEDIA_URL
        assert H.is_static_path("/img/a.PNG")
        assert not H.is_static_path("/products/")

    def test_api_paths(self):
        assert policy.is_api_path("/api/products/")
        assert policy.is_api_path("/en/api/products/")
        assert not policy.is_api_path("/products/")

    @override_settings(BOUNCER_API_PREFIXES="/rest/")
    def test_api_prefixes_configurable(self):
        assert policy.is_api_path("/rest/v1/")
        assert not policy.is_api_path("/api/v1/")


class TestModes:
    def test_default_is_enforce(self):
        assert policy.mode() == policy.MODE_ENFORCE
        assert all(policy.is_enforcing(layer) for layer in policy.LAYERS)

    @override_settings(BOUNCER_MODE="observe")
    def test_global_observe(self):
        assert not any(policy.is_enforcing(layer) for layer in policy.LAYERS)

    @override_settings(BOUNCER_MODE="nonsense")
    def test_invalid_mode_falls_back_to_enforce(self):
        assert policy.mode() == policy.MODE_ENFORCE

    @override_settings(BOUNCER_LAYER_MODES={"waf": "observe", "bot": "off"})
    def test_per_layer_override_dict(self):
        assert policy.layer_mode("waf") == policy.MODE_OBSERVE
        assert policy.is_disabled("bot")
        assert policy.is_enforcing("rate_limit")

    @override_settings(BOUNCER_LAYER_MODES="waf=observe,unknown=off,bot=nope")
    def test_per_layer_override_string_ignores_garbage(self):
        assert policy.layer_mode("waf") == policy.MODE_OBSERVE
        assert policy.layer_mode("bot") == policy.MODE_ENFORCE


class TestRateRules:
    def test_default_rules(self):
        assert match_rule("/accounts/login/").limit_per_minute == 10
        assert match_rule("/admin/login/").limit_per_minute == 10
        assert match_rule("/admin/bouncer/securityevent/").limit_per_minute == 120
        assert match_rule("/api/products/").limit_per_minute == 240
        assert match_rule("/products/x/").limit_per_minute == 240
        assert match_rule(policy.strip_lang_prefix("/en/accounts/login/")).limit_per_minute == 10

    @override_settings(
        BOUNCER_RATE_LIMIT_RULES=[
            ("/accounts/login", 10),
            ("/cart/apply-discount/", 15),
            ("/", 60),
        ]
    )
    def test_project_rules_replace_defaults(self):
        assert match_rule("/cart/apply-discount/").limit_per_minute == 15
        assert match_rule("/products/").limit_per_minute == 60
        # The default admin rule is gone because the project declared its own set.
        assert match_rule("/admin/x/").limit_per_minute == 60

    @override_settings(BOUNCER_RATE_LIMIT_RULES="/api/=100,/=30")
    def test_rules_from_environment_string(self):
        assert match_rule("/api/x/").limit_per_minute == 100
        assert match_rule("/x/").limit_per_minute == 30

    @override_settings(BOUNCER_RATE_LIMIT_RULES=[("no-slash", 10), ("/ok/", 20)])
    def test_malformed_rule_is_dropped_not_fatal(self):
        prefixes = [rule.path_prefix for rule in policy.rate_limit_rules()]
        assert "no-slash" not in prefixes
        assert "/ok/" in prefixes

    @override_settings(BOUNCER_RATE_LIMIT_RULES=[("/only/", 5)])
    def test_catch_all_is_always_present(self):
        assert match_rule("/anything/").path_prefix == "/"

    @override_settings(BOUNCER_RATE_MULTIPLIER="2")
    def test_multiplier(self):
        assert burst_limit_for(match_rule("/")) == int(240 * 1.5 * 2)


class TestCounters:
    def test_bump_and_window(self):
        assert H.bump_counter("t", CLIENT, 10) == 1
        assert H.bump_counter("t", CLIENT, 10) == 2
        assert H.count_in_window("t", CLIENT, 10) == 2
        assert H.count_in_window("t", ATTACKER, 10) == 0

    def test_once_per(self):
        assert H.once_per("k", 60)
        assert not H.once_per("k", 60)

    def test_staff_trust_mark(self):
        assert not H.is_staff_trusted_ip(CLIENT)
        H.mark_staff_trusted_ip(CLIENT)
        assert H.is_staff_trusted_ip(CLIENT)
        H.unmark_staff_trusted_ip(CLIENT)
        assert not H.is_staff_trusted_ip(CLIENT)

    def test_unspecified_address_is_never_trusted_as_a_peer(self):
        H.mark_staff_trusted_ip("0.0.0.0")
        assert not H.is_staff_trusted_ip("0.0.0.0")


class TestResponses:
    def test_block_html(self):
        request = rf.get("/x/", REMOTE_ADDR=CLIENT)
        response = H.block_response(
            request, reason="ip_banned", banned=True, show_login=True
        )
        assert response.status_code == 403
        assert response["X-Bouncer-Block"] == "ip_banned"
        assert response["Cache-Control"] == "no-store"
        body = response.content.decode()
        assert CLIENT in body
        assert "/accounts/login/" in body      # settings.LOGIN_URL
        assert "noindex" in body

    @override_settings(BOUNCER_SUPPORT_URL="mailto:help@example.com")
    def test_block_page_shows_configured_contact(self):
        response = H.block_response(rf.get("/x/", REMOTE_ADDR=CLIENT), reason="waf_xss")
        assert "mailto:help@example.com" in response.content.decode()

    def test_block_page_hides_contact_when_unset(self):
        response = H.block_response(rf.get("/x/", REMOTE_ADDR=CLIENT), reason="waf_xss")
        assert "contact" not in response.content.decode().lower()

    def test_block_json(self):
        request = rf.get("/api/x/", REMOTE_ADDR=CLIENT)
        response = H.block_response(request, reason="waf_sqli")
        assert response["Content-Type"].startswith("application/json")
        assert b'"code": "waf_sqli"' in response.content

    def test_429(self):
        request = rf.get(
            "/x/", REMOTE_ADDR=CLIENT, HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        response = H.too_many_requests_response(request, retry_after=17)
        assert response.status_code == 429
        assert response["Retry-After"] == "17"
        assert response["Content-Type"].startswith("application/json")

    @override_settings(BOUNCER_BLOCK_HEADER="X-Custom-Block")
    def test_block_header_is_configurable(self):
        response = H.block_response(rf.get("/x/"), reason="honeypot")
        assert response["X-Custom-Block"] == "honeypot"
