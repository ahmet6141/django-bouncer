"""Middleware decisions: who is blocked, who passes, who can be banned.

Database access is mocked out so these run as fast unit tests; the
database-level guarantees are covered in ``test_ban_safety.py``.
"""
from __future__ import annotations

from unittest.mock import patch
from urllib.parse import urlencode

import pytest
from django.core.cache import cache
from django.test import override_settings

from django_bouncer import policy
from django_bouncer.middleware import (
    BotDetectorMiddleware,
    HoneypotMiddleware,
    IPBanMiddleware,
    RateLimitMiddleware,
    WAFMiddleware,
)
from django_bouncer.middleware.rate_limit import burst_limit_for, match_rule
from django_bouncer.models import BannedIP, SecurityEvent

from .conftest import CHROME, CLIENT, ok, req, rf


@pytest.fixture
def isolate():
    with patch.object(SecurityEvent.objects, "create") as event, patch.object(
        BannedIP, "add_automatic_ban", return_value=True
    ) as add_ban, patch.object(
        BannedIP, "remove_ban", return_value=True
    ) as remove_ban, patch.object(
        BannedIP, "ban_kind", return_value=None
    ) as ban_kind, override_settings(BOUNCER_BAN_ENFORCEMENT=True):
        yield {
            "event": event,
            "add_ban": add_ban,
            "remove_ban": remove_ban,
            "ban_kind": ban_kind,
        }


def _threshold_met():
    """Pretend the persisted event counts already satisfy every policy."""
    patcher = patch("django_bouncer.ban_policy.SecurityEvent")
    events = patcher.start()
    queryset = events.objects.filter.return_value
    queryset.count.return_value = 99
    queryset.values.return_value.distinct.return_value.count.return_value = 99
    return patcher


# ─────────────────────────────────────────────────────────────────────────
# IP ban
# ─────────────────────────────────────────────────────────────────────────

class TestIPBan:
    def test_not_banned_passes(self, isolate):
        assert IPBanMiddleware(ok)(req()).status_code == 200

    def test_temporarily_banned_is_blocked_with_a_login_hint(self, isolate):
        isolate["ban_kind"].return_value = "temp"
        response = IPBanMiddleware(ok)(req("/products/"))
        assert response.status_code == 403
        assert "/accounts/login/" in response.content.decode()
        assert response["X-Bouncer-Block"] == "ip_banned"

    def test_temporarily_banned_can_still_reach_login(self, isolate):
        isolate["ban_kind"].return_value = "temp"
        assert IPBanMiddleware(ok)(req("/accounts/login/")).status_code == 200
        assert (
            IPBanMiddleware(ok)(req("/en/accounts/login/", method="POST")).status_code
            == 200
        )
        assert IPBanMiddleware(ok)(req("/admin/login/")).status_code == 200

    def test_permanently_banned_cannot_reach_login(self, isolate):
        isolate["ban_kind"].return_value = "perm"
        assert IPBanMiddleware(ok)(req("/accounts/login/")).status_code == 403

    def test_banned_staff_session_passes(self, isolate):
        isolate["ban_kind"].return_value = "perm"
        assert IPBanMiddleware(ok)(req(staff=True)).status_code == 200

    def test_banned_but_staff_trusted_address_passes(self, isolate):
        from django_bouncer.middleware._helpers import mark_staff_trusted_ip

        isolate["ban_kind"].return_value = "temp"
        mark_staff_trusted_ip(CLIENT)
        assert IPBanMiddleware(ok)(req()).status_code == 200

    @override_settings(BOUNCER_EXEMPT_PATHS="/callback")
    def test_exempt_and_static_paths_skip_the_ban(self, isolate):
        isolate["ban_kind"].return_value = "perm"
        assert IPBanMiddleware(ok)(req("/callback/", method="POST")).status_code == 200
        assert IPBanMiddleware(ok)(req("/static/a.css")).status_code == 200
        assert IPBanMiddleware(ok)(req("/robots.txt")).status_code == 200

    def test_enforcement_switch_off_lets_a_banned_address_through(self, isolate):
        isolate["ban_kind"].return_value = "perm"
        with override_settings(BOUNCER_BAN_ENFORCEMENT=False):
            assert IPBanMiddleware(ok)(req()).status_code == 200

    def test_ban_logging_is_throttled(self, isolate):
        isolate["ban_kind"].return_value = "temp"
        middleware = IPBanMiddleware(ok)
        for _ in range(5):
            middleware(req())
        assert isolate["event"].call_count == 1  # one row a minute


# ─────────────────────────────────────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────────────────────────────────────

class TestRateLimit:
    @pytest.fixture(autouse=True)
    def _freeze_time(self):
        # Keep a flood inside one minute bucket; a rollover would be flaky.
        import time as _time

        frozen = (int(_time.time()) // 60) * 60 + 5
        with patch(
            "django_bouncer.middleware.rate_limit.time.time", return_value=frozen
        ), patch("django_bouncer.middleware._helpers.time.time", return_value=frozen):
            yield

    def _flood(self, middleware, path, count, **kwargs):
        response = None
        for _ in range(count):
            response = middleware(req(path, **kwargs))
        return response

    def test_under_the_limit_passes(self):
        assert self._flood(RateLimitMiddleware(ok), "/products/", 50).status_code == 200

    def test_over_the_limit_is_429_without_a_ban(self, isolate):
        limit = burst_limit_for(match_rule("/products/"))
        response = self._flood(RateLimitMiddleware(ok), "/products/", limit + 1)
        assert response.status_code == 429
        assert response["Retry-After"]
        assert not isolate["add_ban"].called  # one minute over the limit is not a ban

    def test_staff_never_sees_429(self):
        limit = burst_limit_for(match_rule("/admin/"))
        assert (
            self._flood(
                RateLimitMiddleware(ok), "/admin/x/", limit + 5, staff=True
            ).status_code
            == 200
        )

    def test_login_lock_only_affects_the_login_post(self, isolate):
        import time

        cache.set(f"bnc:loginlock:{CLIENT}", str(time.time() + 600), 600)
        middleware = RateLimitMiddleware(ok)
        assert middleware(req("/accounts/login/", method="POST")).status_code == 429
        assert middleware(req("/accounts/login/")).status_code == 200  # GET is fine
        assert middleware(req("/products/")).status_code == 200
        assert (
            middleware(req("/accounts/login/", method="POST", staff=True)).status_code
            == 200
        )

    @override_settings(BOUNCER_EXEMPT_PATHS="/callback")
    def test_exempt_path_is_not_limited(self):
        assert (
            self._flood(
                RateLimitMiddleware(ok), "/callback/", 500, method="POST"
            ).status_code
            == 200
        )

    def test_hammering_does_not_ban_while_auto_ban_is_off(self, isolate):
        limit = burst_limit_for(match_rule("/products/"))
        self._flood(
            RateLimitMiddleware(ok),
            "/products/",
            limit * policy.RATE_HAMMER_FACTOR + 3,
        )
        assert not isolate["add_ban"].called

    def test_signed_in_user_is_never_ip_banned_for_rate(self, isolate):
        patcher = _threshold_met()
        try:
            with override_settings(BOUNCER_AUTO_BAN=True):
                limit = burst_limit_for(match_rule("/products/"))
                self._flood(
                    RateLimitMiddleware(ok), "/products/", limit + 2, authed=True
                )
        finally:
            patcher.stop()
        assert not isolate["add_ban"].called

    def test_staff_is_never_ip_banned_for_rate(self, isolate):
        patcher = _threshold_met()
        try:
            with override_settings(BOUNCER_AUTO_BAN=True):
                limit = burst_limit_for(match_rule("/products/"))
                self._flood(
                    RateLimitMiddleware(ok), "/products/", limit + 2, staff=True
                )
        finally:
            patcher.stop()
        assert not isolate["add_ban"].called

    def test_anonymous_sustained_abuse_is_banned_when_enabled(self, isolate):
        patcher = _threshold_met()
        try:
            with override_settings(BOUNCER_AUTO_BAN=True):
                limit = burst_limit_for(match_rule("/products/"))
                self._flood(RateLimitMiddleware(ok), "/products/", limit + 2)
        finally:
            patcher.stop()
        assert isolate["add_ban"].call_count == 1


# ─────────────────────────────────────────────────────────────────────────
# Bot detection
# ─────────────────────────────────────────────────────────────────────────

class TestBotDetector:
    def test_browser_passes(self):
        assert BotDetectorMiddleware(ok)(req()).status_code == 200

    def test_curl_on_html_is_403_without_a_ban(self, isolate):
        response = BotDetectorMiddleware(ok)(req("/products/", ua="curl/8.4.0"))
        assert response.status_code == 403
        assert not isolate["add_ban"].called

    def test_curl_head_is_allowed(self):
        assert (
            BotDetectorMiddleware(ok)(
                req("/", method="HEAD", ua="curl/8.4.0")
            ).status_code
            == 200
        )

    def test_library_user_agent_on_api_is_allowed(self):
        assert (
            BotDetectorMiddleware(ok)(
                req("/api/products/", ua="python-requests/2.31")
            ).status_code
            == 200
        )

    def test_headless_browser_is_blocked_even_on_api(self):
        ua = CHROME.replace("Chrome/", "HeadlessChrome/")
        assert BotDetectorMiddleware(ok)(req("/api/products/", ua=ua)).status_code == 403

    def test_staff_tooling_passes(self):
        ua = CHROME.replace("Chrome/", "HeadlessChrome/")
        assert (
            BotDetectorMiddleware(ok)(req("/products/", ua=ua, staff=True)).status_code
            == 200
        )
        assert (
            BotDetectorMiddleware(ok)(
                req("/products/", ua="python-requests/2.31", staff=True)
            ).status_code
            == 200
        )

    def test_staff_trusted_address_passes_with_curl(self):
        from django_bouncer.middleware._helpers import mark_staff_trusted_ip

        mark_staff_trusted_ip(CLIENT)
        assert (
            BotDetectorMiddleware(ok)(req("/products/", ua="curl/8.4.0")).status_code
            == 200
        )

    def test_scanner_is_403_but_never_a_global_ban(self, isolate):
        with override_settings(BOUNCER_AUTO_BAN=True):
            response = BotDetectorMiddleware(ok)(req("/", ua="sqlmap/1.7"))
        assert response.status_code == 403
        assert not isolate["add_ban"].called

    def test_scraper_volume_never_creates_a_global_ban(self, isolate):
        middleware = BotDetectorMiddleware(ok)
        with override_settings(BOUNCER_AUTO_BAN=True):
            for _ in range(80):
                assert (
                    middleware(req("/products/", ua="python-requests/2.31")).status_code
                    == 403
                )
        assert not isolate["add_ban"].called
        # 80 requests produce one event a minute
        assert (
            sum(
                1
                for call in isolate["event"].call_args_list
                if call.kwargs.get("reason") == "bot_ua"
            )
            == 1
        )

    def test_good_bot_passes(self):
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        assert BotDetectorMiddleware(ok)(req("/products/", ua=ua)).status_code == 200

    def test_empty_user_agent_is_403_without_a_ban(self, isolate):
        assert BotDetectorMiddleware(ok)(req("/products/", ua="")).status_code == 403
        assert not isolate["add_ban"].called

    @override_settings(BOUNCER_EXEMPT_PATHS="/callback,/ad-callback/")
    def test_webhook_with_empty_user_agent_is_exempt(self):
        assert (
            BotDetectorMiddleware(ok)(
                req("/callback/", method="POST", ua="")
            ).status_code
            == 200
        )
        assert (
            BotDetectorMiddleware(ok)(
                req("/ad-callback/x/", ua="Go-http-client/1.1")
            ).status_code
            == 200
        )

    def test_fast_navigation_only_logs(self, isolate):
        middleware = BotDetectorMiddleware(ok)
        for _ in range(10):
            assert (
                middleware(
                    req("/products/", HTTP_SEC_FETCH_MODE="navigate")
                ).status_code
                == 200
            )
        assert not isolate["add_ban"].called

    def test_prefetch_does_not_count_as_navigation(self, isolate):
        middleware = BotDetectorMiddleware(ok)
        for _ in range(10):
            middleware(
                req(
                    "/products/",
                    HTTP_SEC_FETCH_MODE="navigate",
                    HTTP_SEC_PURPOSE="prefetch",
                )
            )
        assert not any(
            call.kwargs.get("reason") == "scraper"
            for call in isolate["event"].call_args_list
        )


# ─────────────────────────────────────────────────────────────────────────
# WAF
# ─────────────────────────────────────────────────────────────────────────

class TestWAF:
    def test_clean_request_passes(self):
        assert WAFMiddleware(ok)(req("/products/?q=sci-fi+door")).status_code == 200

    def test_sql_injection_in_query_is_403(self, isolate):
        response = WAFMiddleware(ok)(
            req("/products/?q=1%27%20UNION%20SELECT%20a%2Cb%20FROM%20x--")
        )
        assert response.status_code == 403
        assert not isolate["add_ban"].called  # one hit is not a ban

    def test_signed_in_user_is_never_banned_by_the_waf(self, isolate):
        patcher = _threshold_met()
        try:
            with override_settings(BOUNCER_AUTO_BAN=True):
                middleware = WAFMiddleware(ok)
                for _ in range(3):
                    assert (
                        middleware(
                            req("/products/?q=%3Cscript%3E", authed=True)
                        ).status_code
                        == 403
                    )
        finally:
            patcher.stop()
        assert not isolate["add_ban"].called

    def test_anonymous_repetition_is_banned_when_enabled(self, isolate):
        patcher = _threshold_met()
        try:
            with override_settings(BOUNCER_AUTO_BAN=True):
                assert (
                    WAFMiddleware(ok)(req("/products/?q=%3Cscript%3E")).status_code
                    == 403
                )
        finally:
            patcher.stop()
        assert isolate["add_ban"].call_count == 1

    def test_staff_bypasses_the_waf(self):
        assert (
            WAFMiddleware(ok)(req("/products/?q=%3Cscript%3E", staff=True)).status_code
            == 200
        )

    def test_scanner_path_is_404_without_a_ban_by_default(self, isolate):
        middleware = WAFMiddleware(ok)
        for index in range(4):
            assert middleware(req(f"/foo{index}.php")).status_code == 404
        assert not isolate["add_ban"].called
        # Distinct paths stay distinct events: the policy counts three of them.
        assert (
            sum(
                1
                for call in isolate["event"].call_args_list
                if call.kwargs.get("reason") == "honeypot_url"
            )
            == 4
        )

    def test_legitimate_slug_is_not_a_scanner_path(self):
        assert WAFMiddleware(ok)(req("/products/mysql-icon-pack/")).status_code == 200
        assert WAFMiddleware(ok)(req("/en/products/old-house/")).status_code == 200

    def test_natural_language_search_passes(self):
        assert (
            WAFMiddleware(ok)(req("/products/?q=select+model+from+list")).status_code
            == 200
        )
        assert WAFMiddleware(ok)(req("/products/?q=drop+table+lamp")).status_code == 200
        assert WAFMiddleware(ok)(req("/products/?q=..%2Ftextures")).status_code == 200

    def test_json_api_body_is_scanned(self, isolate):
        request = rf.post(
            "/api/x/",
            data='{"q":"1 union select a from b"}',
            content_type="application/json",
            REMOTE_ADDR=CLIENT,
            HTTP_USER_AGENT=CHROME,
        )
        request._bouncer_user_info = {"id": None, "staff": False}
        assert WAFMiddleware(ok)(request).status_code == 403

    @override_settings(BOUNCER_WAF_BODY_SCAN_EXCLUDED_PATHS="/bouncer/csp-report/")
    def test_excluded_path_skips_body_scanning(self, isolate):
        request = rf.post(
            "/bouncer/csp-report/",
            data='{"csp-report":{"blocked-uri":"<script>alert(1)</script>"}}',
            content_type="application/json",
            REMOTE_ADDR=CLIENT,
            HTTP_USER_AGENT=CHROME,
        )
        request._bouncer_user_info = {"id": None, "staff": False}
        assert WAFMiddleware(ok)(request).status_code == 200


# ─────────────────────────────────────────────────────────────────────────
# Honeypot
# ─────────────────────────────────────────────────────────────────────────

class TestHoneypot:
    def test_wp_login_is_404_without_a_ban_by_default(self, isolate):
        response = HoneypotMiddleware(ok)(req("/wp-login.php"))
        assert response.status_code == 404
        assert not isolate["add_ban"].called

    def test_three_distinct_paths_ban_but_never_for_staff(self, isolate):
        patcher = _threshold_met()
        try:
            with override_settings(BOUNCER_AUTO_BAN=True):
                middleware = HoneypotMiddleware(ok)
                assert middleware(req("/.env", staff=True)).status_code == 200
                assert not isolate["add_ban"].called
                # The staff address is now trusted; another address is not.
                assert middleware(req("/.env")).status_code == 200
                assert middleware(req("/.env", ip="203.0.113.9")).status_code == 404
                assert isolate["add_ban"].call_count == 1
        finally:
            patcher.stop()

    def test_legitimate_console_slug_passes(self, isolate):
        assert HoneypotMiddleware(ok)(req("/products/console/")).status_code == 200
        assert (
            HoneypotMiddleware(ok)(req("/collections/game-console/")).status_code == 200
        )
        assert not isolate["add_ban"].called

    def test_form_field_filled_is_403_without_a_ban(self, isolate):
        field = policy.honeypot_field_name()
        request = rf.post(
            "/contact/",
            data=urlencode({"name": "x", field: "http://spam"}),
            content_type="application/x-www-form-urlencoded",
            REMOTE_ADDR=CLIENT,
            HTTP_USER_AGENT=CHROME,
        )
        request._bouncer_user_info = {"id": None, "staff": False}
        assert HoneypotMiddleware(ok)(request).status_code == 403
        assert not isolate["add_ban"].called

        multipart = rf.post(
            "/contact/", data={field: "bot"}, REMOTE_ADDR=CLIENT, HTTP_USER_AGENT=CHROME
        )
        multipart._bouncer_user_info = {"id": None, "staff": False}
        assert HoneypotMiddleware(ok)(multipart).status_code == 403

    def test_ordinary_website_field_does_not_trigger(self, isolate):
        request = rf.post(
            "/contact/",
            data=urlencode({"name": "x", "website_url": "https://me.example"}),
            content_type="application/x-www-form-urlencoded",
            REMOTE_ADDR=CLIENT,
            HTTP_USER_AGENT=CHROME,
        )
        request._bouncer_user_info = {"id": None, "staff": False}
        assert HoneypotMiddleware(ok)(request).status_code == 200
        assert not isolate["add_ban"].called


# ─────────────────────────────────────────────────────────────────────────
# Signals
# ─────────────────────────────────────────────────────────────────────────

class TestSignals:
    def test_staff_login_lifts_the_ban_and_trusts_the_address(self, isolate):
        from django_bouncer.middleware._helpers import is_staff_trusted_ip
        from django_bouncer.signals import on_user_logged_in

        class User:
            pk = 1
            is_staff = True
            is_superuser = False

        on_user_logged_in(
            sender=None, request=req("/accounts/login/", method="POST"), user=User()
        )
        assert isolate["remove_ban"].called
        assert is_staff_trusted_ip(CLIENT)

    def test_ordinary_login_does_not_trust_the_address(self, isolate):
        from django_bouncer.middleware._helpers import is_staff_trusted_ip
        from django_bouncer.signals import on_user_logged_in

        class User:
            pk = 2
            is_staff = False
            is_superuser = False

        on_user_logged_in(sender=None, request=req(), user=User())
        assert not isolate["remove_ban"].called
        assert not is_staff_trusted_ip(CLIENT)

    def test_failures_lock_first_and_only_then_ban(self, isolate):
        from django_bouncer import signals
        from django_bouncer.middleware.rate_limit import login_locked
        from django_bouncer.signals import on_user_login_failed

        for _ in range(policy.LOGIN_FAIL_LOCK_COUNT - 1):
            on_user_login_failed(sender=None, credentials={}, request=req(method="POST"))
        assert login_locked(CLIENT) == 0

        on_user_login_failed(sender=None, credentials={}, request=req(method="POST"))
        assert login_locked(CLIENT) > 0
        assert not isolate["add_ban"].called

        for _ in range(signals.LOGIN_FAIL_BAN_COUNT):
            on_user_login_failed(sender=None, credentials={}, request=req(method="POST"))
        assert not isolate["add_ban"].called  # auto-ban is off by default

        with override_settings(BOUNCER_AUTO_BAN=True):
            for _ in range(10):
                on_user_login_failed(
                    sender=None, credentials={}, request=req(method="POST")
                )
        assert isolate["add_ban"].called

    def test_staff_address_is_never_locked(self, isolate):
        from django_bouncer.middleware._helpers import mark_staff_trusted_ip
        from django_bouncer.middleware.rate_limit import login_locked
        from django_bouncer.signals import on_user_login_failed

        mark_staff_trusted_ip(CLIENT)
        for _ in range(policy.LOGIN_FAIL_LOCK_COUNT + 5):
            on_user_login_failed(sender=None, credentials={}, request=req(method="POST"))
        assert login_locked(CLIENT) == 0
