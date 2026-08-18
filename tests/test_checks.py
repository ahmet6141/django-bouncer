"""System checks: the misconfigurations that would otherwise fail silently."""
from __future__ import annotations

from django_bouncer.checks import (
    check_deployment,
    check_middleware,
    check_policy_coherence,
    check_runtime_dependencies,
    check_values,
)

FULL_STACK = [
    "django.middleware.security.SecurityMiddleware",
    "django_bouncer.middleware.ClientIPMiddleware",
    "django_bouncer.middleware.IPBanMiddleware",
    "django_bouncer.middleware.HoneypotMiddleware",
    "django_bouncer.middleware.JSONRequestValidationMiddleware",
    "django_bouncer.middleware.WAFMiddleware",
    "django_bouncer.middleware.BotDetectorMiddleware",
    "django_bouncer.middleware.RateLimitMiddleware",
]
REDIS = {"default": {"BACKEND": "django_redis.cache.RedisCache", "LOCATION": "redis://x"}}


def ids(messages):
    return {message.id for message in messages}


class TestMiddlewareChecks:
    def test_clean_stack_has_no_middleware_findings(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        assert check_middleware(None) == []

    def test_no_middleware_at_all_is_reported(self, settings):
        settings.MIDDLEWARE = ["django.middleware.security.SecurityMiddleware"]
        assert "bouncer.W001" in ids(check_middleware(None))

    def test_missing_client_ip_middleware_is_an_error(self, settings):
        settings.MIDDLEWARE = [m for m in FULL_STACK if "ClientIP" not in m]
        assert "bouncer.E001" in ids(check_middleware(None))

    def test_wrong_order_is_an_error(self, settings):
        shuffled = list(FULL_STACK)
        shuffled.remove("django_bouncer.middleware.IPBanMiddleware")
        shuffled.append("django_bouncer.middleware.IPBanMiddleware")
        settings.MIDDLEWARE = shuffled
        found = check_middleware(None)
        assert "bouncer.E002" in ids(found)
        assert "IPBanMiddleware" in found[0].hint


class TestValueChecks:
    def test_clean_settings_have_no_findings(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        assert check_values(None) == []

    def test_unparseable_trusted_address(self, settings):
        settings.BOUNCER_TRUSTED_IPS = "203.0.113.7,not-an-address"
        assert "bouncer.E003" in ids(check_values(None))

    def test_invalid_mode(self, settings):
        settings.BOUNCER_MODE = "paranoid"
        assert "bouncer.E004" in ids(check_values(None))

    def test_unknown_layer_name(self, settings):
        settings.BOUNCER_LAYER_MODES = {"wafff": "observe"}
        assert "bouncer.E005" in ids(check_values(None))

    def test_dropped_rate_rule(self, settings):
        settings.BOUNCER_RATE_LIMIT_RULES = [("no-slash", 10), ("/ok/", 20)]
        assert "bouncer.E006" in ids(check_values(None))


class TestRuntimeChecks:
    def test_dummy_cache_is_reported(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.CACHES = {
            "default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}
        }
        assert "bouncer.W002" in ids(check_runtime_dependencies(None))

    def test_locmem_cache_is_reported(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        assert "bouncer.W003" in ids(check_runtime_dependencies(None))

    def test_missing_sessions_app_is_reported(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.CACHES = REDIS
        settings.INSTALLED_APPS = [
            app for app in settings.INSTALLED_APPS if "sessions" not in app
        ]
        assert "bouncer.W004" in ids(check_runtime_dependencies(None))

    def test_nothing_is_reported_without_the_middleware(self, settings):
        settings.MIDDLEWARE = ["django.middleware.security.SecurityMiddleware"]
        settings.CACHES = {
            "default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}
        }
        assert check_runtime_dependencies(None) == []


class TestCoherenceChecks:
    def test_auto_ban_without_enforcement(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.BOUNCER_AUTO_BAN = True
        settings.BOUNCER_BAN_ENFORCEMENT = False
        assert "bouncer.W005" in ids(check_policy_coherence(None))

    def test_enforcement_without_any_recovery_route(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.BOUNCER_BAN_ENFORCEMENT = True
        settings.BOUNCER_STAFF_BYPASS = False
        settings.BOUNCER_TRUSTED_IPS = []
        assert "bouncer.W006" in ids(check_policy_coherence(None))

    def test_pointless_shadow_count(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.BOUNCER_TRUSTED_PROXY_COUNT = 1
        settings.BOUNCER_SHADOW_PROXY_COUNT = 1
        assert "bouncer.W007" in ids(check_policy_coherence(None))


class TestDeploymentChecks:
    def test_proxied_deployment_without_a_proxy_count(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
        settings.BOUNCER_TRUSTED_PROXY_COUNT = 0
        assert "bouncer.W008" in ids(check_deployment(None))

    def test_observe_mode_is_flagged_on_deploy(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.BOUNCER_MODE = "observe"
        assert "bouncer.W009" in ids(check_deployment(None))

    def test_partial_rollout_is_flagged_on_deploy(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.BOUNCER_LAYER_MODES = {"waf": "observe"}
        found = check_deployment(None)
        assert "bouncer.W010" in ids(found)
        assert "waf" in found[0].msg

    def test_enforcing_stack_behind_one_proxy_is_clean(self, settings):
        settings.MIDDLEWARE = FULL_STACK
        settings.BOUNCER_TRUSTED_PROXY_COUNT = 1
        settings.SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
        assert check_deployment(None) == []
