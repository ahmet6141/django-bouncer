"""Observe and off modes.

The point of observe mode is to answer "what would this have blocked?" against
real traffic before anything is enforced, so the detection and the audit row
must stay identical — only the outcome changes.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from django_bouncer.middleware import (
    BotDetectorMiddleware,
    HoneypotMiddleware,
    IPBanMiddleware,
    RateLimitMiddleware,
    WAFMiddleware,
)
from django_bouncer.middleware.rate_limit import burst_limit_for, match_rule
from django_bouncer.models import BannedIP, SecurityEvent

from .conftest import ok, req


@pytest.fixture
def isolate():
    with patch.object(SecurityEvent.objects, "create") as event, patch.object(
        BannedIP, "add_automatic_ban", return_value=True
    ) as add_ban, patch.object(BannedIP, "ban_kind", return_value=None) as ban_kind:
        yield {"event": event, "add_ban": add_ban, "ban_kind": ban_kind}


ATTACK = "/products/?q=1%27%20UNION%20SELECT%20a%2Cb%20FROM%20x--"


class TestObserveMode:
    @pytest.fixture(autouse=True)
    def _observe_mode(self, settings):
        settings.BOUNCER_MODE = "observe"
        settings.BOUNCER_AUTO_BAN = True

    def test_waf_detects_and_logs_without_blocking(self, isolate):
        assert WAFMiddleware(ok)(req(ATTACK)).status_code == 200
        assert isolate["event"].called
        assert isolate["event"].call_args.kwargs["blocked"] is False
        assert not isolate["add_ban"].called

    def test_honeypot_logs_without_blocking(self, isolate):
        assert HoneypotMiddleware(ok)(req("/wp-login.php")).status_code == 200
        assert isolate["event"].call_args.kwargs["reason"] == "honeypot_url"
        assert not isolate["add_ban"].called

    def test_bot_detector_logs_without_blocking(self, isolate):
        assert (
            BotDetectorMiddleware(ok)(req("/products/", ua="sqlmap/1.7")).status_code
            == 200
        )
        assert isolate["event"].called

    def test_rate_limit_logs_without_429(self, isolate):
        middleware = RateLimitMiddleware(ok)
        limit = burst_limit_for(match_rule("/products/"))
        for _ in range(limit + 3):
            assert middleware(req("/products/")).status_code == 200
        assert isolate["event"].called
        assert not isolate["add_ban"].called

    def test_banned_address_is_logged_but_served(self, isolate, settings):
        settings.BOUNCER_BAN_ENFORCEMENT = True
        isolate["ban_kind"].return_value = "perm"
        assert IPBanMiddleware(ok)(req("/products/")).status_code == 200
        assert isolate["event"].call_args.kwargs["blocked"] is False


class TestPerLayerOverride:
    def test_one_layer_observes_while_the_rest_enforce(self, isolate, settings):
        settings.BOUNCER_LAYER_MODES = {"waf": "observe"}
        assert WAFMiddleware(ok)(req(ATTACK)).status_code == 200
        assert HoneypotMiddleware(ok)(req("/wp-login.php")).status_code == 404

    def test_off_skips_detection_entirely(self, isolate, settings):
        settings.BOUNCER_LAYER_MODES = {"bot": "off"}
        assert (
            BotDetectorMiddleware(ok)(req("/products/", ua="sqlmap/1.7")).status_code
            == 200
        )
        assert not isolate["event"].called
