"""The promises that matter most, verified against a real database.

Each test here corresponds to a way a security layer can hurt the people it is
supposed to protect: banning a shared address for one probe, letting a stale
cache outlive an expired ban, or letting an automatic detector overwrite an
operator's decision.
"""
from __future__ import annotations

import pytest
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.utils import timezone

from django_bouncer import policy
from django_bouncer.ban_policy import evaluate_auto_ban
from django_bouncer.middleware.bot_detector import BotDetectorMiddleware
from django_bouncer.middleware.honeypot import HoneypotMiddleware
from django_bouncer.middleware.ip_ban import IPBanMiddleware
from django_bouncer.middleware.rate_limit import RateLimitMiddleware
from django_bouncer.models import BannedIP, SecurityEvent

TEST_IP = "198.51.100.27"

pytestmark = pytest.mark.django_db


def _request(factory: RequestFactory, method: str, path: str, data=None, **extra):
    defaults = {
        "REMOTE_ADDR": TEST_IP,
        "HTTP_USER_AGENT": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
        ),
        "HTTP_ACCEPT": "text/html,application/xhtml+xml",
        "HTTP_ACCEPT_LANGUAGE": "en-GB,en;q=0.9",
        "HTTP_ACCEPT_ENCODING": "gzip, deflate, br",
    }
    defaults.update(extra)
    return getattr(factory, method)(path, data=data, **defaults)


def test_standard_security_txt_is_not_a_honeypot():
    middleware = HoneypotMiddleware(lambda request: HttpResponse("ok"))
    response = middleware(_request(RequestFactory(), "get", "/.well-known/security.txt"))

    assert response.status_code == 200
    assert not SecurityEvent.objects.filter(ip=TEST_IP).exists()
    assert not BannedIP.objects.filter(ip=TEST_IP).exists()


def test_one_scanner_path_is_blocked_without_banning_a_shared_address():
    middleware = HoneypotMiddleware(lambda request: HttpResponse("ok"))
    response = middleware(_request(RequestFactory(), "get", "/wp-login.php"))

    assert response.status_code == 404
    assert (
        SecurityEvent.objects.filter(
            ip=TEST_IP, reason=SecurityEvent.REASON_HONEYPOT_URL
        ).count()
        == 1
    )
    assert not BannedIP.is_banned(TEST_IP)


@override_settings(BOUNCER_AUTO_BAN=True)
def test_three_distinct_scanner_paths_create_a_short_temporary_ban():
    middleware = HoneypotMiddleware(lambda request: HttpResponse("ok"))
    factory = RequestFactory()

    for path in ("/wp-login.php", "/.env", "/phpmyadmin/"):
        assert middleware(_request(factory, "get", path)).status_code == 404

    ban = BannedIP.objects.get(ip=TEST_IP)
    remaining = ban.expires_at - timezone.now()
    assert not ban.is_permanent
    assert timezone.timedelta(minutes=29) < remaining <= timezone.timedelta(minutes=30)


def test_an_ordinary_website_field_does_not_trigger_the_form_honeypot():
    middleware = HoneypotMiddleware(lambda request: HttpResponse("ok"))
    response = middleware(
        _request(
            RequestFactory(),
            "post",
            "/products/edit/",
            data={"website_url": "https://creator.example"},
        )
    )

    assert response.status_code == 200
    assert not BannedIP.objects.filter(ip=TEST_IP).exists()


def test_form_honeypot_blocks_the_submission_but_never_bans():
    middleware = HoneypotMiddleware(lambda request: HttpResponse("ok"))
    response = middleware(
        _request(
            RequestFactory(),
            "post",
            "/contact/",
            data={policy.honeypot_field_name(): "filled-by-bot"},
        )
    )

    assert response.status_code == 403
    assert not BannedIP.objects.filter(ip=TEST_IP).exists()


def test_blocked_developer_user_agent_never_creates_a_global_ban():
    middleware = BotDetectorMiddleware(lambda request: HttpResponse("ok"))
    factory = RequestFactory()

    for index in range(25):
        response = middleware(
            _request(
                factory, "get", f"/products/?page={index}", HTTP_USER_AGENT="curl/8.10.1"
            )
        )
        assert response.status_code == 403

    assert not BannedIP.objects.filter(ip=TEST_IP).exists()
    assert (
        SecurityEvent.objects.filter(
            ip=TEST_IP, reason=SecurityEvent.REASON_BOT_UA_BLACKLIST
        ).count()
        == 1
    )


@override_settings(BOUNCER_AUTO_BAN=True)
def test_waf_policy_requires_repetition_across_multiple_paths():
    for _ in range(5):
        SecurityEvent.objects.create(
            ip=TEST_IP,
            reason=SecurityEvent.REASON_WAF_XSS,
            severity=SecurityEvent.SEVERITY_HIGH,
            path="/products/search/",
            blocked=True,
        )

    assert not evaluate_auto_ban(TEST_IP, "waf", reason="waf_xss")
    assert not BannedIP.objects.filter(ip=TEST_IP).exists()

    SecurityEvent.objects.create(
        ip=TEST_IP,
        reason=SecurityEvent.REASON_WAF_SQLI,
        severity=SecurityEvent.SEVERITY_HIGH,
        path="/accounts/login/",
        blocked=True,
    )
    assert evaluate_auto_ban(TEST_IP, "waf", reason="waf_mixed")
    assert BannedIP.is_banned(TEST_IP)


def test_automatic_ban_cannot_overwrite_an_active_permanent_ban():
    original = BannedIP.add_ban(
        TEST_IP, reason="manual_abuse", permanent=True, note="operator decision"
    )

    assert not BannedIP.add_automatic_ban(
        TEST_IP, reason="waf_xss", minutes=15, note="automatic detector"
    )
    original.refresh_from_db()
    assert original.is_permanent
    assert original.reason == "manual_abuse"
    assert original.note == "operator decision"


def test_unknown_cache_shape_does_not_extend_an_expired_ban():
    BannedIP.objects.create(
        ip=TEST_IP,
        reason="expired",
        expires_at=timezone.now() - timezone.timedelta(minutes=1),
    )
    cache.set(BannedIP.cache_key(TEST_IP), "1", timeout=600)

    assert not BannedIP.is_banned(TEST_IP)
    assert cache.get(BannedIP.cache_key(TEST_IP)) == "0"


def test_temporary_ban_is_cached_only_for_its_remaining_lifetime():
    BannedIP.add_automatic_ban(TEST_IP, reason="rate_limit", minutes=5)
    cached = cache.get(BannedIP.cache_key(TEST_IP))
    assert isinstance(cached, str) and cached.startswith("e:")
    assert BannedIP.ban_kind(TEST_IP) == "temp"


def test_unspecified_address_can_never_be_an_active_ban_target():
    # Historical rows can exist from an old Unix-socket or proxy configuration.
    BannedIP.objects.create(ip="0.0.0.0", reason="legacy", is_permanent=True)
    cache.set(BannedIP.cache_key("0.0.0.0"), "p", timeout=600)

    assert not BannedIP.is_banned("0.0.0.0")
    assert not BannedIP.add_automatic_ban("0.0.0.0", reason="rate_limit", minutes=15)
    with pytest.raises(ValueError, match="Unspecified"):
        BannedIP.add_ban("0.0.0.0", reason="manual")


@pytest.mark.django_db(transaction=False)
def test_unknown_peer_does_not_share_one_global_rate_bucket():
    middleware = RateLimitMiddleware(lambda request: HttpResponse("ok"))
    factory = RequestFactory()

    for _ in range(250):
        request = factory.get(
            "/products/", REMOTE_ADDR="", HTTP_USER_AGENT="Mozilla/5.0 real browser"
        )
        assert middleware(request).status_code == 200


@override_settings(BOUNCER_BAN_ENFORCEMENT=False)
def test_enforcement_switch_keeps_existing_bans_from_blocking_visitors():
    BannedIP.add_ban(TEST_IP, reason="historical", permanent=True)
    middleware = IPBanMiddleware(lambda request: HttpResponse("ok"))

    assert middleware(_request(RequestFactory(), "get", "/products/")).status_code == 200


@override_settings(BOUNCER_BAN_ENFORCEMENT=True)
def test_enforcement_can_be_enabled_deliberately():
    BannedIP.add_ban(TEST_IP, reason="manual", permanent=True)
    middleware = IPBanMiddleware(lambda request: HttpResponse("ok"))

    assert middleware(_request(RequestFactory(), "get", "/products/")).status_code == 403


@override_settings(BOUNCER_AUTO_BAN=False)
def test_automatic_bans_have_an_emergency_kill_switch():
    for path in ("/.env", "/wp-login.php", "/phpmyadmin/"):
        SecurityEvent.objects.create(
            ip=TEST_IP,
            reason=SecurityEvent.REASON_HONEYPOT_URL,
            severity=SecurityEvent.SEVERITY_HIGH,
            path=path,
            blocked=True,
        )

    assert not evaluate_auto_ban(TEST_IP, "honeypot_url", reason="scanner")
    assert not BannedIP.objects.filter(ip=TEST_IP).exists()
