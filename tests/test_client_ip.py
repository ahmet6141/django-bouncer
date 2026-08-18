"""Client-IP resolution: the setting that decides whether anything else is safe."""
from __future__ import annotations

from django.test import RequestFactory, override_settings

from django_bouncer.client_ip import (
    UNSPECIFIED_IP,
    get_client_ip,
    is_bannable_client_ip,
    normalize_ip,
    resolve_client_ip,
)
from django_bouncer.middleware import ClientIPMiddleware

rf = RequestFactory()
PROXY = "10.0.0.9"
REAL = "203.0.113.10"
SPOOFED = "1.2.3.4"


def _request(**extra):
    return rf.get("/", **extra)


class TestNormalize:
    def test_valid_addresses(self):
        assert normalize_ip("203.0.113.10") == "203.0.113.10"
        assert normalize_ip("::1") == "::1"
        assert normalize_ip(" 203.0.113.10 ") == "203.0.113.10"

    def test_host_port_forms(self):
        assert normalize_ip("203.0.113.10:8443") == "203.0.113.10"
        assert normalize_ip("[2001:db8::1]:443") == "2001:db8::1"

    def test_rejects_text(self):
        assert normalize_ip("evil.example") is None
        assert normalize_ip("") is None
        assert normalize_ip(None) is None

    def test_unspecified_is_not_bannable(self):
        assert not is_bannable_client_ip("0.0.0.0")
        assert not is_bannable_client_ip("::")
        assert not is_bannable_client_ip("not-an-ip")
        assert is_bannable_client_ip(REAL)


class TestResolve:
    def test_zero_proxies_ignores_forwarded_headers(self):
        request = _request(REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=f"{SPOOFED}, {REAL}")
        assert resolve_client_ip(request, trusted_proxy_count=0) == PROXY

    def test_one_proxy_takes_the_rightmost_entry(self):
        request = _request(REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=f"{SPOOFED}, {REAL}")
        assert resolve_client_ip(request, trusted_proxy_count=1) == REAL

    def test_two_proxies_take_the_second_from_the_right(self):
        request = _request(
            REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=f"{SPOOFED}, {REAL}, {PROXY}"
        )
        assert resolve_client_ip(request, trusted_proxy_count=2) == REAL

    def test_short_chain_fails_closed_to_the_peer(self):
        request = _request(REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL)
        assert resolve_client_ip(request, trusted_proxy_count=3) == PROXY

    def test_malformed_trusted_position_falls_back_to_the_peer(self):
        request = _request(REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR="not-an-ip")
        assert resolve_client_ip(request, trusted_proxy_count=1) == PROXY

    def test_missing_peer_returns_the_unspecified_sentinel(self):
        request = _request(REMOTE_ADDR="")
        assert resolve_client_ip(request, trusted_proxy_count=0) == UNSPECIFIED_IP


class TestMiddleware:
    @override_settings(BOUNCER_TRUSTED_PROXY_COUNT=1)
    def test_publishes_the_address_on_the_request(self):
        seen = {}

        def view(request):
            seen["ip"] = request.bouncer_ip
            from django.http import HttpResponse

            return HttpResponse("ok")

        request = _request(REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=f"{SPOOFED}, {REAL}")
        ClientIPMiddleware(view)(request)
        assert seen["ip"] == REAL
        assert get_client_ip(request) == REAL

    @override_settings(BOUNCER_TRUSTED_PROXY_COUNT=0, BOUNCER_SHADOW_PROXY_COUNT=1)
    def test_shadow_count_is_recorded_but_never_used(self):
        from django.http import HttpResponse

        request = _request(REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL)
        ClientIPMiddleware(lambda r: HttpResponse("ok"))(request)
        assert request.bouncer_ip == PROXY          # the active decision
        assert request.bouncer_ip_shadow == REAL    # the candidate being trialled
