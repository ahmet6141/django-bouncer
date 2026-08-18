"""Visitor-facing text is translatable and ships with a Turkish catalogue."""
from __future__ import annotations

from django.test import RequestFactory
from django.utils import translation

from django_bouncer.middleware._helpers import block_response, too_many_requests_response

rf = RequestFactory()


def _page(**kwargs):
    request = rf.get("/x/", REMOTE_ADDR="203.0.113.5")
    return block_response(request, **kwargs).content.decode()


def test_default_language_is_english():
    with translation.override("en"):
        assert "rejected by the security policy" in _page(reason="waf_xss")


def test_turkish_catalogue_is_compiled_and_used():
    with translation.override("tr"):
        body = _page(reason="ip_banned", banned=True)
        assert "güvenlik politikası tarafından reddedildi" in body
        assert "geçici olarak engellendi" in body


def test_rate_limit_page_is_translated():
    request = rf.get("/x/", REMOTE_ADDR="203.0.113.5")
    with translation.override("tr"):
        body = too_many_requests_response(request, retry_after=30).content.decode()
    assert "Çok fazla istek gönderdiniz" in body
    assert "30" in body


def test_json_error_is_translated_too():
    request = rf.get("/api/x/", REMOTE_ADDR="203.0.113.5")
    with translation.override("tr"):
        payload = block_response(request, reason="waf_sqli").content.decode()
    assert "reddedildi" in payload
