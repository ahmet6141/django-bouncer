"""Shared fixtures.

Everything in this package is cache-backed, so a leaked counter or a leaked
parse cache between tests would produce results that depend on ordering.
"""
from __future__ import annotations

import pytest
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory

from django_bouncer.middleware import _helpers

CLIENT = "88.230.10.20"      # a plausible residential address
ATTACKER = "45.33.32.156"
CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

rf = RequestFactory()


@pytest.fixture(autouse=True)
def _clean_state():
    cache.clear()
    _helpers.reset_caches()
    yield
    cache.clear()
    _helpers.reset_caches()


def ok(_request):
    return HttpResponse("OK")


def req(path="/", method="GET", ip=CLIENT, ua=CHROME, staff=False, authed=False, **extra):
    """A browser-shaped request with the session lookup pre-answered.

    ``session_user_info`` is memoised on the request, so setting the memo is
    enough to simulate a staff or signed-in visitor without a database.
    """
    factory_method = getattr(rf, method.lower())
    request = factory_method(
        path,
        REMOTE_ADDR=ip,
        HTTP_USER_AGENT=ua,
        HTTP_ACCEPT="text/html,*/*",
        HTTP_ACCEPT_LANGUAGE="en",
        HTTP_ACCEPT_ENCODING="gzip",
        **extra,
    )
    if staff:
        request._bouncer_user_info = {"id": 1, "staff": True}
    elif authed:
        request._bouncer_user_info = {"id": 2, "staff": False}
    else:
        request._bouncer_user_info = {"id": None, "staff": False}
    return request
