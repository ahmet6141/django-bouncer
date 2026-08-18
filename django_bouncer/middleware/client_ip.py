"""Resolve the trusted client IP once, before any IP-based layer runs."""

from __future__ import annotations

import logging

from django_bouncer import policy
from django_bouncer.client_ip import REQUEST_ATTR, get_client_ip, resolve_client_ip

logger = logging.getLogger("django_bouncer.client_ip")


class ClientIPMiddleware:
    """Publishes ``request.bouncer_ip`` for every later layer and for views.

    With ``BOUNCER_SHADOW_PROXY_COUNT`` set, a second candidate is resolved
    with that count and logged whenever it disagrees with the active one. That
    is how a proxy-count change gets validated against live traffic before it
    is switched on — the shadow value never influences a decision.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        active = get_client_ip(request)
        setattr(request, REQUEST_ATTR, active)

        shadow_count = policy.shadow_proxy_count()
        if shadow_count:
            candidate = resolve_client_ip(request, trusted_proxy_count=shadow_count)
            request.bouncer_ip_shadow = candidate
            if candidate != active:
                logger.info(
                    "client_ip_shadow_mismatch active=%s candidate=%s path=%s",
                    active,
                    candidate,
                    request.path[:256],
                )

        return self.get_response(request)
