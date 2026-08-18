"""IP ban enforcement — runs ahead of every other security layer.

A banned address gets a 403 before it touches an endpoint. The exceptions all
exist so that this layer can never be the reason you lose access to your own
site:

* ``BOUNCER_BAN_ENFORCEMENT`` is off by default. Ban rows are still written and
  kept for audit, but nobody is turned away until you switch it on.
* Static and exempt paths (webhooks, ``/.well-known/``, robots) pass through.
* A privileged request passes: a trusted IP, an address a staff user recently
  signed in from, or a live staff session — read from the session cookie, so it
  works even though this middleware runs before ``AuthenticationMiddleware``.
* Under a *temporary* ban the login pages stay reachable. A staff member signs
  in, :mod:`django_bouncer.signals` lifts the ban and marks the address trusted
  for a week. The login view keeps its own rate limit and brute-force lock, and
  a permanent ban closes this door too.

On the response side, if a view resolved ``request.user`` and it is staff, the
trust window is refreshed without a database query.
"""
from __future__ import annotations

from django_bouncer import policy

from ._helpers import (
    block_response,
    get_client_ip,
    is_exempt_path,
    is_privileged,
    is_static_path,
    log_event,
    refresh_staff_trust_from_response,
)


class IPBanMiddleware:
    """Rejects banned addresses at the earliest possible point (cache-first)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if is_static_path(path) or is_exempt_path(path):
            return self.get_response(request)

        layer_mode = policy.layer_mode(policy.LAYER_IP_BAN)
        if layer_mode == policy.MODE_OFF or not policy.ban_enforcement_enabled():
            # Observe-only: existing rows stay for audit, no visitor is turned
            # away. The other layers keep protecting each request on their own.
            return self._pass(request)

        from django_bouncer.models import BannedIP, SecurityEvent

        ip = get_client_ip(request)
        kind = BannedIP.ban_kind(ip)
        if kind is not None:
            if is_privileged(request, ip):
                # Staff or trusted: ignore the ban, but leave a low-severity
                # breadcrumb every five minutes for diagnosis.
                log_event(
                    request,
                    reason=SecurityEvent.REASON_IP_BANNED,
                    severity=SecurityEvent.SEVERITY_LOW,
                    payload="bypass:privileged",
                    blocked=False,
                    throttle_seconds=300,
                )
                return self._pass(request)
            if kind == "temp" and policy.is_login_path(path):
                return self._pass(request)

            enforcing = layer_mode == policy.MODE_ENFORCE
            # A browser retries several sub-resources at once. Keep the audit
            # useful without one row per blocked sub-request.
            log_event(
                request,
                reason=SecurityEvent.REASON_IP_BANNED,
                severity=SecurityEvent.SEVERITY_HIGH,
                blocked=enforcing,
                throttle_seconds=60,
            )
            if not enforcing:
                return self._pass(request)
            return block_response(
                request,
                reason="ip_banned",
                ip=ip,
                banned=True,
                show_login=(kind == "temp"),
            )

        return self._pass(request)

    def _pass(self, request):
        response = self.get_response(request)
        refresh_staff_trust_from_response(request)
        return response
