"""Trusted client-IP resolution for the whole application.

Forwarded headers are attacker-controlled unless every hop counted from the
right is a proxy you operate. A production nginx that replaces
``X-Forwarded-For`` with one validated address has a trusted proxy count of
exactly one; behind Cloudflare plus that nginx it is still one, because nginx
rewrites the header. Local development defaults to zero and ignores every
forwarded IP header.

Getting this number wrong is the single most damaging misconfiguration in this
package: too high and any visitor can spoof an address (banning someone else,
or evading their own ban); too low and every visitor collapses into one rate
bucket. ``manage.py bouncer_status`` prints what the current setting resolves
to for a sample chain, and :func:`resolve_client_ip` fails closed to the socket
peer whenever the chain is shorter than expected.
"""

from __future__ import annotations

import ipaddress
import logging

from django.http import HttpRequest
from django.http.request import split_domain_port

from django_bouncer import policy

logger = logging.getLogger("django_bouncer.client_ip")

# Canonical sentinel for requests where no valid peer address is available.
# It is data returned by the resolver, never a network bind address.
UNSPECIFIED_IP = str(ipaddress.IPv4Address(0))

#: Attribute set by ``ClientIPMiddleware`` and readable by application code.
REQUEST_ATTR = "bouncer_ip"


def normalize_ip(value: object) -> str | None:
    """Return a canonical IPv4/IPv6 address, rejecting arbitrary text."""
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        domain, port = split_domain_port(raw)
        if not (domain and port):
            return None
        if domain.startswith("[") and domain.endswith("]"):
            domain = domain[1:-1]
        try:
            return str(ipaddress.ip_address(domain))
        except ValueError:
            return None


def is_bannable_client_ip(value: object) -> bool:
    """Whether an address identifies a real peer for IP-wide enforcement.

    ``0.0.0.0`` and ``::`` mean "unspecified"; either can appear when a request
    arrives through a Unix socket without the trusted proxy contract loaded.
    Treating one as a client would merge unrelated visitors into a single rate
    bucket and could ban the entire site at once.
    """
    normalized = normalize_ip(value)
    if normalized is None:
        return False
    return not ipaddress.ip_address(normalized).is_unspecified


def resolve_client_ip(
    request: HttpRequest,
    *,
    trusted_proxy_count: int,
    default: str = UNSPECIFIED_IP,
) -> str:
    """Resolve an IP for an explicit, deployment-owned proxy count.

    The right-most trusted position is used, matching django-allauth's secure
    proxy-count semantics. Invalid or shorter-than-expected chains fail closed
    to the socket peer instead of accepting another header value.
    """
    remote_addr = normalize_ip(request.META.get("REMOTE_ADDR"))
    fallback = remote_addr or normalize_ip(default) or UNSPECIFIED_IP

    if trusted_proxy_count <= 0:
        return fallback

    forwarded = str(request.META.get("HTTP_X_FORWARDED_FOR") or "").strip()
    if not forwarded:
        return fallback

    entries = [entry.strip() for entry in forwarded.split(",")]
    if len(entries) < trusted_proxy_count:
        logger.warning(
            "Client IP proxy count exceeds forwarded chain length: count=%s length=%s",
            trusted_proxy_count,
            len(entries),
        )
        return fallback

    candidate = normalize_ip(entries[-trusted_proxy_count])
    if candidate is None:
        logger.warning("Rejected malformed client IP in trusted forwarded position")
        return fallback
    return candidate


def get_client_ip(request: HttpRequest, default: str = UNSPECIFIED_IP) -> str:
    """Return the active, trusted client IP configured for this environment.

    ``ClientIPMiddleware`` resolves it once per request; this function reuses
    that answer and only recomputes it when the middleware is absent (which is
    also what makes the helper safe to call from application code).
    """
    cached = getattr(request, REQUEST_ATTR, None)
    if cached:
        return cached
    return resolve_client_ip(
        request,
        trusted_proxy_count=policy.trusted_proxy_count(),
        default=default,
    )
