"""Shared helpers: trusted addresses, privilege detection, cache counters,
throttled event logging and block responses.

Client-IP resolution lives in :mod:`django_bouncer.client_ip` (the
``ClientIPMiddleware`` contract) and is only re-exported here.

Design rules every helper follows:

* A middleware asks :func:`is_privileged` immediately before it decides to
  block or ban — never on the happy path. The check can cost a session lookup,
  so it is paid only on the violation path.
* No helper raises. A cache outage, a database hiccup or a malformed header
  degrades the security layer, it never takes the site down with it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import time
from collections.abc import Iterable
from functools import lru_cache
from importlib import import_module

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.html import escape
from django.utils.translation import gettext

from django_bouncer import policy
from django_bouncer.client_ip import (  # noqa: F401  (re-exported)
    get_client_ip,
    is_bannable_client_ip,
)

logger = logging.getLogger("django_bouncer")


# ─────────────────────────────────────────────────────────────────────────
# Trusted addresses (BOUNCER_TRUSTED_IPS)
# ─────────────────────────────────────────────────────────────────────────

def _trusted_networks() -> tuple:
    """Addresses and CIDRs exempt from every layer.

    Loopback is always included so a local health check or a shell session on
    the box itself can never be locked out.
    """
    entries = list(policy.trusted_ips())
    entries.extend(["127.0.0.1", "::1"])
    return _parse_trusted_networks(tuple(entries))


@lru_cache(maxsize=16)
def _parse_trusted_networks(entries: tuple) -> tuple:
    """Parse networks with the current configuration as the cache key."""
    networks = []
    for entry in entries:
        try:
            if "/" in entry:
                networks.append(ipaddress.ip_network(entry, strict=False))
            else:
                suffix = "/32" if "." in entry else "/128"
                networks.append(ipaddress.ip_network(f"{entry}{suffix}"))
        except ValueError:
            logger.warning("Invalid BOUNCER_TRUSTED_IPS entry: %s", entry)
    return tuple(networks)


def is_trusted_ip(ip: str) -> bool:
    """Whether the address is whitelisted and bypasses every middleware."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in _trusted_networks())


def get_user_agent(request: HttpRequest) -> str:
    return (request.META.get("HTTP_USER_AGENT") or "")[:512]


# ─────────────────────────────────────────────────────────────────────────
# Path classes
# ─────────────────────────────────────────────────────────────────────────

_STATIC_PREFIXES = ("/favicon", "/robots.txt", "/sitemap")
_STATIC_EXTS = (
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".avif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webmanifest",
)


@lru_cache(maxsize=8)
def _static_prefixes(static_url: str, media_url: str) -> tuple:
    prefixes = list(_STATIC_PREFIXES)
    for url in (static_url, media_url):
        if url and url.startswith("/") and url != "/":
            prefixes.append(url if url.endswith("/") else url + "/")
    return tuple(prefixes)


def is_static_path(path: str) -> bool:
    """Static assets skip every layer: pure overhead and false-positive risk."""
    if not path:
        return False
    prefixes = _static_prefixes(
        str(getattr(settings, "STATIC_URL", "") or ""),
        str(getattr(settings, "MEDIA_URL", "") or ""),
    )
    if path.startswith(prefixes):
        return True
    return path.lower().endswith(_STATIC_EXTS)


def is_admin_path(path: str) -> bool:
    return path.startswith(("/admin/", "/django-admin/"))


def is_exempt_path(path: str) -> bool:
    return policy.is_exempt_path(path)


def is_api_path(path: str) -> bool:
    """Endpoints where programmatic clients are expected and normal."""
    return policy.is_api_path(path)


# ─────────────────────────────────────────────────────────────────────────
# User / privilege
# ─────────────────────────────────────────────────────────────────────────

_SESSION_INFO_TTL = 300  # seconds


def session_user_info(request: HttpRequest) -> dict:
    """``{"id": <pk|None>, "staff": bool}`` read straight from the session.

    This works even when the security middleware runs before Django's
    ``AuthenticationMiddleware`` — which it must, because a banned address has
    to be rejected before any application code runs. The result is memoised on
    the request and cached per session key for five minutes, and it is only
    consulted on a violation path.
    """
    memo = getattr(request, "_bouncer_user_info", None)
    if memo is not None:
        return memo
    info = {"id": None, "staff": False}
    try:
        # If AuthenticationMiddleware already ran (a different ordering), use it.
        user = request.__dict__.get("user")
        if user is not None and getattr(user, "is_authenticated", False):
            info = {
                "id": user.pk,
                "staff": bool(
                    getattr(user, "is_staff", False) and getattr(user, "is_active", True)
                ),
            }
        else:
            key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
            if key:
                from django.core.cache import cache

                cache_key = "bnc:sess:" + hashlib.sha256(key.encode()).hexdigest()[:32]
                cached = cache.get(cache_key)
                if isinstance(cached, dict):
                    info = cached
                else:
                    engine = import_module(settings.SESSION_ENGINE)
                    store = engine.SessionStore(session_key=key)
                    user_id = store.get("_auth_user_id")
                    if user_id:
                        from django.contrib.auth import get_user_model

                        row = (
                            get_user_model()
                            .objects.filter(pk=user_id)
                            .values_list("is_staff", "is_active")
                            .first()
                        )
                        if row and row[1]:
                            info = {"id": user_id, "staff": bool(row[0])}
                    cache.set(cache_key, info, _SESSION_INFO_TTL)
    except Exception as exc:  # noqa: BLE001
        logger.debug("session_user_info failed: %s", exc)
    try:
        request._bouncer_user_info = info
    except Exception:  # noqa: BLE001
        pass
    return info


def is_authenticated_request(request: HttpRequest) -> bool:
    return bool(session_user_info(request).get("id"))


def is_staff_request(request: HttpRequest) -> bool:
    if not policy.staff_bypass_enabled():
        return False
    return bool(session_user_info(request).get("staff"))


def _staff_trust_key(ip: str) -> str:
    return f"bnc:stafftrust:{ip}"


def is_staff_trusted_ip(ip: str) -> bool:
    """An address a staff user signed in from within the trust window."""
    if not ip or not policy.staff_bypass_enabled() or policy.staff_trust_days() <= 0:
        return False
    try:
        from django.core.cache import cache

        return bool(cache.get(_staff_trust_key(ip)))
    except Exception:  # noqa: BLE001
        return False


def mark_staff_trusted_ip(ip: str, *, days: int | None = None) -> None:
    if not ip or not is_bannable_client_ip(ip):
        return
    days = policy.staff_trust_days() if days is None else days
    if days <= 0:
        return
    try:
        from django.core.cache import cache

        cache.set(_staff_trust_key(ip), 1, timeout=days * 86400)
    except Exception:  # noqa: BLE001
        pass


def unmark_staff_trusted_ip(ip: str) -> None:
    try:
        from django.core.cache import cache

        cache.delete(_staff_trust_key(ip))
    except Exception:  # noqa: BLE001
        pass


def is_privileged(request: HttpRequest, ip: str | None = None) -> bool:
    """Should this request be exempt from every security decision?

    Checks run cheapest first: trusted IP, then staff-trusted IP (cache), then
    an active staff session (session lookup). The answer is memoised on the
    request.
    """
    memo = getattr(request, "_bouncer_privileged", None)
    if memo is not None:
        return memo
    ip = ip or get_client_ip(request)
    result = is_trusted_ip(ip) or is_staff_trusted_ip(ip) or is_staff_request(request)
    if result and is_staff_request(request):
        _refresh_staff_trust(ip)  # a live staff session keeps the IP fresh
    try:
        request._bouncer_privileged = result
    except Exception:  # noqa: BLE001
        pass
    return result


def _refresh_staff_trust(ip: str) -> None:
    try:
        from django.core.cache import cache

        if cache.add(f"bnc:stafftrust:refresh:{ip}", 1, timeout=3600):
            mark_staff_trusted_ip(ip)
    except Exception:  # noqa: BLE001
        pass


def refresh_staff_trust_from_response(request: HttpRequest) -> None:
    """Response phase: if a view or template resolved ``request.user`` and it
    is staff, refresh the trust window. Cheap — it never hits the database and
    never forces the lazy object."""
    try:
        from django.utils.functional import SimpleLazyObject, empty

        user = request.__dict__.get("_cached_user")
        if user is None:
            lazy = request.__dict__.get("user")
            if isinstance(lazy, SimpleLazyObject):
                wrapped = lazy._wrapped
                user = None if wrapped is empty else wrapped
            elif lazy is not None:
                user = lazy
        if (
            user is not None
            and getattr(user, "is_authenticated", False)
            and getattr(user, "is_staff", False)
            and getattr(user, "is_active", True)
        ):
            _refresh_staff_trust(get_client_ip(request))
    except Exception:  # noqa: BLE001
        pass


# ─────────────────────────────────────────────────────────────────────────
# Counters (per-minute cache buckets)
# ─────────────────────────────────────────────────────────────────────────

def _bucket(now: float | None = None) -> int:
    return int(now if now is not None else time.time()) // 60


def bump_counter(kind: str, ip: str, window_minutes: int, *, amount: int = 1) -> int:
    """Increment this minute's counter and return the sum over the window.

    Returns 0 when the cache is unavailable, which is the safe direction: no
    counter means no threshold is ever crossed, so an outage cannot ban anyone.
    """
    try:
        from django.core.cache import cache

        bucket = _bucket()
        ttl = (window_minutes + 2) * 60
        key = f"bnc:c:{kind}:{ip}:{bucket}"
        cache.add(key, 0, timeout=ttl)
        try:
            current = cache.incr(key, amount)
        except ValueError:
            cache.set(key, amount, timeout=ttl)
            current = amount
        total = int(current or 0)
        if window_minutes > 1:
            previous = [
                f"bnc:c:{kind}:{ip}:{bucket - offset}"
                for offset in range(1, window_minutes)
            ]
            for value in cache.get_many(previous).values():
                try:
                    total += int(value or 0)
                except (TypeError, ValueError):
                    continue
        return total
    except Exception as exc:  # noqa: BLE001
        logger.debug("bump_counter failed: %s", exc)
        return 0


def count_in_window(kind: str, ip: str, window_minutes: int) -> int:
    try:
        from django.core.cache import cache

        bucket = _bucket()
        keys = [f"bnc:c:{kind}:{ip}:{bucket - offset}" for offset in range(window_minutes)]
        total = 0
        for value in cache.get_many(keys).values():
            try:
                total += int(value or 0)
            except (TypeError, ValueError):
                continue
        return total
    except Exception:  # noqa: BLE001
        return 0


def once_per(key: str, seconds: int) -> bool:
    """True for the first call within ``seconds``, False afterwards."""
    try:
        from django.core.cache import cache

        return bool(cache.add(f"bnc:once:{key}", 1, timeout=seconds))
    except Exception:  # noqa: BLE001
        return True


# ─────────────────────────────────────────────────────────────────────────
# Event log
# ─────────────────────────────────────────────────────────────────────────

def log_event(
    request: HttpRequest,
    *,
    reason: str,
    severity: int,
    payload: str = "",
    blocked: bool = False,
    throttle_seconds: int = 0,
    throttle_key: str = "",
) -> bool:
    """Write a :class:`~django_bouncer.models.SecurityEvent`.

    With ``throttle_seconds`` set, only one row is written per
    ``(ip, reason[, throttle_key])`` in that window. Returns whether a row was
    written. A database failure is logged and swallowed.

    Note: the ban policy counts persisted events, so policy-relevant reasons
    (``honeypot_url``, ``waf_*``, ``rate_limit``) pass the path as the throttle
    key — otherwise several distinct paths would collapse into one event and
    the "at least N distinct paths" guard could never be satisfied.
    """
    from django_bouncer.models import SecurityEvent

    ip = get_client_ip(request)
    if throttle_seconds:
        key = f"ev:{reason}:{ip}" + (f":{throttle_key}" if throttle_key else "")
        if not once_per(key, throttle_seconds):
            return False
    try:
        info = (
            session_user_info(request)
            if request.COOKIES.get(settings.SESSION_COOKIE_NAME)
            else {"id": None}
        )
        SecurityEvent.objects.create(
            ip=ip,
            user_agent=get_user_agent(request),
            method=(request.method or "")[:8],
            path=(request.path or "")[:512],
            referer=(request.META.get("HTTP_REFERER", "") or "")[:512],
            reason=reason[:32],
            severity=severity,
            payload_snippet=(payload or "")[:500],
            blocked=blocked,
            user_id=info.get("id") or None,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.exception("SecurityEvent could not be written: %s", exc)
        return False


# ─────────────────────────────────────────────────────────────────────────
# Responses
# ─────────────────────────────────────────────────────────────────────────

_PAGE_CSS = (
    "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
    "background:#f6f7f9;color:#111827;display:flex;align-items:center;"
    "justify-content:center;min-height:100vh;margin:0}"
    "main{max-width:520px;text-align:center;padding:2.5rem 2rem;background:#fff;"
    "border:1px solid #e5e7eb;border-radius:16px;box-shadow:0 8px 30px rgba(17,24,39,.06)}"
    "h1{font-size:3rem;margin:0 0 .5rem;letter-spacing:-.02em}"
    "p{color:#4b5563;line-height:1.55;margin:.4rem 0}"
    "code{background:#f3f4f6;color:#111827;padding:.15rem .5rem;border-radius:6px;font-size:.9em}"
    "a{color:#2563eb;font-weight:600;text-decoration:none}a:hover{text-decoration:underline}"
    "small{color:#9ca3af}"
)


def _wants_json(request: HttpRequest) -> bool:
    accept = (request.headers.get("Accept") or "").lower()
    return (
        accept.startswith("application/json")
        or is_api_path(request.path)
        or request.headers.get("X-Requested-With", "") == "XMLHttpRequest"
    )


def _finish(response: HttpResponse, reason: str) -> HttpResponse:
    response["Cache-Control"] = "no-store"
    response[policy.block_header_name()] = reason
    return response


def block_response(
    request: HttpRequest,
    *,
    reason: str = "blocked",
    status: int = 403,
    ip: str = "",
    banned: bool = False,
    show_login: bool = False,
) -> HttpResponse:
    """JSON for API-ish clients, a small self-contained HTML page otherwise.

    The page carries no project branding and no template dependency, so it also
    renders when the application itself is failing.
    """
    ip = ip or get_client_ip(request)
    if _wants_json(request):
        payload = {
            "error": "Forbidden" if status == 403 else "Not Found",
            "code": reason,
            "message": gettext("This request was rejected by the security policy."),
            "ip": ip,
        }
        return _finish(JsonResponse(payload, status=status), reason)

    login_hint = ""
    login_url = policy.login_url()
    if show_login and login_url:
        login_hint = "<p>{}</p>".format(
            gettext(
                "If you administer this site, <a href='%(url)s'>sign in</a>: the ban on "
                "the address you sign in from is lifted automatically."
            )
            % {"url": escape(login_url)}
        )
    support = policy.support_url()
    support_hint = ""
    if support:
        support_hint = "<p>{}</p>".format(
            gettext("If you believe this is a mistake, please <a href='%(url)s'>contact us</a>.")
            % {"url": escape(support)}
        )
    title = "Forbidden" if status == 403 else "Not Found"
    body = (
        "<!doctype html><meta charset='utf-8'>"
        "<meta name='robots' content='noindex'>"
        f"<title>{status} {title}</title>"
        f"<style>{_PAGE_CSS}</style>"
        f"<main><h1>{status}</h1>"
        f"<p>{escape(gettext('Your request was rejected by the security policy.'))}</p>"
        f"<p><code>{escape(reason)}</code> · <small>IP: {escape(ip)}</small></p>"
        + (
            f"<p>{escape(gettext('This address is temporarily blocked.'))}</p>"
            if banned
            else ""
        )
        + login_hint
        + support_hint
        + "</main>"
    )
    return _finish(
        HttpResponse(body, status=status, content_type="text/html; charset=utf-8"),
        reason,
    )


def too_many_requests_response(
    request: HttpRequest,
    *,
    retry_after: int,
    reason: str = "rate_limit",
    message: str = "",
) -> HttpResponse:
    retry_after = max(1, int(retry_after))
    default_message = gettext("You have sent too many requests.")
    if _wants_json(request):
        response = JsonResponse(
            {
                "error": "Too Many Requests",
                "code": reason,
                "retry_after": retry_after,
                "message": message or default_message,
            },
            status=429,
        )
    else:
        retry_hint = gettext(
            "Please try again in <strong>%(seconds)s</strong> seconds."
        ) % {"seconds": retry_after}
        body = (
            "<!doctype html><meta charset='utf-8'>"
            "<meta name='robots' content='noindex'>"
            "<title>429 Too Many Requests</title>"
            f"<style>{_PAGE_CSS}</style>"
            "<main><h1>429</h1>"
            f"<p>{escape(message or default_message)}</p>"
            f"<p>{retry_hint}</p>"
            "</main>"
        )
        response = HttpResponse(body, status=429, content_type="text/html; charset=utf-8")
    response["Retry-After"] = str(retry_after)
    return _finish(response, reason)


# ─────────────────────────────────────────────────────────────────────────
# Pattern helpers
# ─────────────────────────────────────────────────────────────────────────

def any_match(text: str, patterns: Iterable) -> str | None:
    """Return the first matching fragment, for logging and diagnosis."""
    if not text:
        return None
    for expression in patterns:
        match = expression.search(text)
        if match:
            return match.group(0)[:120]
    return None


def reset_caches() -> None:
    """Clear value-keyed parse caches (tests, and after a settings reload)."""
    _parse_trusted_networks.cache_clear()
    _static_prefixes.cache_clear()
    policy.reset_caches()
