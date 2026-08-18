"""Per-address rate limiting on a one-minute window.

Rules are matched by path prefix in order — the first match wins, after the
language prefix is stripped — and every limit is scaled by
``BOUNCER_RATE_MULTIPLIER``. The defaults are deliberately generic; a project
declares its own with ``BOUNCER_RATE_LIMIT_RULES``::

    BOUNCER_RATE_LIMIT_RULES = [
        ("/accounts/login", 10),
        ("/accounts/register", 5),
        ("/cart/apply-discount/", 15),
        ("/api/", 240),
        ("/", 240),
    ]

Behaviour on overflow:

* 429 with ``Retry-After`` on every request over the limit. A privileged
  request (staff, trusted address) never sees one.
* The violation is recorded once per minute bucket, not once per request.
  Otherwise a 5xx storm — where the browser retries and parallel AJAX piles
  up — would look like five violations in as many seconds and ban a real user.
* Ten times the burst limit inside a single minute is treated as hammering and
  evaluated immediately instead of waiting for the next bucket.
* ``django_bouncer.signals`` writes a login lock after repeated failures; this
  middleware turns that into a 429 on the login POST.
* When the peer address is unknown (``0.0.0.0``) no limit is applied at all,
  so unrelated visitors cannot share one bucket.
* When the cache is unavailable the limiter opens: availability wins over a
  limit that cannot be counted correctly anyway.
"""
from __future__ import annotations

import time

from django_bouncer import policy
from django_bouncer.policy import RateLimitRule  # noqa: F401  (re-exported)

from ._helpers import (
    get_client_ip,
    is_bannable_client_ip,
    is_exempt_path,
    is_privileged,
    is_static_path,
    log_event,
    once_per,
    too_many_requests_response,
)


def match_rule(path: str) -> RateLimitRule:
    rules = policy.rate_limit_rules()
    for rule in rules:
        if path.startswith(rule.path_prefix):
            return rule
    return rules[-1]


def burst_limit_for(rule: RateLimitRule) -> int:
    return max(
        1, int(rule.limit_per_minute * rule.burst_factor * policy.rate_multiplier())
    )


def login_locked(ip: str) -> int:
    """Remaining lock in seconds; 0 when there is no lock."""
    try:
        from django.core.cache import cache

        value = cache.get(f"bnc:loginlock:{ip}")
        if not value:
            return 0
        return max(1, int(float(value) - time.time()))
    except Exception:  # noqa: BLE001
        return 0


class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if is_static_path(path) or is_exempt_path(path):
            return self.get_response(request)

        layer_mode = policy.layer_mode(policy.LAYER_RATE_LIMIT)
        if layer_mode == policy.MODE_OFF:
            return self.get_response(request)
        enforcing = layer_mode == policy.MODE_ENFORCE

        from django.core.cache import cache

        from django_bouncer.models import SecurityEvent

        ip = get_client_ip(request)
        if not is_bannable_client_ip(ip):
            return self.get_response(request)

        # ── Login lockout (brute force) — the login POST only ────────────
        if request.method == "POST" and policy.is_login_path(path) and "login" in path:
            remaining = login_locked(ip)
            if remaining and not is_privileged(request, ip):
                log_event(
                    request,
                    reason=SecurityEvent.REASON_BRUTE_FORCE,
                    severity=SecurityEvent.SEVERITY_MEDIUM,
                    payload=f"login locked {remaining}s",
                    blocked=enforcing,
                    throttle_seconds=60,
                )
                if enforcing:
                    from django.utils.translation import gettext

                    return too_many_requests_response(
                        request,
                        retry_after=remaining,
                        reason="login_locked",
                        message=gettext(
                            "Too many failed sign-in attempts. Please wait before retrying."
                        ),
                    )

        rule = match_rule(policy.strip_lang_prefix(path))

        # ── Minute bucket counter (hot path: one round trip) ─────────────
        now = int(time.time())
        bucket = now // 60
        key = f"bnc:rl:{ip}:{rule.path_prefix}:{bucket}"
        try:
            count = cache.incr(key)
        except ValueError:
            try:
                count = 1 if cache.add(key, 1, timeout=120) else cache.incr(key)
            except Exception:  # noqa: BLE001
                count = None
        except Exception:  # noqa: BLE001
            count = None
        if not isinstance(count, int):
            # No cache (or IGNORE_EXCEPTIONS returned None): do not limit, keep
            # the site reachable.
            return self.get_response(request)

        burst_limit = burst_limit_for(rule)
        if count <= burst_limit:
            return self.get_response(request)

        # ── Over the limit ──────────────────────────────────────────────
        if is_privileged(request, ip):
            return self.get_response(request)

        if once_per(f"rlviol:{ip}:{rule.path_prefix}:{bucket}", 120):
            log_event(
                request,
                reason=SecurityEvent.REASON_RATE_LIMIT,
                severity=SecurityEvent.SEVERITY_MEDIUM,
                payload=f"{rule.path_prefix} {count}/{burst_limit}/min",
                blocked=enforcing,
            )
            if enforcing:
                self._tally_violation(request, ip)
        elif count == burst_limit * policy.RATE_HAMMER_FACTOR:
            log_event(
                request,
                reason=SecurityEvent.REASON_RATE_LIMIT,
                severity=SecurityEvent.SEVERITY_HIGH,
                payload=f"{rule.path_prefix} hammer {count}/min",
                blocked=enforcing,
            )
            if enforcing:
                self._tally_violation(request, ip)

        if not enforcing:
            return self.get_response(request)
        return too_many_requests_response(request, retry_after=60 - (now % 60))

    @staticmethod
    def _tally_violation(request, ip):
        from django_bouncer.ban_policy import evaluate_auto_ban

        evaluate_auto_ban(ip, "rate_limit", reason="rate_limit_repeated", request=request)
