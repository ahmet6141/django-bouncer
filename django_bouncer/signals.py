"""Auth signals wired into the security policy.

``user_logged_in``
    * A staff or superuser sign-in **lifts the ban on that address** and marks
      it trusted for ``BOUNCER_STAFF_TRUST_DAYS`` days. This is the primary
      recovery path when you ban your own address.
    * For everyone: the login lock and failure counters are cleared.

``user_login_failed``
    * Per-address failure counters. At the lock threshold a login lock is
      written and the login POST starts returning 429.
    * A much higher threshold over a longer window creates a temporary IP ban,
      but only when ``BOUNCER_AUTO_BAN`` is on. A privileged address is never
      locked or banned.
"""
from __future__ import annotations

import logging
import time

from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver

from django_bouncer import policy

logger = logging.getLogger("django_bouncer")

# 50 failures within 60 minutes → a 60 minute temporary ban (auto-ban only).
LOGIN_FAIL_BAN_COUNT = 50
LOGIN_FAIL_BAN_WINDOW_MIN = 60
LOGIN_FAIL_BAN_MINUTES = 60


def _ip_from(request) -> str:
    if request is None:
        return ""
    try:
        from django_bouncer.middleware._helpers import get_client_ip

        return get_client_ip(request)
    except Exception:  # noqa: BLE001
        return ""


@receiver(user_logged_in, dispatch_uid="django_bouncer.on_user_logged_in")
def on_user_logged_in(sender, request, user, **kwargs):
    ip = _ip_from(request)
    if not ip:
        return
    try:
        from django.core.cache import cache

        # Failure buckets expire on their own; clearing the lock is enough.
        cache.delete(f"bnc:loginlock:{ip}")
    except Exception:  # noqa: BLE001
        pass

    is_staff = bool(
        getattr(user, "is_staff", False) or getattr(user, "is_superuser", False)
    )
    if not is_staff or not policy.staff_bypass_enabled():
        return
    try:
        from django_bouncer.middleware._helpers import log_event, mark_staff_trusted_ip
        from django_bouncer.models import BannedIP, SecurityEvent

        mark_staff_trusted_ip(ip)
        if BannedIP.remove_ban(ip):
            logger.warning("Ban lifted by staff sign-in ip=%s user=%s", ip, user.pk)
            log_event(
                request,
                reason=SecurityEvent.REASON_BAN_LIFTED,
                severity=SecurityEvent.SEVERITY_LOW,
                payload=f"staff login user={user.pk}",
                blocked=False,
            )
        try:
            request._bouncer_privileged = True
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        logger.exception("on_user_logged_in failed: %s", exc)


@receiver(user_login_failed, dispatch_uid="django_bouncer.on_user_login_failed")
def on_user_login_failed(sender, credentials=None, request=None, **kwargs):
    ip = _ip_from(request)
    if not ip or request is None:
        return
    try:
        from django_bouncer.middleware._helpers import (
            bump_counter,
            is_bannable_client_ip,
            is_privileged,
            log_event,
        )
        from django_bouncer.models import BannedIP, SecurityEvent

        if not is_bannable_client_ip(ip) or is_privileged(request, ip):
            return
        fails_short = bump_counter("loginfail", ip, policy.LOGIN_FAIL_LOCK_WINDOW_MIN)
        fails_long = bump_counter("loginfail60", ip, LOGIN_FAIL_BAN_WINDOW_MIN)

        if fails_short >= policy.LOGIN_FAIL_LOCK_COUNT:
            from django.core.cache import cache

            lock_seconds = policy.LOGIN_FAIL_LOCK_MINUTES * 60
            # Store the lock deadline so Retry-After can be exact.
            cache.set(
                f"bnc:loginlock:{ip}",
                str(time.time() + lock_seconds),
                timeout=lock_seconds,
            )
            log_event(
                request,
                reason=SecurityEvent.REASON_BRUTE_FORCE,
                severity=SecurityEvent.SEVERITY_HIGH,
                payload=(
                    f"{fails_short} failed sign-ins / "
                    f"{policy.LOGIN_FAIL_LOCK_WINDOW_MIN}min → locked"
                ),
                blocked=True,
                throttle_seconds=60,
            )
        elif fails_short in (5, 10):
            log_event(
                request,
                reason=SecurityEvent.REASON_BRUTE_FORCE,
                severity=SecurityEvent.SEVERITY_MEDIUM,
                payload=(
                    f"{fails_short} failed sign-ins / "
                    f"{policy.LOGIN_FAIL_LOCK_WINDOW_MIN}min"
                ),
                blocked=False,
            )

        if (
            fails_long >= LOGIN_FAIL_BAN_COUNT
            and fails_long % 10 == 0
            and policy.auto_ban_enabled()
        ):
            if BannedIP.add_automatic_ban(
                ip,
                reason="brute_force_login",
                minutes=LOGIN_FAIL_BAN_MINUTES,
                note=f"{fails_long} failed sign-ins / {LOGIN_FAIL_BAN_WINDOW_MIN}min",
            ):
                logger.warning("brute-force IP ban ip=%s fails=%s", ip, fails_long)
    except Exception as exc:  # noqa: BLE001
        logger.exception("on_user_login_failed failed: %s", exc)
