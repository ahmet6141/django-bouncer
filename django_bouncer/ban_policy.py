"""Conservative automatic IP-ban policy.

Request-level controls still reject an individual malicious request
immediately. A shared public address is promoted to a site-wide ban only after
repeated, independent signals. That distinction is the whole point: mobile
carriers (CGNAT), offices, universities, VPNs and developer tooling all put
many unrelated people behind one address, and a single confident-looking
signature is not worth locking them all out.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.core.cache import cache
from django.utils import timezone

from django_bouncer import policy
from django_bouncer.models import BannedIP, SecurityEvent


@dataclass(frozen=True)
class AutoBanPolicy:
    reasons: tuple
    threshold: int
    window_minutes: int
    duration_minutes: int
    minimum_distinct_paths: int = 1


POLICIES = {
    # A single probe gets a 404, but it does not ban a household or a company.
    # Real scanners enumerate several unrelated paths.
    "honeypot_url": AutoBanPolicy(
        reasons=(SecurityEvent.REASON_HONEYPOT_URL,),
        threshold=3,
        window_minutes=10,
        duration_minutes=30,
        minimum_distinct_paths=3,
    ),
    # WAF false positives happen in search text and product descriptions.
    # Require repetition across more than one endpoint before a global ban.
    "waf": AutoBanPolicy(
        reasons=(
            SecurityEvent.REASON_WAF_SQLI,
            SecurityEvent.REASON_WAF_XSS,
            SecurityEvent.REASON_WAF_PATH_TRAVERSAL,
            SecurityEvent.REASON_WAF_CMD_INJECTION,
        ),
        threshold=5,
        window_minutes=10,
        duration_minutes=60,
        minimum_distinct_paths=2,
    ),
    # Rate-limit events are already deduplicated to one event per minute.
    "rate_limit": AutoBanPolicy(
        reasons=(SecurityEvent.REASON_RATE_LIMIT,),
        threshold=5,
        window_minutes=10,
        duration_minutes=15,
    ),
}


# Signals a signed-in account can trigger by accident: search text, a product
# description, a burst of restored tabs. An account is traceable, so abuse is
# handled at account level; a global IP ban would also hit CGNAT neighbours.
SOFT_POLICIES = frozenset({"waf", "rate_limit"})


def evaluate_auto_ban(ip: str, policy_name: str, *, reason: str, request=None) -> bool:
    """Apply a policy after its triggering event has been persisted.

    Returns True only when this call creates a new automatic ban. User-Agent
    detections and form honeypots deliberately have no ban policy at all: the
    individual request stays blocked, and sustained abuse is caught by rate
    limiting instead.

    When ``request`` is given, a privileged request (trusted IP, staff-trusted
    IP, active staff session) never creates a ban, and an authenticated user is
    not IP-banned for a soft policy.
    """
    if not policy.auto_ban_enabled():
        return False
    from django_bouncer.client_ip import is_bannable_client_ip

    if not is_bannable_client_ip(ip):
        return False
    if request is not None:
        from django_bouncer.middleware._helpers import (
            is_authenticated_request,
            is_privileged,
        )

        if is_privileged(request, ip):
            return False
        if policy_name in SOFT_POLICIES and is_authenticated_request(request):
            return False

    ban_policy = POLICIES[policy_name]
    cutoff = timezone.now() - timezone.timedelta(minutes=ban_policy.window_minutes)
    events = SecurityEvent.objects.filter(
        ip=ip,
        reason__in=ban_policy.reasons,
        created_at__gte=cutoff,
    )
    if events.count() < ban_policy.threshold:
        return False
    if (
        ban_policy.minimum_distinct_paths > 1
        and events.values("path").distinct().count() < ban_policy.minimum_distinct_paths
    ):
        return False

    # Collapse concurrent threshold-crossing requests into one write.
    lock_key = f"bnc:auto-ban-lock:{policy_name}:{ip}"
    if not cache.add(lock_key, "1", timeout=30):
        return False

    note = (
        f"Automatic {policy_name} policy: at least {ban_policy.threshold} signals "
        f"within {ban_policy.window_minutes} minutes"
    )
    return BannedIP.add_automatic_ban(
        ip,
        reason=reason,
        minutes=ban_policy.duration_minutes,
        note=note,
    )
