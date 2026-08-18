"""Security audit log and IP ban list.

Two tables, both small by design:

``SecurityEvent``  append-only audit trail. Every layer writes here, throttled,
                   so "why was this address blocked?" has an answer that does
                   not depend on log retention. ``manage.py bouncer_prune``
                   keeps it bounded.
``BannedIP``       the ban list itself. Reads go through the cache; writes
                   invalidate it. An automatic ban can never overwrite,
                   shorten or extend a manual one.
"""
from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class SecurityEvent(models.Model):
    """A persisted record of one detected event.

    Reasons are categorised so the admin and ``bouncer_report`` can group them,
    and so :mod:`django_bouncer.ban_policy` can count only the reasons a given
    policy cares about.
    """

    SEVERITY_LOW = 10
    SEVERITY_MEDIUM = 20
    SEVERITY_HIGH = 30
    SEVERITY_CRITICAL = 40
    SEVERITY_CHOICES = [
        (SEVERITY_LOW, _("low")),
        (SEVERITY_MEDIUM, _("medium")),
        (SEVERITY_HIGH, _("high")),
        (SEVERITY_CRITICAL, _("critical")),
    ]

    REASON_WAF_SQLI = "waf_sqli"
    REASON_WAF_XSS = "waf_xss"
    REASON_WAF_PATH_TRAVERSAL = "waf_path"
    REASON_WAF_CMD_INJECTION = "waf_cmd"
    REASON_BOT_UA_BLACKLIST = "bot_ua"
    REASON_BOT_HEADLESS = "bot_headless"
    REASON_BOT_NO_HEADERS = "bot_no_headers"
    REASON_RATE_LIMIT = "rate_limit"
    REASON_HONEYPOT_URL = "honeypot_url"
    REASON_HONEYPOT_FORM = "honeypot_form"
    REASON_BRUTE_FORCE = "brute_force"
    REASON_SCRAPER = "scraper"
    REASON_CSP_VIOLATION = "csp_violation"
    REASON_IP_BANNED = "ip_banned"
    REASON_BAN_LIFTED = "ban_lifted"
    REASON_CHOICES = [
        (REASON_WAF_SQLI, "waf_sqli"),
        (REASON_WAF_XSS, "waf_xss"),
        (REASON_WAF_PATH_TRAVERSAL, "waf_path"),
        (REASON_WAF_CMD_INJECTION, "waf_cmd"),
        (REASON_BOT_UA_BLACKLIST, "bot_ua"),
        (REASON_BOT_HEADLESS, "bot_headless"),
        (REASON_BOT_NO_HEADERS, "bot_no_headers"),
        (REASON_RATE_LIMIT, "rate_limit"),
        (REASON_HONEYPOT_URL, "honeypot_url"),
        (REASON_HONEYPOT_FORM, "honeypot_form"),
        (REASON_BRUTE_FORCE, "brute_force"),
        (REASON_SCRAPER, "scraper"),
        (REASON_CSP_VIOLATION, "csp_violation"),
        (REASON_IP_BANNED, "ip_banned"),
        (REASON_BAN_LIFTED, "ban_lifted"),
    ]

    ip = models.GenericIPAddressField(db_index=True)
    user_agent = models.CharField(max_length=512, blank=True)
    method = models.CharField(max_length=8, blank=True)
    path = models.CharField(max_length=512, blank=True)
    referer = models.CharField(max_length=512, blank=True)
    reason = models.CharField(max_length=32, db_index=True, choices=REASON_CHOICES)
    severity = models.PositiveSmallIntegerField(
        choices=SEVERITY_CHOICES, default=SEVERITY_MEDIUM, db_index=True
    )
    payload_snippet = models.CharField(
        max_length=500,
        blank=True,
        help_text=_("The fragment that matched, taken from the URL or body (max 500 chars)."),
    )
    blocked = models.BooleanField(
        default=False,
        help_text=_("True when the request was rejected; False when it was only logged."),
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = _("security event")
        verbose_name_plural = _("security events")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "severity"], name="bnc_evt_recent_sev_idx"),
            models.Index(fields=["ip", "-created_at"], name="bnc_evt_ip_recent_idx"),
        ]

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.reason} {self.ip} {self.path[:40]}"


class BannedIP(models.Model):
    """A permanent or temporary IP ban.

    Lookups are cache-first: middleware asks the cache, falls back to the
    database on a miss, and caches the answer for exactly the ban's remaining
    lifetime so an expiry cannot be outlived by a stale entry.
    """

    ip = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.CharField(max_length=64, blank=True)
    is_permanent = models.BooleanField(default=False)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text=_("Empty together with permanent means forever; otherwise the deadline."),
    )
    hit_count = models.PositiveIntegerField(default=0)
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("banned IP")
        verbose_name_plural = _("banned IPs")
        ordering = ["-created_at"]

    def __str__(self):
        kind = "perma" if self.is_permanent else "temp"
        return f"[{kind}] {self.ip} — {self.reason}"

    def clean(self):
        super().clean()
        from django_bouncer.client_ip import is_bannable_client_ip

        if self.ip and not is_bannable_client_ip(self.ip):
            raise ValidationError({"ip": _("Unspecified addresses cannot be banned.")})

    @property
    def is_active(self) -> bool:
        if self.is_permanent:
            return True
        if self.expires_at is None:
            return False
        return self.expires_at > timezone.now()

    # ── Cache-aware reads ────────────────────────────────────────────────

    @classmethod
    def cache_key(cls, ip: str) -> str:
        return f"bnc:ban:{ip}"

    @classmethod
    def is_banned(cls, ip: str) -> bool:
        """Cache-aware ban check.

        Cache value semantics:
            ``"p"``            permanent ban
            ``"e:<epoch>"``    temporary ban with its exact deadline
            ``"0"``            not banned (negative cache, short TTL)
        """
        from django.core.cache import cache

        from django_bouncer.client_ip import is_bannable_client_ip

        if not is_bannable_client_ip(ip):
            cache.delete(cls.cache_key(ip))
            return False
        key = cls.cache_key(ip)
        value = cache.get(key)
        if value == "p":
            return True
        if value == "0":
            return False
        if isinstance(value, str) and value.startswith("e:"):
            try:
                if float(value[2:]) > timezone.now().timestamp():
                    return True
            except ValueError:
                pass
            cache.delete(key)
        elif value is not None:
            # Unknown shape (an older release, or another writer): revalidate
            # rather than trust it, so an expired ban cannot stay active.
            cache.delete(key)

        now = timezone.now()
        ban = (
            cls.objects.filter(ip=ip)
            .filter(models.Q(is_permanent=True) | models.Q(expires_at__gt=now))
            .only("ip", "is_permanent", "expires_at")
            .first()
        )
        if ban is None:
            cache.set(key, "0", timeout=60)
            return False
        cls._cache_active_ban(ban)
        return True

    @classmethod
    def _cache_active_ban(cls, ban: BannedIP) -> None:
        """Cache a ban for exactly its remaining lifetime."""
        from django.core.cache import cache

        key = cls.cache_key(ban.ip)
        if ban.is_permanent:
            # Revalidate permanent rows periodically so an out-of-band database
            # correction cannot leave an address blocked forever in cache.
            cache.set(key, "p", timeout=600)
            return
        if ban.expires_at is None:
            cache.set(key, "0", timeout=60)
            return
        remaining = max(1, int((ban.expires_at - timezone.now()).total_seconds()) + 1)
        cache.set(key, f"e:{ban.expires_at.timestamp()}", timeout=remaining)

    @classmethod
    def ban_kind(cls, ip: str) -> str | None:
        """``None`` | ``"temp"`` | ``"perm"`` — same cache/DB path as is_banned."""
        if not cls.is_banned(ip):
            return None
        from django.core.cache import cache

        return "perm" if cache.get(cls.cache_key(ip)) == "p" else "temp"

    # ── Writes ───────────────────────────────────────────────────────────

    @classmethod
    def add_ban(
        cls,
        ip: str,
        reason: str = "",
        *,
        hours: int | None = None,
        permanent: bool = False,
        note: str = "",
    ) -> BannedIP:
        """Ban an address manually (database write plus cache refresh).

        Args:
            ip: Target address.
            reason: Short category, e.g. ``rate_limit`` or ``waf_sqli``.
            hours: Temporary duration; ``None`` with ``permanent=False`` is 24h.
            permanent: Never expires.
            note: Free-form operator note.
        """
        from django_bouncer.client_ip import is_bannable_client_ip

        if not is_bannable_client_ip(ip):
            raise ValueError("Unspecified addresses cannot be banned")
        defaults = {
            "reason": reason[:64],
            "is_permanent": permanent,
            "note": note,
        }
        if permanent:
            defaults["expires_at"] = None
        else:
            duration = hours if hours is not None else 24
            defaults["expires_at"] = timezone.now() + timezone.timedelta(hours=duration)
        obj, _created = cls.objects.update_or_create(ip=ip, defaults=defaults)
        cls.objects.filter(pk=obj.pk).update(hit_count=models.F("hit_count") + 1)
        obj.refresh_from_db()
        cls._cache_active_ban(obj)
        return obj

    @classmethod
    def add_automatic_ban(
        cls,
        ip: str,
        *,
        reason: str,
        minutes: int,
        note: str = "",
    ) -> bool:
        """Create a temporary ban without mutating an already-active one.

        An automatic detector must not be able to replace a manual permanent
        ban, rewrite its reason or note, or keep pushing a temporary deadline
        forward as concurrent requests arrive. Returns True only for a new or
        previously expired ban.
        """
        from django_bouncer.client_ip import is_bannable_client_ip

        if not is_bannable_client_ip(ip):
            return False
        expires_at = timezone.now() + timezone.timedelta(minutes=minutes)
        with transaction.atomic():
            existing = cls.objects.select_for_update().filter(ip=ip).first()
            if existing is not None and existing.is_active:
                cls.objects.filter(pk=existing.pk).update(
                    hit_count=models.F("hit_count") + 1
                )
                cls._cache_active_ban(existing)
                return False

            if existing is None:
                ban = cls.objects.create(
                    ip=ip,
                    reason=reason[:64],
                    is_permanent=False,
                    expires_at=expires_at,
                    hit_count=1,
                    note=note,
                )
            else:
                existing.reason = reason[:64]
                existing.is_permanent = False
                existing.expires_at = expires_at
                existing.hit_count += 1
                existing.note = note
                existing.save(
                    update_fields=(
                        "reason",
                        "is_permanent",
                        "expires_at",
                        "hit_count",
                        "note",
                        "updated_at",
                    )
                )
                ban = existing
        cls._cache_active_ban(ban)
        return True

    @classmethod
    def remove_ban(cls, ip: str) -> bool:
        """Delete the row and drop the cache entry. Returns whether a row existed."""
        from django.core.cache import cache

        deleted, _details = cls.objects.filter(ip=ip).delete()
        cache.delete(cls.cache_key(ip))
        return bool(deleted)
