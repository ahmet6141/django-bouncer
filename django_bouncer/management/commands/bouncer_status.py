"""bouncer_status — print the configuration that is actually in effect.

Every knob can come from settings **or** the environment, layers can be
overridden individually, and rate rules can be supplied as tuples, dicts or a
string. That flexibility is worth very little if nobody can tell what the
process ended up with, so this command resolves everything through the same
code path the middleware uses and prints the result.

    python manage.py bouncer_status
    python manage.py bouncer_status --json      # for monitoring or a smoke test
"""
from __future__ import annotations

import json

from django.conf import settings
from django.core.management.base import BaseCommand

from django_bouncer import __version__, policy
from django_bouncer.middleware import MIDDLEWARE_ORDER


class Command(BaseCommand):
    help = "Show the effective django-bouncer configuration."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--json", action="store_true", help="Machine-readable output.")

    def handle(self, *args, **options) -> None:
        data = self._collect()
        if options["json"]:
            self.stdout.write(json.dumps(data, indent=2, sort_keys=True))
            return
        self._render(data)

    # ── data ─────────────────────────────────────────────────────────────

    def _collect(self) -> dict:
        installed = [str(item) for item in getattr(settings, "MIDDLEWARE", ()) or ()]
        ours = [item for item in installed if item.startswith("django_bouncer.middleware.")]
        expected = [name for name in MIDDLEWARE_ORDER if name in ours]
        actual = sorted(expected, key=installed.index)

        data = {
            "version": __version__,
            "mode": policy.mode(),
            "layers": {layer: policy.layer_mode(layer) for layer in policy.LAYERS},
            "ban_enforcement": policy.ban_enforcement_enabled(),
            "auto_ban": policy.auto_ban_enabled(),
            "trusted_proxy_count": policy.trusted_proxy_count(),
            "shadow_proxy_count": policy.shadow_proxy_count(),
            "trusted_ips": list(policy.trusted_ips()),
            "staff_bypass": policy.staff_bypass_enabled(),
            "staff_trust_days": policy.staff_trust_days(),
            "rate_multiplier": policy.rate_multiplier(),
            "rate_limit_rules": [
                {
                    "prefix": rule.path_prefix,
                    "limit_per_minute": rule.limit_per_minute,
                    "burst_factor": rule.burst_factor,
                    "effective_burst": max(
                        1,
                        int(
                            rule.limit_per_minute
                            * rule.burst_factor
                            * policy.rate_multiplier()
                        ),
                    ),
                }
                for rule in policy.rate_limit_rules()
            ],
            "exempt_prefixes": list(policy.exempt_prefixes()),
            "api_prefixes": list(policy.api_prefixes()),
            "login_paths": list(policy.login_paths()),
            "honeypot_field": policy.honeypot_field_name(),
            "event_retention_days": policy.event_retention_days(),
            "middleware_installed": ours,
            "middleware_order_ok": expected == actual,
            "cache_backend": self._cache_backend(),
        }
        data.update(self._database_snapshot())
        return data

    @staticmethod
    def _cache_backend() -> str:
        try:
            return str(settings.CACHES["default"]["BACKEND"])
        except Exception:  # noqa: BLE001
            return "unknown"

    @staticmethod
    def _database_snapshot() -> dict:
        try:
            from django.utils import timezone

            from django_bouncer.models import BannedIP, SecurityEvent

            now = timezone.now()
            active = BannedIP.objects.filter(is_permanent=True).count() + (
                BannedIP.objects.filter(is_permanent=False, expires_at__gt=now).count()
            )
            recent = SecurityEvent.objects.filter(
                created_at__gte=now - timezone.timedelta(hours=24)
            ).count()
            return {"active_bans": active, "events_last_24h": recent}
        except Exception as exc:  # noqa: BLE001 - status must work without a database
            return {"database_error": str(exc)[:200]}

    # ── rendering ────────────────────────────────────────────────────────

    def _render(self, data: dict) -> None:
        write = self.stdout.write
        write(self.style.MIGRATE_HEADING(f"\ndjango-bouncer {data['version']}"))

        write(self.style.WARNING("\nModes"))
        write(f"  global                 {data['mode']}")
        for layer, layer_mode in data["layers"].items():
            marker = "" if layer_mode == data["mode"] else "   (override)"
            write(f"  {layer:<22} {layer_mode}{marker}")

        write(self.style.WARNING("\nBans"))
        write(f"  enforcement            {'on' if data['ban_enforcement'] else 'OFF'}")
        write(f"  automatic bans         {'on' if data['auto_ban'] else 'OFF'}")
        write(f"  active bans            {data.get('active_bans', '?')}")
        write(f"  events (24h)           {data.get('events_last_24h', '?')}")
        if "database_error" in data:
            write(self.style.ERROR(f"  database               {data['database_error']}"))

        write(self.style.WARNING("\nClient IP"))
        write(f"  trusted proxy count    {data['trusted_proxy_count']}")
        write(f"  shadow proxy count     {data['shadow_proxy_count']}")
        write(f"  trusted addresses      {', '.join(data['trusted_ips']) or '(none)'}")

        write(self.style.WARNING("\nStaff"))
        write(f"  bypass                 {'on' if data['staff_bypass'] else 'off'}")
        write(f"  trust window (days)    {data['staff_trust_days']}")

        write(self.style.WARNING("\nRate limits"))
        write(f"  multiplier             {data['rate_multiplier']}")
        write(f"  {'prefix':<28} {'per minute':>10} {'burst':>8}")
        for rule in data["rate_limit_rules"]:
            write(
                f"  {rule['prefix']:<28} {rule['limit_per_minute']:>10} "
                f"{rule['effective_burst']:>8}"
            )

        write(self.style.WARNING("\nPaths"))
        write(f"  exempt                 {', '.join(data['exempt_prefixes'])}")
        write(f"  api                    {', '.join(data['api_prefixes'])}")
        write(f"  login                  {', '.join(data['login_paths']) or '(none)'}")
        write(f"  honeypot field         {data['honeypot_field']}")

        write(self.style.WARNING("\nRuntime"))
        write(f"  cache backend          {data['cache_backend']}")
        order = "ok" if data["middleware_order_ok"] else "WRONG ORDER"
        write(f"  middleware ({len(data['middleware_installed'])})         {order}")
        for name in data["middleware_installed"]:
            write(f"    - {name.rsplit('.', 1)[-1]}")
        write("")
