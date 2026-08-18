"""bouncer_report — the "why was this blocked?" diagnostic.

    python manage.py bouncer_report                    # last 24 hours
    python manage.py bouncer_report --hours 72
    python manage.py bouncer_report --ip 203.0.113.7   # one address, in order
    python manage.py bouncer_report --ip 203.0.113.7 --limit 200
    python manage.py bouncer_report --bans             # active bans only

The output shows event counts per reason, the addresses producing the most
events, the active bans with their reason and remaining time, and — with
``--ip`` — that address's timeline including the matched fragment, so you can
see exactly which rule fired instead of guessing.
"""
from __future__ import annotations

from collections import Counter

from django.core.management.base import BaseCommand
from django.db.models import Count
from django.utils import timezone

from django_bouncer import policy
from django_bouncer.models import BannedIP, SecurityEvent


class Command(BaseCommand):
    help = "Summarise security events and bans (diagnostics)."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--hours", type=int, default=24)
        parser.add_argument("--ip", default="")
        parser.add_argument("--limit", type=int, default=60)
        parser.add_argument(
            "--bans", action="store_true", help="Show active bans only."
        )

    def handle(self, *args, **options) -> None:
        now = timezone.now()
        since = now - timezone.timedelta(hours=options["hours"])
        write = self.stdout.write

        write(
            self.style.MIGRATE_HEADING(
                f"\n=== bouncer_report — last {options['hours']}h "
                f"(mode={policy.mode()}, "
                f"ban_enforcement={'on' if policy.ban_enforcement_enabled() else 'OFF'}, "
                f"auto_ban={'on' if policy.auto_ban_enabled() else 'OFF'}, "
                f"staff_bypass={'on' if policy.staff_bypass_enabled() else 'off'}) ==="
            )
        )

        active = [
            ban for ban in BannedIP.objects.order_by("-updated_at")[:500] if ban.is_active
        ]
        write(self.style.WARNING(f"\nActive bans: {len(active)}"))
        for ban in active[: options["limit"]]:
            if ban.is_permanent:
                left = "PERMANENT"
            else:
                seconds = int((ban.expires_at - now).total_seconds()) if ban.expires_at else 0
                left = f"{seconds // 3600}h {seconds % 3600 // 60}m left"
            write(
                f"  {ban.ip:<40} {ban.reason[:28]:<28} hits={ban.hit_count:<4} "
                f"{left:<16} {ban.note[:70]}"
            )
        if options["bans"]:
            return

        if options["ip"]:
            self._timeline(options["ip"], since, options["limit"])
            return

        events = SecurityEvent.objects.filter(created_at__gte=since)
        write(self.style.WARNING(f"\nEvents: {events.count()}"))
        for row in events.values("reason", "blocked").annotate(n=Count("id")).order_by("-n"):
            flag = "BLOCK" if row["blocked"] else "log  "
            write(f"  {row['reason']:<18} {flag}  {row['n']}")

        write(self.style.WARNING("\nBusiest addresses:"))
        for row in events.values("ip").annotate(n=Count("id")).order_by("-n")[:15]:
            reasons = Counter(
                events.filter(ip=row["ip"]).values_list("reason", flat=True)[:500]
            )
            top = ", ".join(f"{name}={count}" for name, count in reasons.most_common(4))
            banned = "BANNED" if BannedIP.is_banned(row["ip"]) else ""
            write(f"  {row['ip']:<40} {row['n']:<6} {banned:<7} {top}")

        write(
            "\nNext: one address   python manage.py bouncer_report --ip <IP>\n"
            "      lift a ban    python manage.py bouncer_unban <IP> --trust\n"
        )

    def _timeline(self, ip: str, since, limit: int) -> None:
        write = self.stdout.write
        write(self.style.MIGRATE_HEADING(f"\n--- {ip} ---"))
        ban = BannedIP.objects.filter(ip=ip).first()
        if ban:
            write(
                f"BannedIP: active={ban.is_active} reason={ban.reason} "
                f"hits={ban.hit_count} expires={ban.expires_at} note={ban.note[:120]}"
            )
        else:
            write("BannedIP: no row")
        try:
            from django.core.cache import cache

            write(
                f"cache ban={cache.get(BannedIP.cache_key(ip))!r} "
                f"staff_trust={bool(cache.get(f'bnc:stafftrust:{ip}'))} "
                f"login_lock={cache.get(f'bnc:loginlock:{ip}')!r}"
            )
        except Exception:  # noqa: BLE001
            pass

        events = SecurityEvent.objects.filter(ip=ip, created_at__gte=since).order_by(
            "-created_at"
        )[:limit]
        write(f"\nLast {len(events)} event(s):")
        for event in events:
            flag = "BLOCK" if event.blocked else "log  "
            write(
                f"  {event.created_at:%m-%d %H:%M:%S} {flag} {event.reason:<16} "
                f"{event.method:<5} {event.path[:48]:<48} {event.payload_snippet[:60]}"
            )
        reasons = Counter(event.reason for event in events)
        if reasons:
            write(
                "\nReasons: "
                + ", ".join(f"{name}={count}" for name, count in reasons.most_common())
            )
        agents = Counter(event.user_agent[:80] for event in events)
        if agents:
            write("User agents:")
            for agent, count in agents.most_common(5):
                write(f"  {count:<4} {agent}")
