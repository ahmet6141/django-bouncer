"""bouncer_unban — remove one or more addresses from the ban list.

Deletes the ``BannedIP`` row and clears the cache entry. This is the shell-side
recovery path for the case where you cannot reach the admin because your own
address is banned.

    python manage.py bouncer_unban 203.0.113.7
    python manage.py bouncer_unban 203.0.113.7 198.51.100.4
    python manage.py bouncer_unban --list                    # show current bans
    python manage.py bouncer_unban --all                     # clear every active ban
    python manage.py bouncer_unban 203.0.113.7 --trust       # + trust it for N days
    python manage.py bouncer_unban 203.0.113.7 --trust --days 30
    python manage.py bouncer_unban --trust-only 203.0.113.7  # trust without unbanning

A staff sign-in already lifts the ban on that address and marks it trusted
(see ``django_bouncer.signals``); this command exists for when signing in is
not an option.
"""
from __future__ import annotations

from django.core.cache import cache
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q
from django.utils import timezone

from django_bouncer.models import BannedIP


class Command(BaseCommand):
    help = "Remove addresses from the ban list (database and cache)."

    def add_arguments(self, parser) -> None:
        parser.add_argument("ips", nargs="*", help="Addresses to unban.")
        parser.add_argument(
            "--all", action="store_true", help="Lift every active (unexpired) ban."
        )
        parser.add_argument(
            "--list", action="store_true", help="List bans and change nothing."
        )
        parser.add_argument(
            "--trust",
            action="store_true",
            help="Also mark the address staff-trusted for --days days.",
        )
        parser.add_argument(
            "--trust-only",
            action="store_true",
            help="Do not unban; only mark the address trusted.",
        )
        parser.add_argument(
            "--days",
            type=int,
            default=None,
            help="Trust window for --trust (default BOUNCER_STAFF_TRUST_DAYS).",
        )
        parser.add_argument(
            "--no-input",
            action="store_true",
            help="Do not prompt for confirmation with --all.",
        )

    def handle(self, *args, **options) -> None:
        if options["list"]:
            self._list()
            return
        if options["all"]:
            self._unban_all(no_input=options["no_input"])
            return

        addresses = [ip.strip() for ip in options["ips"] if ip.strip()]
        if not addresses:
            raise CommandError(
                "At least one address is required, for example:\n"
                "  python manage.py bouncer_unban 203.0.113.7\n"
                "Or use --list / --all."
            )

        unbanned, missing = [], []
        if not options["trust_only"]:
            for ip in addresses:
                if BannedIP.remove_ban(ip):
                    unbanned.append(ip)
                else:
                    missing.append(ip)
                    cache.delete(BannedIP.cache_key(ip))  # clear the cache regardless

        for ip in unbanned:
            self.stdout.write(self.style.SUCCESS(f"OK  {ip} unbanned (database + cache)."))
        for ip in missing:
            self.stdout.write(
                self.style.WARNING(f"--  {ip} had no ban row; cache cleared anyway.")
            )

        if options["trust"] or options["trust_only"]:
            from django_bouncer import policy
            from django_bouncer.middleware._helpers import mark_staff_trusted_ip

            days = options["days"] or policy.staff_trust_days() or 7
            for ip in addresses:
                mark_staff_trusted_ip(ip, days=days)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"OK  {ip} trusted for {days} days (bypasses every layer)."
                    )
                )

    # ── helpers ──────────────────────────────────────────────────────────

    def _list(self) -> None:
        bans = BannedIP.objects.all().order_by("-created_at")
        active, expired = [], []
        for ban in bans:
            (active if ban.is_active else expired).append(ban)
        self.stdout.write(
            self.style.SUCCESS(
                f"\n{len(active)} active ban(s), {len(expired)} expired row(s).\n"
            )
        )
        if active:
            self.stdout.write("ACTIVE BANS:")
            self.stdout.write(f"  {'address':<40}  {'reason':<20}  expires")
            for ban in active:
                expires = (
                    "permanent"
                    if ban.is_permanent
                    else (ban.expires_at.strftime("%Y-%m-%d %H:%M") if ban.expires_at else "—")
                )
                self.stdout.write(f"  {ban.ip:<40}  {ban.reason[:20]:<20}  {expires}")
        if expired:
            self.stdout.write(
                f"\n{len(expired)} expired row(s) — clear them with "
                "`manage.py bouncer_prune`."
            )

    def _unban_all(self, *, no_input: bool) -> None:
        active = BannedIP.objects.filter(
            Q(is_permanent=True) | Q(expires_at__gt=timezone.now())
        )
        addresses = list(active.values_list("ip", flat=True))
        if not addresses:
            self.stdout.write(self.style.WARNING("No active bans."))
            return
        self.stdout.write(
            self.style.WARNING(f"\n{len(addresses)} active ban(s) will be deleted:")
        )
        for ip in addresses[:20]:
            self.stdout.write(f"  - {ip}")
        if len(addresses) > 20:
            self.stdout.write(f"  - ... and {len(addresses) - 20} more")
        if not no_input:
            if input("\nContinue? (yes/no): ").strip().lower() != "yes":
                self.stdout.write("Cancelled.")
                return
        active.delete()
        for ip in addresses:
            cache.delete(BannedIP.cache_key(ip))
        self.stdout.write(self.style.SUCCESS(f"{len(addresses)} address(es) unbanned."))
