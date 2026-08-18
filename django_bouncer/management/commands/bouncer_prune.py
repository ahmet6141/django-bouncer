"""bouncer_prune — keep the audit tables bounded.

Every layer writes to ``SecurityEvent``. On a site that attracts scanners that
is thousands of rows a day, and an unbounded audit table eventually costs more
than it is worth. Run this from cron:

    python manage.py bouncer_prune                 # BOUNCER_EVENT_RETENTION_DAYS (90)
    python manage.py bouncer_prune --days 30
    python manage.py bouncer_prune --dry-run
    python manage.py bouncer_prune --keep-bans     # events only

Expired ban rows are deleted too, one day after expiry, so a recent ban is
still visible in ``bouncer_report`` while stale ones do not accumulate.
Permanent bans and active bans are never touched.

Deletion runs in batches so a long backlog cannot hold one long transaction
open against a production database.
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from django_bouncer import policy
from django_bouncer.models import BannedIP, SecurityEvent

BATCH_SIZE = 5000
EXPIRED_BAN_GRACE_DAYS = 1


class Command(BaseCommand):
    help = "Delete old security events and expired ban rows."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--days",
            type=int,
            default=None,
            help="Event retention in days (default BOUNCER_EVENT_RETENTION_DAYS).",
        )
        parser.add_argument(
            "--dry-run", action="store_true", help="Count what would be deleted."
        )
        parser.add_argument(
            "--keep-bans", action="store_true", help="Do not delete expired ban rows."
        )

    def handle(self, *args, **options) -> None:
        days = options["days"] if options["days"] is not None else policy.event_retention_days()
        if days < 0:
            raise CommandError("--days cannot be negative.")
        write = self.stdout.write
        now = timezone.now()

        if days == 0:
            write(
                self.style.WARNING(
                    "Retention is 0 — event pruning is disabled "
                    "(set --days or BOUNCER_EVENT_RETENTION_DAYS)."
                )
            )
            events_deleted = 0
        else:
            cutoff = now - timezone.timedelta(days=days)
            stale = SecurityEvent.objects.filter(created_at__lt=cutoff)
            if options["dry_run"]:
                events_deleted = stale.count()
            else:
                events_deleted = self._delete_in_batches(stale)
            write(
                f"Events older than {days} day(s): "
                f"{events_deleted} {'would be deleted' if options['dry_run'] else 'deleted'}."
            )

        bans_deleted = 0
        if not options["keep_bans"]:
            ban_cutoff = now - timezone.timedelta(days=EXPIRED_BAN_GRACE_DAYS)
            expired = BannedIP.objects.filter(
                is_permanent=False, expires_at__lt=ban_cutoff
            )
            if options["dry_run"]:
                bans_deleted = expired.count()
            else:
                # Drop the cache entries first: a row deleted underneath a live
                # cache entry would otherwise keep blocking until the TTL ends.
                from django.core.cache import cache

                for ip in expired.values_list("ip", flat=True).iterator():
                    cache.delete(BannedIP.cache_key(ip))
                bans_deleted = self._delete_in_batches(expired)
            write(
                f"Ban rows expired more than {EXPIRED_BAN_GRACE_DAYS} day(s) ago: "
                f"{bans_deleted} {'would be deleted' if options['dry_run'] else 'deleted'}."
            )

        if not options["dry_run"]:
            write(self.style.SUCCESS(f"Pruned {events_deleted + bans_deleted} row(s)."))

    @staticmethod
    def _delete_in_batches(queryset) -> int:
        total = 0
        while True:
            pks = list(queryset.values_list("pk", flat=True)[:BATCH_SIZE])
            if not pks:
                return total
            deleted, _details = queryset.model.objects.filter(pk__in=pks).delete()
            total += deleted
            if len(pks) < BATCH_SIZE:
                return total
