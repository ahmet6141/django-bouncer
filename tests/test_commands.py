"""The operator commands: recovery, diagnosis, retention and introspection."""
from __future__ import annotations

import json
from io import StringIO

import pytest
from django.core.cache import cache
from django.core.management import call_command
from django.utils import timezone

from django_bouncer.middleware._helpers import is_staff_trusted_ip
from django_bouncer.models import BannedIP, SecurityEvent

BANNED = "203.0.113.44"
OTHER = "198.51.100.5"

pytestmark = pytest.mark.django_db


def run(command, *args, **options):
    out = StringIO()
    call_command(command, *args, stdout=out, stderr=StringIO(), **options)
    return out.getvalue()


class TestUnban:
    def test_unban_clears_the_row_and_the_cache(self):
        BannedIP.add_ban(BANNED, reason="manual", permanent=True)
        assert BannedIP.is_banned(BANNED)

        output = run("bouncer_unban", BANNED)

        assert "unbanned" in output
        assert not BannedIP.objects.filter(ip=BANNED).exists()
        assert cache.get(BannedIP.cache_key(BANNED)) is None

    def test_trust_marks_the_address(self):
        BannedIP.add_ban(BANNED, reason="manual", hours=1)
        run("bouncer_unban", BANNED, "--trust", "--days", "30")
        assert is_staff_trusted_ip(BANNED)

    def test_trust_only_keeps_the_ban(self):
        BannedIP.add_ban(BANNED, reason="manual", hours=1)
        run("bouncer_unban", BANNED, "--trust-only")
        assert BannedIP.objects.filter(ip=BANNED).exists()
        assert is_staff_trusted_ip(BANNED)

    def test_missing_row_still_clears_the_cache(self):
        cache.set(BannedIP.cache_key(OTHER), "p", timeout=600)
        run("bouncer_unban", OTHER)
        assert cache.get(BannedIP.cache_key(OTHER)) is None

    def test_list_does_not_delete_anything(self):
        BannedIP.add_ban(BANNED, reason="manual", permanent=True)
        output = run("bouncer_unban", "--list")
        assert BANNED in output
        assert BannedIP.objects.filter(ip=BANNED).exists()

    def test_all_requires_confirmation_unless_suppressed(self):
        BannedIP.add_ban(BANNED, reason="manual", permanent=True)
        run("bouncer_unban", "--all", "--no-input")
        assert not BannedIP.objects.exists()

    def test_no_address_is_an_error(self):
        from django.core.management.base import CommandError

        with pytest.raises(CommandError):
            run("bouncer_unban")


class TestPrune:
    def _event(self, days_old):
        event = SecurityEvent.objects.create(
            ip=OTHER, reason=SecurityEvent.REASON_RATE_LIMIT, path="/x/"
        )
        SecurityEvent.objects.filter(pk=event.pk).update(
            created_at=timezone.now() - timezone.timedelta(days=days_old)
        )
        return event

    def test_old_events_are_deleted_and_recent_ones_kept(self):
        self._event(days_old=200)
        self._event(days_old=1)
        run("bouncer_prune", "--days", "90")
        assert SecurityEvent.objects.count() == 1

    def test_dry_run_changes_nothing(self):
        self._event(days_old=200)
        output = run("bouncer_prune", "--days", "90", "--dry-run")
        assert "would be deleted" in output
        assert SecurityEvent.objects.count() == 1

    def test_expired_bans_are_removed_but_active_ones_stay(self):
        BannedIP.objects.create(
            ip=BANNED,
            reason="old",
            expires_at=timezone.now() - timezone.timedelta(days=5),
        )
        BannedIP.add_ban(OTHER, reason="live", hours=6)
        run("bouncer_prune")
        assert not BannedIP.objects.filter(ip=BANNED).exists()
        assert BannedIP.objects.filter(ip=OTHER).exists()

    def test_permanent_bans_are_never_pruned(self):
        BannedIP.add_ban(BANNED, reason="manual", permanent=True)
        run("bouncer_prune", "--days", "1")
        assert BannedIP.objects.filter(ip=BANNED).exists()

    def test_retention_zero_disables_event_pruning(self, settings):
        settings.BOUNCER_EVENT_RETENTION_DAYS = 0
        self._event(days_old=500)
        output = run("bouncer_prune")
        assert "disabled" in output
        assert SecurityEvent.objects.count() == 1


class TestReport:
    def test_summary_lists_reasons_and_bans(self):
        SecurityEvent.objects.create(
            ip=OTHER, reason=SecurityEvent.REASON_WAF_SQLI, path="/x/", blocked=True
        )
        BannedIP.add_ban(BANNED, reason="manual", permanent=True)
        output = run("bouncer_report", "--hours", "24")
        assert "waf_sqli" in output
        assert BANNED in output

    def test_single_address_timeline(self):
        SecurityEvent.objects.create(
            ip=OTHER,
            reason=SecurityEvent.REASON_HONEYPOT_URL,
            path="/wp-login.php",
            payload_snippet="/wp-login.php",
            blocked=True,
        )
        output = run("bouncer_report", "--ip", OTHER)
        assert "/wp-login.php" in output
        assert "honeypot_url" in output


class TestStatus:
    def test_human_output_shows_the_effective_configuration(self):
        output = run("bouncer_status")
        assert "django-bouncer" in output
        assert "enforce" in output
        assert "middleware" in output

    def test_json_output_is_machine_readable(self, settings):
        settings.BOUNCER_LAYER_MODES = {"waf": "observe"}
        data = json.loads(run("bouncer_status", "--json"))
        assert data["mode"] == "enforce"
        assert data["layers"]["waf"] == "observe"
        assert data["middleware_order_ok"] is True
        assert data["active_bans"] == 0
