"""Admin screens for the audit log and the ban list."""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from .models import BannedIP, SecurityEvent

_SEVERITY_COLORS = {
    SecurityEvent.SEVERITY_LOW: "#64748b",
    SecurityEvent.SEVERITY_MEDIUM: "#f59e0b",
    SecurityEvent.SEVERITY_HIGH: "#ef4444",
    SecurityEvent.SEVERITY_CRITICAL: "#7c3aed",
}
_BADGE = (
    '<span style="background:{};color:#fff;padding:2px 8px;border-radius:4px;'
    'font-size:11px;font-weight:600">{}</span>'
)


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        "created_at", "severity_badge", "reason", "ip", "method", "path_short", "blocked",
    )
    list_filter = ("severity", "reason", "blocked", "method")
    search_fields = ("ip", "user_agent", "path", "payload_snippet")
    list_select_related = ("user",)
    readonly_fields = (
        "created_at", "ip", "user_agent", "method", "path", "referer",
        "reason", "severity", "payload_snippet", "blocked", "user",
    )
    date_hierarchy = "created_at"
    list_per_page = 50

    @admin.display(description=_("severity"), ordering="severity")
    def severity_badge(self, obj):
        return format_html(
            _BADGE,
            _SEVERITY_COLORS.get(obj.severity, "#64748b"),
            str(obj.get_severity_display()).upper(),
        )

    @admin.display(description=_("path"))
    def path_short(self, obj):
        return obj.path[:70] + ("…" if len(obj.path) > 70 else "")

    def has_add_permission(self, request):
        # Rows are written by the middleware; a hand-made one would corrupt the
        # counts the ban policy reads.
        return False


@admin.register(BannedIP)
class BannedIPAdmin(admin.ModelAdmin):
    list_display = (
        "ip", "is_permanent", "expires_at", "reason", "hit_count", "active_badge",
        "created_at",
    )
    list_filter = ("is_permanent", "reason")
    search_fields = ("ip", "reason", "note")
    readonly_fields = ("hit_count", "created_at", "updated_at")
    actions = ["unban_selected", "unban_and_trust_selected", "make_permanent"]

    @admin.display(description=_("active"))
    def active_badge(self, obj):
        if obj.is_active:
            return format_html(_BADGE, "#ef4444", "ACTIVE")
        return format_html(_BADGE, "#64748b", "expired")

    @admin.action(description=_("Lift the ban on the selected addresses"))
    def unban_selected(self, request, queryset):
        addresses = list(queryset.values_list("ip", flat=True))
        for ip in addresses:
            BannedIP.remove_ban(ip)
        self.message_user(
            request,
            ngettext(
                "%(count)d ban lifted.", "%(count)d bans lifted.", len(addresses)
            )
            % {"count": len(addresses)},
        )

    @admin.action(
        description=_("Lift the ban and trust the address for 30 days (bypasses every layer)")
    )
    def unban_and_trust_selected(self, request, queryset):
        from django_bouncer.middleware._helpers import mark_staff_trusted_ip

        addresses = list(queryset.values_list("ip", flat=True))
        for ip in addresses:
            BannedIP.remove_ban(ip)
            mark_staff_trusted_ip(ip, days=30)
        self.message_user(
            request,
            _("%(count)d address(es): ban lifted, trusted for 30 days.")
            % {"count": len(addresses)},
        )

    @admin.action(description=_("Make the ban permanent"))
    def make_permanent(self, request, queryset):
        from django.core.cache import cache

        addresses = list(queryset.values_list("ip", flat=True))
        updated = queryset.update(is_permanent=True, expires_at=None)
        for ip in addresses:
            cache.set(BannedIP.cache_key(ip), "p", timeout=600)
        self.message_user(
            request,
            _("%(count)d address(es) banned permanently.") % {"count": updated},
        )
