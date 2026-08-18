"""URL and form honeypots with a low false-positive budget.

* A request for a known scanner path (``/wp-login.php``, ``/.env``,
  ``/phpmyadmin/`` …) gets a 404. A global ban needs the ``honeypot_url``
  policy: three *distinct* such paths within ten minutes, because one probe
  from a shared address is not evidence about everyone behind it.
  Matching is anchored at the root — exact match, or the entry plus ``/``.
  There is deliberately no ``endswith`` test, so a legitimate slug such as
  ``/products/console`` cannot be mistaken for ``/console``. Language prefixes
  (``/en/wp-login.php``) are stripped first.

* A hidden form field filled in means a bot submitted the form → 403, and
  never a ban: browser autofill and shared addresses make this an unsafe
  site-wide signal. Add the field to your templates with::

      {% include "django_bouncer/honeypot_field.html" %}

Privileged requests are untouched and exempt paths are skipped.
"""
from __future__ import annotations

from django_bouncer import policy

from ._helpers import (
    block_response,
    get_client_ip,
    is_exempt_path,
    is_privileged,
    is_static_path,
    log_event,
)

# None of these is a valid route in a Django project. A hit is blocked at once;
# a ban still requires several independent scanner paths (see ban_policy).
# /.well-known/security.txt is intentionally absent: it is a standard endpoint,
# not an attack signal.
DEFAULT_HONEYPOT_PATHS = (
    "/wp-login.php", "/wp-admin", "/wp-content", "/wp-includes", "/wp-json",
    "/xmlrpc.php", "/.env", "/.git", "/.aws/credentials", "/.ssh/id_rsa",
    "/.htaccess", "/.htpasswd", "/web.config",
    "/phpmyadmin", "/phpMyAdmin", "/pma", "/adminer.php", "/mysql",
    "/server-status", "/server-info",
    "/cgi-bin", "/console", "/jenkins", "/manager/html",
    "/owa", "/exchange", "/ecp", "/autodiscover",
    "/api/v1/auth/login.php", "/login.aspx", "/login.cfm",
    "/_profiler", "/debug/default/view", "/telescope", "/_ignition",
    "/actuator", "/admin.php", "/admin/login.php", "/administrator",
    "/backup.zip", "/backup.tar.gz", "/site.tar.gz", "/database.sql",
    "/.DS_Store", "/Thumbs.db", "/vendor/phpunit", "/solr", "/struts",
)


def honeypot_paths() -> tuple:
    """Built-in paths plus anything in ``BOUNCER_HONEYPOT_PATHS``."""
    from django_bouncer.policy import _list  # value-keyed, cheap

    return DEFAULT_HONEYPOT_PATHS + tuple(_list("BOUNCER_HONEYPOT_PATHS"))


def match_honeypot_path(path: str):
    """Return the matching honeypot entry, or None. Anchored at the root."""
    if not path:
        return None
    candidate = policy.strip_lang_prefix(path).rstrip("/") or "/"
    for entry in honeypot_paths():
        normalized = entry.rstrip("/")
        if candidate == normalized or candidate.startswith(normalized + "/"):
            return entry
    return None


class HoneypotMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if is_static_path(path) or is_exempt_path(path):
            return self.get_response(request)

        layer_mode = policy.layer_mode(policy.LAYER_HONEYPOT)
        if layer_mode == policy.MODE_OFF:
            return self.get_response(request)
        enforcing = layer_mode == policy.MODE_ENFORCE

        from django_bouncer.models import SecurityEvent

        # 1) Honeypot URL
        entry = match_honeypot_path(path)
        if entry:
            ip = get_client_ip(request)
            if is_privileged(request, ip):
                return self.get_response(request)
            # One row per path per ten seconds; distinct paths stay distinct,
            # because the ban policy requires three different ones.
            log_event(
                request,
                reason=SecurityEvent.REASON_HONEYPOT_URL,
                severity=SecurityEvent.SEVERITY_HIGH,
                payload=entry,
                blocked=enforcing,
                throttle_seconds=10,
                throttle_key=path[:200],
            )
            if not enforcing:
                return self.get_response(request)
            from django_bouncer.ban_policy import evaluate_auto_ban

            evaluate_auto_ban(
                ip, "honeypot_url", reason=f"honeypot:{entry[:48]}", request=request
            )
            return block_response(request, reason="honeypot", status=404, ip=ip)

        # 2) Honeypot form field
        if request.method == "POST":
            field = policy.honeypot_field_name()
            try:
                value = (request.POST.get(field) or "").strip()
            except Exception:  # noqa: BLE001
                # A body parsing error must not break the real request.
                value = ""
            if value:
                ip = get_client_ip(request)
                if is_privileged(request, ip):
                    return self.get_response(request)
                # Block the submission, never ban the address for it.
                log_event(
                    request,
                    reason=SecurityEvent.REASON_HONEYPOT_FORM,
                    severity=SecurityEvent.SEVERITY_HIGH,
                    payload=f"{field}={value[:60]}",
                    blocked=enforcing,
                )
                if enforcing:
                    return block_response(request, reason="honeypot_form", ip=ip)

        return self.get_response(request)
