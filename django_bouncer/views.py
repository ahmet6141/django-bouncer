"""Small, bounded endpoints owned by the security application."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from urllib.parse import urlsplit, urlunsplit

from django.core.cache import cache
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from django_bouncer import policy
from django_bouncer.client_ip import get_client_ip
from django_bouncer.models import SecurityEvent

logger = logging.getLogger("django_bouncer.csp")

MAX_CSP_REPORT_BYTES = 32 * 1024
ALLOWED_CSP_REPORT_CONTENT_TYPES = {
    "application/csp-report",
    "application/json",
}


def _error(code: str, status: int) -> JsonResponse:
    response = JsonResponse({"success": False, "error": code}, status=status)
    response["Cache-Control"] = "no-store"
    return response


def _clean_report_value(value: object, *, max_length: int = 300) -> str:
    cleaned = "".join(
        character
        for character in str(value or "")
        if character.isprintable() and character not in "\r\n"
    ).strip()
    if cleaned.startswith(("http://", "https://")):
        parsed = urlsplit(cleaned)
        cleaned = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return cleaned[:max_length]


def _normalized_report(payload: object):
    if not isinstance(payload, dict):
        return None
    report = payload.get("csp-report", payload)
    if not isinstance(report, dict):
        return None
    normalized = {
        "document_uri": _clean_report_value(report.get("document-uri")),
        "violated_directive": _clean_report_value(
            report.get("effective-directive") or report.get("violated-directive"),
            max_length=100,
        ),
        "blocked_uri": _clean_report_value(report.get("blocked-uri")),
        "source_file": _clean_report_value(report.get("source-file")),
        "line_number": _clean_report_value(report.get("line-number"), max_length=20),
        "disposition": _clean_report_value(report.get("disposition"), max_length=20),
    }
    if not normalized["violated_directive"]:
        return None
    return normalized


def _empty_response() -> HttpResponse:
    response = HttpResponse(status=204)
    response["Cache-Control"] = "no-store"
    return response


@csrf_exempt
@require_POST
def csp_violation_report(request):
    """Collect sampled browser CSP reports without opening a log-flood vector.

    A report is attacker-controllable and browsers send them in volume, so the
    endpoint is bounded three ways: a hard body limit, one row per identical
    report per hour, and a per-address hourly cap. Anything over the cap is
    accepted with 204 and dropped — a rejected report would only teach a
    flooder to vary the payload.
    """
    content_type = (request.content_type or "").partition(";")[0].lower()
    if content_type not in ALLOWED_CSP_REPORT_CONTENT_TYPES:
        return _error("unsupported_media_type", 415)

    try:
        declared_length = int(request.META.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        declared_length = 0
    if declared_length > MAX_CSP_REPORT_BYTES:
        return _error("payload_too_large", 413)

    raw_body = request.body
    if not raw_body or len(raw_body) > MAX_CSP_REPORT_BYTES:
        return _error(
            "payload_too_large" if raw_body else "invalid_report",
            413 if raw_body else 400,
        )
    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return _error("invalid_report", 400)
    report = _normalized_report(payload)
    if report is None:
        return _error("invalid_report", 400)

    ip = get_client_ip(request)
    fingerprint_source = json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    fingerprint = hashlib.sha256(
        fingerprint_source.encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    hour_bucket = int(time.time()) // 3600
    dedupe_key = f"bnc:csp:dedupe:{ip}:{fingerprint}"
    count_key = f"bnc:csp:count:{ip}:{hour_bucket}"
    limit = policy.csp_reports_per_ip_per_hour()
    try:
        cache.add(count_key, 0, timeout=3700)
        report_count = cache.incr(count_key)
        if report_count > limit:
            return _empty_response()
        if not cache.add(dedupe_key, 1, timeout=3600):
            return _empty_response()
    except Exception:  # noqa: BLE001 - reports must fail closed without user impact
        logger.exception("CSP report cache unavailable ip=%s", ip)
        return _empty_response()

    try:
        SecurityEvent.objects.create(
            ip=ip,
            user_agent=_clean_report_value(
                request.headers.get("User-Agent", ""), max_length=512
            ),
            method="POST",
            path=(urlsplit(report["document_uri"]).path or "/")[:512],
            referer="",
            reason=SecurityEvent.REASON_CSP_VIOLATION,
            severity=SecurityEvent.SEVERITY_LOW,
            payload_snippet=json.dumps(report, ensure_ascii=False, separators=(",", ":"))[
                :500
            ],
            blocked=False,
            user=(
                request.user
                if getattr(getattr(request, "user", None), "is_authenticated", False)
                else None
            ),
        )
    except Exception:  # noqa: BLE001 - telemetry must never affect visitors
        logger.exception("CSP report persistence failed ip=%s", ip)
    return _empty_response()
