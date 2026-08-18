"""Bound and parse JSON request bodies before application views run."""

from __future__ import annotations

import json
from collections.abc import Callable

from django.core.exceptions import RequestDataTooBig
from django.http import HttpRequest, HttpResponse, JsonResponse

from django_bouncer import policy

DEFAULT_JSON_REQUEST_MAX_BYTES = 256 * 1024


def _is_json_content_type(content_type: str) -> bool:
    """Whether a media type represents JSON, including ``+json`` suffixes."""
    media_type = (content_type or "").partition(";")[0].strip().lower()
    return media_type == "application/json" or media_type.endswith("+json")


def _error_response(*, code: str, message: str, status: int) -> JsonResponse:
    response = JsonResponse(
        {"success": False, "error": code, "message": message},
        status=status,
    )
    response["Cache-Control"] = "no-store"
    return response


class JSONRequestValidationMiddleware:
    """Reject oversized or structurally invalid JSON with stable API errors.

    Only explicitly declared JSON media types are inspected; form and multipart
    requests — file uploads, payment callbacks — pass through untouched. A
    parsed object is cached on ``request.json_body`` so views can stop
    re-parsing without a flag-day rewrite.

    In ``observe`` mode the body is still parsed and attached, but nothing is
    rejected, which is how you find out whether any real client sends
    non-object or oversized JSON before enforcing.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        layer_mode = policy.layer_mode(policy.LAYER_JSON)
        if layer_mode == policy.MODE_OFF:
            return self.get_response(request)
        if not _is_json_content_type(request.META.get("CONTENT_TYPE", "")):
            return self.get_response(request)

        enforcing = layer_mode == policy.MODE_ENFORCE
        max_bytes = policy.json_max_bytes()
        try:
            declared_size = int(request.META.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            declared_size = 0

        too_large = _error_response(
            code="payload_too_large",
            message="JSON request body exceeds the permitted size.",
            status=413,
        )
        if declared_size > max_bytes:
            return too_large if enforcing else self.get_response(request)

        try:
            raw_body = request.body
        except RequestDataTooBig:
            return too_large if enforcing else self.get_response(request)

        if len(raw_body) > max_bytes:
            return too_large if enforcing else self.get_response(request)

        if not raw_body.strip():
            if not enforcing:
                return self.get_response(request)
            return _error_response(
                code="invalid_json",
                message="A non-empty JSON request body is required.",
                status=400,
            )

        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            if not enforcing:
                return self.get_response(request)
            return _error_response(
                code="invalid_json",
                message="The request body is not valid JSON.",
                status=400,
            )

        if not isinstance(payload, dict):
            if not enforcing:
                return self.get_response(request)
            return _error_response(
                code="json_object_required",
                message="The top-level JSON value must be an object.",
                status=400,
            )

        request.json_body = payload
        return self.get_response(request)
