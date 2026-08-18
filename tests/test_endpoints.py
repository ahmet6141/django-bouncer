"""JSON request validation and the CSP report collector."""
from __future__ import annotations

import json

import pytest
from django.http import HttpResponse
from django.test import Client, RequestFactory, override_settings

from django_bouncer.middleware import JSONRequestValidationMiddleware
from django_bouncer.models import SecurityEvent

rf = RequestFactory()
CSP_URL = "/bouncer/csp-report/"


def _ok(request):
    return HttpResponse("OK")


class TestJSONValidation:
    def test_non_json_passes_untouched(self):
        request = rf.post("/upload/", data={"a": "b"})  # multipart
        assert JSONRequestValidationMiddleware(_ok)(request).status_code == 200

    def test_valid_object_is_attached_to_the_request(self):
        seen = {}

        def view(request):
            seen["body"] = request.json_body
            return HttpResponse("OK")

        request = rf.post("/api/x/", data='{"a": 1}', content_type="application/json")
        assert JSONRequestValidationMiddleware(view)(request).status_code == 200
        assert seen["body"] == {"a": 1}

    def test_suffix_media_type_is_inspected(self):
        request = rf.post(
            "/api/x/", data="not json", content_type="application/merge-patch+json"
        )
        assert JSONRequestValidationMiddleware(_ok)(request).status_code == 400

    @pytest.mark.parametrize(
        "body,code",
        [
            (" ", "invalid_json"),
            ("{", "invalid_json"),
            ("[1, 2]", "json_object_required"),
            ('"a string"', "json_object_required"),
        ],
    )
    def test_invalid_bodies_get_stable_error_codes(self, body, code):
        request = rf.post("/api/x/", data=body, content_type="application/json")
        response = JSONRequestValidationMiddleware(_ok)(request)
        assert response.status_code in (400, 413)
        assert json.loads(response.content)["error"] == code

    @override_settings(BOUNCER_JSON_MAX_BYTES=2048)
    def test_oversized_body_is_413(self):
        payload = json.dumps({"a": "x" * 4096})
        request = rf.post("/api/x/", data=payload, content_type="application/json")
        response = JSONRequestValidationMiddleware(_ok)(request)
        assert response.status_code == 413
        assert json.loads(response.content)["error"] == "payload_too_large"

    @override_settings(BOUNCER_LAYER_MODES={"json": "observe"})
    def test_observe_mode_parses_without_rejecting(self):
        request = rf.post("/api/x/", data="[1,2]", content_type="application/json")
        assert JSONRequestValidationMiddleware(_ok)(request).status_code == 200


@pytest.mark.django_db
class TestCSPReport:
    def _post(self, payload, content_type="application/csp-report"):
        return Client().post(
            CSP_URL, data=json.dumps(payload), content_type=content_type
        )

    def test_valid_report_is_recorded_once(self):
        payload = {
            "csp-report": {
                "document-uri": "https://example.com/page/?token=secret",
                "violated-directive": "script-src",
                "blocked-uri": "https://cdn.example/x.js",
            }
        }
        assert self._post(payload).status_code == 204
        event = SecurityEvent.objects.get(reason=SecurityEvent.REASON_CSP_VIOLATION)
        assert event.path == "/page/"
        assert "secret" not in event.payload_snippet  # the query string is stripped

        # An identical report inside the hour is deduplicated.
        assert self._post(payload).status_code == 204
        assert SecurityEvent.objects.count() == 1

    def test_wrong_content_type_is_415(self):
        response = Client().post(CSP_URL, data="{}", content_type="text/plain")
        assert response.status_code == 415

    def test_report_without_a_directive_is_rejected(self):
        assert self._post({"csp-report": {"document-uri": "https://x/"}}).status_code == 400

    def test_get_is_not_allowed(self):
        assert Client().get(CSP_URL).status_code == 405

    @override_settings(BOUNCER_CSP_REPORTS_PER_IP_PER_HOUR=2)
    def test_per_address_hourly_cap_drops_the_excess_quietly(self):
        for index in range(6):
            payload = {
                "csp-report": {
                    "document-uri": f"https://example.com/p{index}/",
                    "violated-directive": "img-src",
                }
            }
            assert self._post(payload).status_code == 204
        assert SecurityEvent.objects.count() == 2
