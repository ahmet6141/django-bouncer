"""Optional URLs. Include them where you like::

    path("bouncer/", include("django_bouncer.urls")),

and point the CSP ``report-uri`` / ``report-to`` endpoint at
``/bouncer/csp-report/``. Add that same path to
``BOUNCER_WAF_BODY_SCAN_EXCLUDED_PATHS``: a violation report legitimately
quotes the markup that was blocked, which is exactly what the WAF looks for.
"""
from django.urls import path

from django_bouncer import views

app_name = "django_bouncer"

urlpatterns = [
    path("csp-report/", views.csp_violation_report, name="csp-report"),
]
