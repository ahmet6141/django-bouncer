"""The bouncer middleware stack.

Activation — in ``settings.MIDDLEWARE``, directly after Django's own
``SecurityMiddleware``:

    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        # ── django-bouncer ──
        "django_bouncer.middleware.ClientIPMiddleware",
        "django_bouncer.middleware.IPBanMiddleware",
        "django_bouncer.middleware.HoneypotMiddleware",
        "django_bouncer.middleware.JSONRequestValidationMiddleware",
        "django_bouncer.middleware.WAFMiddleware",
        "django_bouncer.middleware.BotDetectorMiddleware",
        "django_bouncer.middleware.RateLimitMiddleware",
        # ───────────────────
        "django.contrib.sessions.middleware.SessionMiddleware",
        ...
    ]

The order matters. ``ClientIPMiddleware`` resolves the forwarded-header
contract once and every later layer reads only that answer; ``IPBanMiddleware``
must come first among the enforcing layers so a banned address is rejected
before anything else runs. ``django_bouncer.checks`` verifies the ordering at
startup and reports a system check when it is wrong.
"""
from .bot_detector import BotDetectorMiddleware
from .client_ip import ClientIPMiddleware
from .honeypot import HoneypotMiddleware
from .ip_ban import IPBanMiddleware
from .rate_limit import RateLimitMiddleware
from .request_validation import JSONRequestValidationMiddleware
from .waf import WAFMiddleware

#: Canonical order, used by the startup check and by the documentation.
MIDDLEWARE_ORDER = (
    "django_bouncer.middleware.ClientIPMiddleware",
    "django_bouncer.middleware.IPBanMiddleware",
    "django_bouncer.middleware.HoneypotMiddleware",
    "django_bouncer.middleware.JSONRequestValidationMiddleware",
    "django_bouncer.middleware.WAFMiddleware",
    "django_bouncer.middleware.BotDetectorMiddleware",
    "django_bouncer.middleware.RateLimitMiddleware",
)

__all__ = [
    "BotDetectorMiddleware",
    "ClientIPMiddleware",
    "HoneypotMiddleware",
    "IPBanMiddleware",
    "JSONRequestValidationMiddleware",
    "MIDDLEWARE_ORDER",
    "RateLimitMiddleware",
    "WAFMiddleware",
]
