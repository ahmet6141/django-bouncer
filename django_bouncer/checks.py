"""Startup checks for the bouncer configuration itself.

These do not duplicate Django's ``check --deploy`` (HTTPS, cookies, secret
key). They cover the mistakes that make *this* package behave differently from
how it reads: a middleware in the wrong position, a proxy count that silently
trusts a forwarded header, a per-process cache that cannot share counters
between workers, or an auto-ban switch that writes bans nothing ever applies.

Run them with::

    python manage.py check
    python manage.py check --deploy
"""
from __future__ import annotations

import ipaddress

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

from django_bouncer import policy

BOUNCER_MIDDLEWARE_PREFIX = "django_bouncer.middleware."
CLIENT_IP_MIDDLEWARE = BOUNCER_MIDDLEWARE_PREFIX + "ClientIPMiddleware"


def _installed_middleware() -> list:
    try:
        return [str(item) for item in getattr(settings, "MIDDLEWARE", ()) or ()]
    except Exception:  # noqa: BLE001
        return []


def _bouncer_middleware(installed: list) -> list:
    return [item for item in installed if item.startswith(BOUNCER_MIDDLEWARE_PREFIX)]


def _cache_backend() -> str:
    try:
        return str(settings.CACHES["default"]["BACKEND"])
    except Exception:  # noqa: BLE001
        return ""


@register(Tags.security)
def check_middleware(app_configs, **kwargs):
    """Presence and ordering of the middleware stack."""
    from django_bouncer.middleware import MIDDLEWARE_ORDER

    issues = []
    installed = _installed_middleware()
    ours = _bouncer_middleware(installed)

    if not ours:
        return [
            Warning(
                "django_bouncer is installed but none of its middleware is active.",
                hint=(
                    "Add the middleware listed in django_bouncer.middleware."
                    "MIDDLEWARE_ORDER to settings.MIDDLEWARE, right after "
                    "django.middleware.security.SecurityMiddleware."
                ),
                id="bouncer.W001",
            )
        ]

    if CLIENT_IP_MIDDLEWARE not in installed:
        issues.append(
            Error(
                "ClientIPMiddleware is missing while other bouncer middleware is active.",
                hint=(
                    "Without it every layer resolves the client address on its own and "
                    "request.bouncer_ip is never set. Add "
                    f"'{CLIENT_IP_MIDDLEWARE}' as the first bouncer entry."
                ),
                id="bouncer.E001",
            )
        )

    positions = {name: installed.index(name) for name in ours if name in installed}
    expected = [name for name in MIDDLEWARE_ORDER if name in positions]
    actual = sorted(expected, key=lambda name: positions[name])
    if expected != actual:
        issues.append(
            Error(
                "Bouncer middleware is out of order in settings.MIDDLEWARE.",
                hint=(
                    "Expected relative order: "
                    + " → ".join(name.rsplit(".", 1)[-1] for name in expected)
                    + ". Found: "
                    + " → ".join(name.rsplit(".", 1)[-1] for name in actual)
                    + ". IPBanMiddleware in particular must run before the "
                    "detection layers so a banned address is rejected first."
                ),
                id="bouncer.E002",
            )
        )
    return issues


@register(Tags.security)
def check_values(app_configs, **kwargs):
    """Settings that are silently ignored when they are malformed."""
    issues = []

    for entry in policy.trusted_ips():
        try:
            if "/" in entry:
                ipaddress.ip_network(entry, strict=False)
            else:
                ipaddress.ip_address(entry)
        except ValueError:
            issues.append(
                Error(
                    f"BOUNCER_TRUSTED_IPS contains an unparseable entry: {entry!r}.",
                    hint="Use an address (203.0.113.7) or a CIDR block (10.0.0.0/8).",
                    id="bouncer.E003",
                )
            )

    raw_mode = str(policy._raw("BOUNCER_MODE") or "").strip().lower()
    if raw_mode and raw_mode not in policy.MODES:
        issues.append(
            Error(
                f"BOUNCER_MODE={raw_mode!r} is not a valid mode; 'enforce' is being used.",
                hint="Valid values: " + ", ".join(policy.MODES) + ".",
                id="bouncer.E004",
            )
        )

    raw_layers = policy._raw("BOUNCER_LAYER_MODES")
    if raw_layers is not None:
        declared = (
            set(raw_layers)
            if isinstance(raw_layers, dict)
            else {
                part.split("=", 1)[0].strip().lower()
                for part in str(raw_layers).split(",")
                if "=" in part
            }
        )
        unknown = {str(name).lower() for name in declared} - set(policy.LAYERS)
        if unknown:
            issues.append(
                Error(
                    "BOUNCER_LAYER_MODES names unknown layers: "
                    + ", ".join(sorted(unknown))
                    + ".",
                    hint="Valid layers: " + ", ".join(policy.LAYERS) + ".",
                    id="bouncer.E005",
                )
            )

    raw_rules = policy._raw("BOUNCER_RATE_LIMIT_RULES")
    if raw_rules is not None:
        if isinstance(raw_rules, str):
            declared = [item.strip() for item in raw_rules.split(",") if item.strip()]
        else:
            declared = list(raw_rules)
        dropped = [item for item in declared if policy._coerce_rule(item) is None]
        if dropped:
            issues.append(
                Error(
                    "These BOUNCER_RATE_LIMIT_RULES entries could not be parsed and "
                    "were dropped: " + ", ".join(repr(item) for item in dropped[:5]) + ".",
                    hint=(
                        "Each rule is ('/prefix', requests_per_minute[, burst_factor]) "
                        "or {'prefix': '/x/', 'limit': 60}. The prefix must start with "
                        "'/' and the limit must be at least 1."
                    ),
                    id="bouncer.E006",
                )
            )
    return issues


@register(Tags.security)
def check_runtime_dependencies(app_configs, **kwargs):
    """The cache and session pieces every counter depends on."""
    issues = []
    if not _bouncer_middleware(_installed_middleware()):
        return issues

    backend = _cache_backend()
    if backend.endswith("DummyCache"):
        issues.append(
            Warning(
                "The default cache is DummyCache, so no bouncer counter can work.",
                hint=(
                    "Rate limits, staff trust, login locks and ban caching are all "
                    "cache-backed. Configure a real cache (Redis or Memcached) before "
                    "relying on any of them."
                ),
                id="bouncer.W002",
            )
        )
    elif backend.endswith("LocMemCache"):
        issues.append(
            Warning(
                "The default cache is LocMemCache, which is per-process.",
                hint=(
                    "With several gunicorn workers each one counts separately, so the "
                    "effective rate limit is the configured limit times the worker "
                    "count. Use a shared cache in production."
                ),
                id="bouncer.W003",
            )
        )

    if policy.staff_bypass_enabled():
        installed_apps = set(getattr(settings, "INSTALLED_APPS", ()) or ())
        if "django.contrib.sessions" not in installed_apps:
            issues.append(
                Warning(
                    "Staff bypass is enabled but django.contrib.sessions is not installed.",
                    hint=(
                        "Staff are recognised from the session cookie, because the "
                        "security layers run before AuthenticationMiddleware. Without "
                        "sessions only BOUNCER_TRUSTED_IPS can grant a bypass."
                    ),
                    id="bouncer.W004",
                )
            )
    return issues


@register(Tags.security)
def check_policy_coherence(app_configs, **kwargs):
    """Combinations that are valid but almost certainly not what was meant."""
    issues = []
    if not _bouncer_middleware(_installed_middleware()):
        return issues

    if policy.auto_ban_enabled() and not policy.ban_enforcement_enabled():
        issues.append(
            Warning(
                "BOUNCER_AUTO_BAN is on while BOUNCER_BAN_ENFORCEMENT is off.",
                hint=(
                    "Bans are being written and audited but nobody is turned away. "
                    "That is a valid dry run — switch BOUNCER_BAN_ENFORCEMENT on once "
                    "the ban list looks right."
                ),
                id="bouncer.W005",
            )
        )

    if (
        policy.ban_enforcement_enabled()
        and not policy.staff_bypass_enabled()
        and not policy.trusted_ips()
    ):
        issues.append(
            Warning(
                "Ban enforcement is on with no staff bypass and no trusted addresses.",
                hint=(
                    "Nothing can lift a ban on your own address from the browser; "
                    "recovery would need shell access "
                    "(manage.py bouncer_unban <ip> --trust). Set BOUNCER_TRUSTED_IPS "
                    "or leave BOUNCER_STAFF_BYPASS on."
                ),
                id="bouncer.W006",
            )
        )

    if policy.shadow_proxy_count() and (
        policy.shadow_proxy_count() == policy.trusted_proxy_count()
    ):
        issues.append(
            Warning(
                "BOUNCER_SHADOW_PROXY_COUNT equals BOUNCER_TRUSTED_PROXY_COUNT.",
                hint=(
                    "The shadow resolver exists to compare a *different* candidate "
                    "count against live traffic; matching values only add work."
                ),
                id="bouncer.W007",
            )
        )
    return issues


@register(Tags.security, deploy=True)
def check_deployment(app_configs, **kwargs):
    """Production-only expectations."""
    issues = []
    if not _bouncer_middleware(_installed_middleware()):
        return issues

    behind_proxy = bool(
        getattr(settings, "SECURE_PROXY_SSL_HEADER", None)
        or getattr(settings, "USE_X_FORWARDED_HOST", False)
        or getattr(settings, "USE_X_FORWARDED_PORT", False)
    )
    if behind_proxy and policy.trusted_proxy_count() == 0:
        issues.append(
            Warning(
                "This deployment looks proxied but BOUNCER_TRUSTED_PROXY_COUNT is 0.",
                hint=(
                    "Every request will be attributed to the proxy's address, so one "
                    "rate bucket is shared by all visitors and a ban would hit "
                    "everyone. Set the number of proxies you operate, counted from the "
                    "right of X-Forwarded-For (usually 1)."
                ),
                id="bouncer.W008",
            )
        )

    if policy.mode() != policy.MODE_ENFORCE:
        issues.append(
            Warning(
                f"BOUNCER_MODE is {policy.mode()!r}, so no layer blocks anything.",
                hint=(
                    "Detections are still logged, which is the right way to start. "
                    "Set BOUNCER_MODE=enforce once the audit log looks clean."
                ),
                id="bouncer.W009",
            )
        )
    else:
        observing = sorted(
            layer for layer in policy.LAYERS if policy.layer_mode(layer) != policy.MODE_ENFORCE
        )
        if observing:
            issues.append(
                Warning(
                    "Some layers are not enforcing: " + ", ".join(observing) + ".",
                    hint="Set or remove the BOUNCER_LAYER_MODES entry when the rollout ends.",
                    id="bouncer.W010",
                )
            )
    return issues
