"""Central configuration surface for django-bouncer.

Every knob is read through this module and every read follows one precedence
rule:

    settings.BOUNCER_X   >   os.environ["BOUNCER_X"]   >   built-in default

The environment fallback is deliberate: an operator can widen a limit or move a
layer to observe-only with a process restart instead of a code deploy. Values
are re-read on each call so ``override_settings`` behaves in tests; only the
parsing of a raw value is cached, keyed by that value.

Layer modes
-----------
Each middleware asks :func:`layer_mode` before it acts:

    ``enforce``   detect, log, block, and feed the auto-ban policy
    ``observe``   detect and log with ``blocked=False``; never block, never ban
    ``off``       skip the layer entirely (no detection, no logging)

``BOUNCER_MODE`` sets the default for every layer; ``BOUNCER_LAYER_MODES``
overrides individual layers, which is how a new signature set gets rolled out
in observe-only while the rest of the stack keeps enforcing.
"""
from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

from django.conf import settings

MODE_ENFORCE = "enforce"
MODE_OBSERVE = "observe"
MODE_OFF = "off"
MODES = (MODE_ENFORCE, MODE_OBSERVE, MODE_OFF)

LAYER_IP_BAN = "ip_ban"
LAYER_HONEYPOT = "honeypot"
LAYER_JSON = "json"
LAYER_WAF = "waf"
LAYER_BOT = "bot"
LAYER_RATE_LIMIT = "rate_limit"
LAYERS = (
    LAYER_IP_BAN,
    LAYER_HONEYPOT,
    LAYER_JSON,
    LAYER_WAF,
    LAYER_BOT,
    LAYER_RATE_LIMIT,
)


# ── Raw readers ───────────────────────────────────────────────────────────

def _raw(name: str, default=None):
    """settings.NAME > env NAME > default."""
    value = getattr(settings, name, None)
    if value is None:
        value = os.environ.get(name)
    return default if value is None else value


def _bool(name: str, default: bool) -> bool:
    value = _raw(name)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    value = _raw(name)
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    value = _raw(name)
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _str(name: str, default: str = "") -> str:
    value = _raw(name)
    return default if value is None else str(value).strip()


def _list(name: str, default: Iterable[str] = ()) -> tuple:
    value = _raw(name)
    if value is None:
        return tuple(default)
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    return tuple(str(item).strip() for item in value if str(item).strip())


# ── Modes ─────────────────────────────────────────────────────────────────

def mode() -> str:
    value = _str("BOUNCER_MODE", MODE_ENFORCE).lower()
    return value if value in MODES else MODE_ENFORCE


@lru_cache(maxsize=8)
def _parse_layer_modes(raw) -> dict:
    """Accept ``{"waf": "observe"}`` (as sorted pairs) or ``"waf=observe"``."""
    parsed: dict = {}
    if isinstance(raw, tuple):
        items = list(raw)
    else:
        items = [
            tuple(part.split("=", 1))
            for part in str(raw).split(",")
            if "=" in part
        ]
    for pair in items:
        if len(pair) != 2:
            continue
        key = str(pair[0]).strip().lower()
        value = str(pair[1]).strip().lower()
        if key in LAYERS and value in MODES:
            parsed[key] = value
    return parsed


def layer_modes() -> dict:
    raw = _raw("BOUNCER_LAYER_MODES")
    if raw is None:
        return {}
    if isinstance(raw, dict):
        raw = tuple(sorted((str(k), str(v)) for k, v in raw.items()))
    return _parse_layer_modes(raw)


def layer_mode(layer: str) -> str:
    return layer_modes().get(layer, mode())


def is_enforcing(layer: str) -> bool:
    return layer_mode(layer) == MODE_ENFORCE


def is_disabled(layer: str) -> bool:
    return layer_mode(layer) == MODE_OFF


# ── Client IP contract ────────────────────────────────────────────────────

def trusted_proxy_count() -> int:
    """Number of proxies you operate, counted from the right of the chain.

    Zero — the default — ignores every forwarded header, which is the only
    safe assumption for a server that can also be reached directly.
    """
    return max(0, _int("BOUNCER_TRUSTED_PROXY_COUNT", 0))


def shadow_proxy_count() -> int:
    """Optional second count, resolved and logged but never acted on.

    Used to verify a proxy-count change against live traffic before switching.
    """
    return max(0, _int("BOUNCER_SHADOW_PROXY_COUNT", 0))


# ── Ban switches ──────────────────────────────────────────────────────────

def ban_enforcement_enabled() -> bool:
    """Whether existing ban rows may block anyone. Default off (recovery-safe)."""
    return _bool("BOUNCER_BAN_ENFORCEMENT", False)


def auto_ban_enabled() -> bool:
    """Whether detectors may create new automatic bans. Default off."""
    return _bool("BOUNCER_AUTO_BAN", False)


def trusted_ips() -> tuple:
    """Addresses/CIDRs that bypass every layer (loopback is always added)."""
    return _list("BOUNCER_TRUSTED_IPS")


# ── Staff bypass ──────────────────────────────────────────────────────────

def staff_bypass_enabled() -> bool:
    return _bool("BOUNCER_STAFF_BYPASS", True)


def staff_trust_days() -> int:
    return max(0, _int("BOUNCER_STAFF_TRUST_DAYS", 7))


# ── Rate limiting ─────────────────────────────────────────────────────────

def rate_multiplier() -> float:
    value = _float("BOUNCER_RATE_MULTIPLIER", 1.0)
    return value if value > 0 else 1.0


@dataclass(frozen=True)
class RateLimitRule:
    path_prefix: str
    limit_per_minute: int
    burst_factor: float = 1.5


DEFAULT_RATE_LIMIT_RULES = (
    ("/admin/login", 10),
    ("/admin/", 120),
    ("/api/", 240),
    ("/", 240),
)


def _coerce_rule(item):
    try:
        if isinstance(item, RateLimitRule):
            return item
        if isinstance(item, dict):
            prefix = str(item["prefix"])
            limit = int(item["limit"])
            burst = float(item.get("burst", 1.5))
        elif isinstance(item, str) and "=" in item:
            head, _, limit_text = item.partition("=")
            prefix, limit, burst = head.strip(), int(limit_text), 1.5
        else:
            prefix = str(item[0])
            limit = int(item[1])
            burst = float(item[2]) if len(item) > 2 else 1.5
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    if not prefix.startswith("/") or limit < 1:
        return None
    return RateLimitRule(prefix, limit, burst if burst > 0 else 1.5)


@lru_cache(maxsize=8)
def _build_rules(raw: tuple, login_prefixes: tuple) -> tuple:
    rules = [rule for rule in map(_coerce_rule, raw) if rule is not None]
    if not rules:
        rules = [_coerce_rule(item) for item in DEFAULT_RATE_LIMIT_RULES]
        rules = [rule for rule in rules if rule is not None]
        # Auth endpoints are the brute-force surface, so they get their own
        # strict bucket ahead of the generic rules — unless the project
        # supplied a full rule list of its own. A login path already covered by
        # a specific default (``/admin/login/`` under ``/admin/login``) is
        # skipped, so the table stays free of duplicate rows.
        covered = tuple(
            rule.path_prefix for rule in rules if rule.path_prefix != "/"
        )
        auth_rules = [
            RateLimitRule(prefix, 10)
            for prefix in login_prefixes
            if not prefix.startswith(covered)
        ]
        rules = auth_rules + rules
    if not any(rule.path_prefix == "/" for rule in rules):
        rules.append(RateLimitRule("/", 240))
    return tuple(rules)


def rate_limit_rules() -> tuple:
    """Ordered rules; the first matching prefix wins. Always ends with ``/``."""
    raw = _raw("BOUNCER_RATE_LIMIT_RULES")
    if raw is None:
        normalized: tuple = ()
    elif isinstance(raw, str):
        normalized = tuple(item.strip() for item in raw.split(",") if item.strip())
    else:
        items = []
        for item in raw:
            if isinstance(item, dict):
                items.append(tuple(sorted(item.items())))
            elif isinstance(item, str | RateLimitRule):
                items.append(item)
            else:
                items.append(tuple(item))
        normalized = tuple(items)
    return _build_rules(normalized, _login_prefixes())


# Single-minute burst multiple treated as hammering: the ban policy is
# evaluated immediately instead of waiting for the next minute bucket.
RATE_HAMMER_FACTOR = 10

# Brute force: N failures inside a window lock the login POST for M minutes.
LOGIN_FAIL_LOCK_COUNT = 15
LOGIN_FAIL_LOCK_WINDOW_MIN = 15
LOGIN_FAIL_LOCK_MINUTES = 15


# ── Paths ─────────────────────────────────────────────────────────────────

# Server-to-server endpoints normally carry their own HMAC/signature check and
# arrive with an empty or library User-Agent. Blocking one of them silently
# breaks payment confirmations, so a project must list them explicitly in
# BOUNCER_EXEMPT_PATHS — nothing project-specific is assumed here.
DEFAULT_EXEMPT_PREFIXES = (
    "/.well-known/",
    "/robots.txt",
    "/sitemap",
    "/sw.js",
    "/manifest.json",
    "/ads.txt",
)


@lru_cache(maxsize=8)
def _exempt_prefixes(extra: tuple) -> tuple:
    return tuple(DEFAULT_EXEMPT_PREFIXES) + tuple(extra)


def exempt_prefixes() -> tuple:
    return _exempt_prefixes(_list("BOUNCER_EXEMPT_PATHS"))


def is_exempt_path(path: str) -> bool:
    if not path:
        return False
    return strip_lang_prefix(path).startswith(exempt_prefixes())


def api_prefixes() -> tuple:
    return _list("BOUNCER_API_PREFIXES", ("/api/",))


def is_api_path(path: str) -> bool:
    """Endpoints where programmatic clients are expected and normal."""
    if not path:
        return False
    stripped = strip_lang_prefix(path)
    return any(
        stripped.startswith(prefix) or prefix in stripped
        for prefix in api_prefixes()
    )


# ── Language prefixes (i18n_patterns: /en/...) ────────────────────────────

@lru_cache(maxsize=8)
def _lang_prefixes(codes: tuple) -> tuple:
    return tuple(f"/{code}/" for code in codes) + tuple(f"/{code}" for code in codes)


def _language_codes() -> tuple:
    codes = []
    try:
        for code, _name in getattr(settings, "LANGUAGES", ()):
            codes.append(str(code).lower())
    except Exception:  # noqa: BLE001
        pass
    return tuple(codes)


def strip_lang_prefix(path: str) -> str:
    """``/en/accounts/login/`` → ``/accounts/login/``.

    Every rule match runs on the stripped path, so a translated URL cannot be
    used to slip past a prefix rule.
    """
    if not path:
        return path
    lowered = path.lower()
    for prefix in _lang_prefixes(_language_codes()):
        if prefix.endswith("/"):
            if lowered.startswith(prefix):
                return "/" + path[len(prefix):]
        elif lowered == prefix:
            return "/"
    return path


# ── Login paths ───────────────────────────────────────────────────────────

def _resolve_url(value: object) -> str:
    """Turn a settings URL (path or url name) into a path, or "" if unknown."""
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("/"):
        return text
    try:
        from django.urls import NoReverseMatch, reverse

        try:
            return reverse(text)
        except NoReverseMatch:
            return ""
    except Exception:  # noqa: BLE001 - the URLconf may not be importable yet
        return ""


def _login_prefixes() -> tuple:
    configured = _list("BOUNCER_LOGIN_PATHS")
    if configured:
        return configured
    paths = ["/admin/login/", "/admin/logout/"]
    for name in ("LOGIN_URL", "LOGOUT_URL", "LOGOUT_REDIRECT_URL"):
        resolved = _resolve_url(getattr(settings, name, ""))
        if resolved and resolved != "/":
            paths.append(resolved)
    seen, ordered = set(), []
    for path in paths:
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return tuple(ordered)


def login_url() -> str:
    """Path of the project's login view, or "" when it cannot be resolved."""
    return _resolve_url(getattr(settings, "LOGIN_URL", ""))


def login_paths() -> tuple:
    """Paths a temporarily banned IP may still reach.

    A staff member who banned their own address has to be able to sign in; the
    login view keeps its own rate limit and brute-force lock, and a permanent
    ban closes this door too.
    """
    return _login_prefixes()


def is_login_path(path: str) -> bool:
    stripped = strip_lang_prefix(path or "")
    candidates = login_paths()
    return stripped in candidates or stripped.rstrip("/") + "/" in candidates


# ── Misc knobs ────────────────────────────────────────────────────────────

def honeypot_field_name() -> str:
    """Hidden form field name.

    Override it with something specific to the project so browser autofill for
    a real ``website``/``company`` field cannot trigger a false positive.
    """
    return _str("BOUNCER_HONEYPOT_FIELD_NAME", "bouncer_hp_check") or "bouncer_hp_check"


def json_max_bytes() -> int:
    return max(1024, _int("BOUNCER_JSON_MAX_BYTES", 256 * 1024))


def waf_body_scan_excluded_paths() -> frozenset:
    return frozenset(_list("BOUNCER_WAF_BODY_SCAN_EXCLUDED_PATHS"))


def csp_reports_per_ip_per_hour() -> int:
    return max(1, _int("BOUNCER_CSP_REPORTS_PER_IP_PER_HOUR", 60))


def event_retention_days() -> int:
    """Retention used by ``manage.py bouncer_prune`` (0 disables pruning)."""
    return max(0, _int("BOUNCER_EVENT_RETENTION_DAYS", 90))


def support_url() -> str:
    """Optional contact link rendered on the block page ("" hides the line)."""
    return _str("BOUNCER_SUPPORT_URL", "")


def block_header_name() -> str:
    return _str("BOUNCER_BLOCK_HEADER", "X-Bouncer-Block") or "X-Bouncer-Block"


def reset_caches() -> None:
    """Clear value-keyed parse caches (tests, and after a settings reload)."""
    _exempt_prefixes.cache_clear()
    _lang_prefixes.cache_clear()
    _parse_layer_modes.cache_clear()
    _build_rules.cache_clear()
