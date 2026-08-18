"""User-Agent classification — a graded equivalent of "bot fight mode".

Tiers:

    scanner    nikto / sqlmap / masscan / nuclei …      → 403, high severity
    scraper    python-requests / curl / axios / okhttp  → 403 on HTML pages
    headless   HeadlessChrome / puppeteer / playwright  → 403 on HTML pages
    empty      missing or shorter than 20 characters    → 403 on HTML pages
    good       Googlebot / social previews / uptime     → always allowed here

For the middle three tiers, API paths and ``HEAD``/``OPTIONS`` are treated as
legitimate: a library User-Agent is exactly what an API client or an uptime
check looks like, so those are logged and let through.

**A User-Agent never produces a global IP ban.** Developer tooling, an uptime
probe and a real browser routinely share one address, and the string itself is
trivially forged, so it is not evidence about the address. The request is
rejected; sustained abuse is caught by the rate limiter, which counts volume.

Two further signals are logged only, never enforced:

* missing browser headers (Accept / Accept-Language / Accept-Encoding);
* sub-second page transitions, counted only for real navigations
  (``Sec-Fetch-Mode: navigate``, prefetch and prerender excluded). Tab
  restores and link prefetching produce the same pattern, so this cannot be a
  blocking signal.

Projects extend the lists through ``BOUNCER_SCANNER_UAS``,
``BOUNCER_GOOD_BOT_UAS`` and ``BOUNCER_ALLOWED_UA_TOKENS`` — the last one is
how you exempt your own client, for example an Electron desktop app or a
first-party mobile SDK.
"""
from __future__ import annotations

import time

from django_bouncer import policy

from ._helpers import (
    block_response,
    get_client_ip,
    get_user_agent,
    is_api_path,
    is_bannable_client_ip,
    is_exempt_path,
    is_privileged,
    is_static_path,
    log_event,
)

# ── Attack tooling — the unambiguous tier ────────────────────────────────
# Tokens are deliberately specific: short words that could collide with a
# device or model name (xray, hydra, nmap alone) are absent or spelled out.
DEFAULT_SCANNER_UAS = (
    "nikto", "sqlmap", "nmap scripting", "masscan", "zgrab", "nessus",
    "openvas", "wpscan", "dirbuster", "gobuster", "feroxbuster", "ffuf",
    "nuclei", "metasploit", "havij", "acunetix", "burpsuite", "burp suite",
    "qualys", "netsparker", "arachni", "w3af", "jaeles", "commix",
    "joomscan", "zmeu", "morfeus", "dirb/", "whatweb",
)

# ── HTTP libraries and generic scrapers ──────────────────────────────────
DEFAULT_SCRAPER_UAS = (
    "python-requests", "python-urllib", "python/", "aiohttp", "httpx/",
    "go-http-client", "java/", "okhttp", "libwww-perl", "curl/", "wget/",
    "httpie", "node-fetch", "undici", "axios/", "guzzlehttp", "guzzle",
    "apache-httpclient", "http_request2", "scrapy", "php/", "faraday",
    "restsharp", "powershell", "rest-client", "perl/", "lwp::simple",
    "mozilla/4.0 (compatible;)",  # the classic empty-ish bot string
)

# ── Headless browsers ────────────────────────────────────────────────────
# "electron" is intentionally absent: desktop applications built on Electron
# are real first-party clients. Add your own via BOUNCER_ALLOWED_UA_TOKENS.
DEFAULT_HEADLESS_UAS = (
    "headlesschrome", "phantomjs", "slimerjs", "htmlunit", "selenium",
    "puppeteer", "playwright", "splash",
)

# ── Good bots (fully allowed in this layer) ──────────────────────────────
DEFAULT_GOOD_BOT_UAS = (
    # search engines
    "googlebot", "google-inspectiontool", "google-pagerenderer",
    "google-site-verification", "adsbot-google", "mediapartners-google",
    "storebot-google", "googleother", "google-safety", "feedfetcher-google",
    "bingbot", "bingpreview", "msnbot", "duckduckbot", "yandex", "baiduspider",
    "slurp", "applebot", "petalbot", "seznambot", "qwantify", "yeti",
    "coccocbot", "sogou", "naverbot",
    # social and messaging previews
    "facebookexternalhit", "facebookcatalog", "twitterbot", "linkedinbot",
    "telegrambot", "whatsapp", "discordbot", "slackbot", "skypeuripreview",
    "redditbot", "pinterestbot", "embedly", "iframely", "mastodon",
    "bluesky", "vkshare", "viber",
    # performance and uptime
    "chrome-lighthouse", "lighthouse", "gtmetrix", "pingdom", "uptimerobot",
    "statuscake", "betteruptime", "better uptime", "site24x7", "cloudflare",
    "pagespeed", "webpagetest",
)


def _extra(name: str) -> tuple:
    from django_bouncer.policy import _list

    return tuple(token.lower() for token in _list(name))


def scanner_uas() -> tuple:
    return DEFAULT_SCANNER_UAS + _extra("BOUNCER_SCANNER_UAS")


def good_bot_uas() -> tuple:
    return DEFAULT_GOOD_BOT_UAS + _extra("BOUNCER_GOOD_BOT_UAS")


def allowed_ua_tokens() -> tuple:
    """First-party clients that must never be classified (desktop app, SDK)."""
    return _extra("BOUNCER_ALLOWED_UA_TOKENS")


def is_good_bot(ua: str) -> bool:
    lowered = (ua or "").lower()
    return any(token in lowered for token in good_bot_uas())


def is_allowed_client(ua: str) -> bool:
    lowered = (ua or "").lower()
    tokens = allowed_ua_tokens()
    return bool(tokens) and any(token in lowered for token in tokens)


def classify_ua(ua: str):
    """Return ``(tier, token)`` or None. Tier ∈ scanner|headless|scraper|empty."""
    if not ua or not ua.strip():
        return ("empty", "empty_ua")
    lowered = ua.lower()
    if is_allowed_client(ua):
        return None
    for token in scanner_uas():
        if token in lowered:
            return ("scanner", token)
    for token in DEFAULT_HEADLESS_UAS:
        if token in lowered:
            return ("headless", token)
    for token in DEFAULT_SCRAPER_UAS:
        if token in lowered:
            return ("scraper", token)
    if len(ua.strip()) < 20:
        return ("empty", "short_ua")
    return None


def _missing_browser_headers(request) -> list:
    """Headers a real browser always sends and most bots do not."""
    missing = []
    if not request.META.get("HTTP_ACCEPT"):
        missing.append("accept")
    if not request.META.get("HTTP_ACCEPT_LANGUAGE"):
        missing.append("accept_language")
    if not request.META.get("HTTP_ACCEPT_ENCODING"):
        missing.append("accept_encoding")
    return missing


def _is_real_navigation(request) -> bool:
    """A person actually opening a page — not a prefetch, prerender or fetch."""
    meta = request.META
    purpose = (meta.get("HTTP_SEC_PURPOSE") or meta.get("HTTP_PURPOSE") or "").lower()
    if "prefetch" in purpose or "prerender" in purpose:
        return False
    mode = (meta.get("HTTP_SEC_FETCH_MODE") or "").lower()
    if mode:
        return mode == "navigate"
    # Older or header-less clients: treat an HTML Accept as a navigation.
    return (meta.get("HTTP_ACCEPT") or "")[:9] == "text/html"


_REQUEST_INTERVAL_KEY_TTL = 30  # seconds
_MIN_HUMAN_INTERVAL_MS = 80     # two navigations closer than this look automated


class BotDetectorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if is_static_path(path) or is_exempt_path(path):
            return self.get_response(request)

        layer_mode = policy.layer_mode(policy.LAYER_BOT)
        if layer_mode == policy.MODE_OFF:
            return self.get_response(request)
        enforcing = layer_mode == policy.MODE_ENFORCE

        from django.core.cache import cache

        from django_bouncer.models import SecurityEvent

        ua = get_user_agent(request)

        # 1) Good-bot allowlist
        if is_good_bot(ua):
            return self.get_response(request)

        verdict = classify_ua(ua)
        if verdict:
            tier, token = verdict
            ip = get_client_ip(request)

            # scraper / headless / empty: a library User-Agent is normal on an
            # API path, and HEAD/OPTIONS is what uptime and health checks use.
            harmless_method = request.method in ("HEAD", "OPTIONS")
            if tier != "scanner" and (
                harmless_method or (is_api_path(path) and tier != "headless")
            ):
                log_event(
                    request,
                    reason=SecurityEvent.REASON_BOT_UA_BLACKLIST,
                    severity=SecurityEvent.SEVERITY_LOW,
                    payload=f"{token} (allowed)",
                    blocked=False,
                    throttle_seconds=300,
                    throttle_key=token,
                )
                return self.get_response(request)
            if is_privileged(request, ip):
                return self.get_response(request)

            if tier == "scanner":
                reason = SecurityEvent.REASON_BOT_UA_BLACKLIST
                severity = SecurityEvent.SEVERITY_HIGH
            elif tier == "headless":
                reason = SecurityEvent.REASON_BOT_HEADLESS
                severity = SecurityEvent.SEVERITY_MEDIUM
            else:
                reason = SecurityEvent.REASON_BOT_UA_BLACKLIST
                severity = SecurityEvent.SEVERITY_MEDIUM
            log_event(
                request,
                reason=reason,
                severity=severity,
                payload=token,
                blocked=enforcing,
                throttle_seconds=60,
                throttle_key=token,
            )
            if enforcing:
                return block_response(request, reason="bot_blocked", ip=ip)
            return self.get_response(request)

        # 2) Missing browser headers — logged every five minutes, never blocked
        missing = _missing_browser_headers(request)
        if len(missing) >= 2:
            log_event(
                request,
                reason=SecurityEvent.REASON_BOT_NO_HEADERS,
                severity=SecurityEvent.SEVERITY_LOW,
                payload=",".join(missing),
                blocked=False,
                throttle_seconds=300,
            )

        # 3) Sub-second navigations — logged once a minute, never blocked
        if _is_real_navigation(request):
            ip = get_client_ip(request)
            if not is_bannable_client_ip(ip):
                return self.get_response(request)
            last_key = f"bnc:lastnav:{ip}"
            now_ms = int(time.time() * 1000)
            try:
                last_ms = cache.get(last_key)
                if last_ms is not None:
                    interval = now_ms - int(last_ms)
                    if 0 <= interval < _MIN_HUMAN_INTERVAL_MS:
                        log_event(
                            request,
                            reason=SecurityEvent.REASON_SCRAPER,
                            severity=SecurityEvent.SEVERITY_LOW,
                            payload=f"nav interval={interval}ms",
                            blocked=False,
                            throttle_seconds=60,
                        )
                cache.set(last_key, str(now_ms), timeout=_REQUEST_INTERVAL_KEY_TTL)
            except Exception:  # noqa: BLE001
                pass

        return self.get_response(request)
