"""Signature WAF — high-confidence OWASP-style attack patterns.

This is the equivalent of a CDN's managed rule set. Django already protects you
through the ORM and template auto-escaping, so this layer is defence in depth
plus scanner detection, not the primary shield. That framing drives the one
rule every signature here obeys: **never match something that can occur in
natural language**. "select the model from the list", "drop table lamp",
"delete from cart", "JavaScript: an intro", "foo -- bar" must all pass.

What is scanned:

* URL path and query string, percent-decoded once (scanning the raw encoded
  text would miss ``select%20*%20from`` while flagging harmless ``..%2f``).
* POST/PUT/PATCH bodies: form fields individually, with secret-looking field
  names skipped; JSON as raw text; multipart (file uploads) not at all.
  The body is read up to 64 KB.
* Known scanner paths (``wp-*``, ``.php``, ``.env``, ``phpmyadmin`` …) → 404.

What happens on a hit:

* 403, and the ``waf`` ban policy is consulted: at least five WAF events across
  at least two distinct endpoints within ten minutes. Privileged requests are
  never blocked; a signed-in user is never IP-banned for this soft signal.
* Scanner paths count towards the ``honeypot_url`` policy (three distinct paths).
* ``BOUNCER_WAF_BODY_SCAN_EXCLUDED_PATHS`` skips body scanning for endpoints
  that legitimately receive markup, such as a CSP report collector.

Every pattern is bounded (no unbounded ``.*`` between anchors) so a hostile
64 KB body cannot turn matching into a denial of service.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

from django_bouncer import policy

from ._helpers import (
    any_match,
    block_response,
    get_client_ip,
    is_exempt_path,
    is_privileged,
    is_static_path,
    log_event,
)

# ── SQL injection ────────────────────────────────────────────────────────
# Only SQL-specific combinations; prose stays clean.
_SQLI_PATTERNS = [
    re.compile(r"\bunion\s+(all\s+|distinct\s+)?select\b", re.I),
    re.compile(
        r"\bselect\s+(\*|[\w`\"'.]+(\s*,\s*[\w`\"'.]+)*)\s+from\s+[\w`\".]+"
        r"\s*(where\b|--|#|/\*|;)",
        re.I,
    ),
    re.compile(
        r"\bselect\s+(@@\w+|version\(\)|user\(\)|database\(\)|"
        r"current_user|sleep\s*\(|pg_sleep\s*\(|benchmark\s*\()",
        re.I,
    ),
    re.compile(
        r"(['\"`)]\s*|\b)(or|and)\s+['\"`]?\d+['\"`]?\s*=\s*['\"`]?\d+"
        r"\s*(--|#|/\*|'|\"|;|$)",
        re.I,
    ),  # ' OR 1=1--
    re.compile(r"'\s*(or|and)\s+'[^']*'\s*=\s*'", re.I),        # ' or 'a'='a
    re.compile(r"'\s*(--|#)\s*$", re.I),                        # trailing '-- / '#
    re.compile(r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d", re.I),  # time-based
    re.compile(r"\bwaitfor\s+delay\s+'", re.I),
    re.compile(r"\b(extractvalue|updatexml)\s*\(", re.I),       # error-based
    re.compile(r"\binformation_schema\.(tables|columns|schemata)\b", re.I),
    re.compile(r"\b(xp_cmdshell|sp_executesql|sp_oacreate)\b", re.I),   # MSSQL
    re.compile(r"\b(load_file\s*\(|into\s+(out|dump)file\b)", re.I),    # MySQL file
    re.compile(r"/\*!\d*\s*(select|union|and|or)\b", re.I),     # MySQL versioned
    re.compile(r"\b(unhex|char)\s*\(\s*\d+\s*(,\s*\d+\s*){3,}\)", re.I),
    re.compile(r"\bconcat\s*\(\s*0x[0-9a-f]+", re.I),
    re.compile(r";\s*(drop|truncate|alter)\s+(table|database)\s+\w+", re.I),  # stacked
    re.compile(r";\s*(insert\s+into|delete\s+from|update\s+\w+\s+set)\s+\w+", re.I),
]

# ── Cross-site scripting ─────────────────────────────────────────────────
# A tag context or an executable combination is required, so prose about
# "onclick handlers" or "javascript" survives.
_XSS_PATTERNS = [
    re.compile(r"<\s*script\b", re.I),
    re.compile(r"<\s*/\s*script\s*>", re.I),
    re.compile(
        r"(href|src|action|formaction|data|xlink:href)\s*=\s*['\"]?\s*javascript\s*:", re.I
    ),
    re.compile(
        r"javascript\s*:\s*(alert|prompt|confirm|eval|document|window|"
        r"fetch|location|self|top|parent|import)\b",
        re.I,
    ),
    re.compile(
        r"<\s*\w+[^<>]{0,1000}\s+on(load|error|click|mouseover|mouseenter|focus|"
        r"blur|change|submit|keydown|keyup|pointerover|animationstart|"
        r"toggle|begin|start|end)\s*=",
        re.I,
    ),
    re.compile(
        r"<\s*(iframe|object|embed|applet)\b[^<>]{0,1000}(javascript:|srcdoc|data:text/html)",
        re.I,
    ),
    re.compile(r"<\s*svg\b[^<>]{0,1000}\bon\w+\s*=", re.I),
    re.compile(r"<\s*img\b[^<>]{0,1000}\bonerror\s*=", re.I),
    re.compile(r"<\s*body\b[^<>]{0,1000}\bonload\s*=", re.I),
    re.compile(r"<\s*meta\b[^<>]{0,1000}http-equiv\s*=\s*['\"]?refresh", re.I),
    re.compile(r"document\s*\.\s*(cookie|domain)\b", re.I),
    re.compile(
        r"\b(alert|prompt|confirm)\s*\(\s*(document|window|origin|1|'xss'|\"xss\")", re.I
    ),
    re.compile(r"\beval\s*\(\s*(atob|String\s*\.\s*fromCharCode|unescape|decodeURI)", re.I),
    re.compile(r"String\s*\.\s*fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){2,}\)", re.I),
    re.compile(r"\bexpression\s*\(", re.I),
    re.compile(r"\bvbscript\s*:", re.I),
]

# ── Path traversal ───────────────────────────────────────────────────────
_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./){3,}|(\.\.\\){3,}", re.I),   # three levels up, not one or two
    re.compile(r"\.\.[/\\](etc|proc|windows|winnt|boot|usr|var|root|home)\b", re.I),
    re.compile(r"/etc/(passwd|shadow|hosts|group)\b", re.I),
    re.compile(r"/proc/self/(environ|cmdline|status)\b", re.I),
    re.compile(r"(c:\\|c:/)?(windows|winnt)[/\\](system32|win\.ini)", re.I),
    re.compile(r"\bboot\.ini\b", re.I),
    re.compile(r"%2e%2e(%2f|%5c|/|\\)", re.I),       # double-encoded
    re.compile(r"\.\.(%c0%af|%c1%9c|%252f|%255c)", re.I),  # overlong / double
    re.compile(r"\.\.;/", re.I),                     # Tomcat ..;/
    re.compile(r"\\\\\.\\(pipe|root|globalroot)", re.I),
]

# ── Command injection ────────────────────────────────────────────────────
_CMD_INJECTION_PATTERNS = [
    re.compile(r"(;|\||&&|`|\$\()\s*(cat|type)\s+(/etc/|c:\\)", re.I),
    re.compile(r"(;|\||&&|`|\$\()\s*(wget|curl)\s+(-\S+\s+)*(https?://|ftp://)", re.I),
    re.compile(
        r"(;|\||&&|`|\$\()\s*(nc|ncat|netcat)\s+(\S+\s+){0,4}\d+\.\d+\.\d+\.\d+", re.I
    ),
    re.compile(r"(nc|ncat|netcat)\s+(-\S+\s+)*-e\s+/bin/", re.I),
    re.compile(r"(;|\||&&|`|\$\()\s*(bash|sh|zsh)\s+-[ic]\b", re.I),
    re.compile(r"(;|\||&&|`|\$\()\s*/bin/(ba)?sh\b", re.I),
    re.compile(r"(;|\||&&|`|\$\()\s*(chmod|chown)\s+[0-7]{3,4}\s", re.I),
    re.compile(r"(;|\||&&|`|\$\()\s*rm\s+-rf\s+/", re.I),
    re.compile(r"(;|\||&&|`|\$\()\s*(whoami|uname\s+-a)\s*(;|\||&&|`|\)|$)", re.I),
    re.compile(r"(;|\||&&|`|\$\()\s*(python[23]?|perl|php|ruby)\s+-[cer]\s", re.I),
    re.compile(r"(;|\||&&)\s*(powershell|cmd\.exe|cmd)\s+(/c|-enc|-e|-nop)\b", re.I),
    re.compile(r"/dev/(tcp|udp)/\d", re.I),
    re.compile(r"\$\{jndi:(ldap|rmi|dns|ldaps|iiop|corba|nds|http)s?:", re.I),  # log4shell
    re.compile(r"\$\{\s*(env|sys|java|lower|upper)\s*:", re.I),
]

# ── Scanner paths ────────────────────────────────────────────────────────
# Routes that simply do not exist in a Django project; only scanners ask for
# them. Anchored, so a slug like "/products/mysql-icon" is never matched.
_SUSPICIOUS_PATH_PATTERNS = [
    re.compile(
        r"^/(wp-admin|wp-content|wp-includes|wp-json|wp-login\.php|xmlrpc\.php|"
        r"wlwmanifest\.xml)(/|$)",
        re.I,
    ),
    re.compile(r"/(wp-login|wp-config|wp-settings|xmlrpc)\.php(\?|$)", re.I),
    re.compile(
        r"^/(phpmyadmin|phpMyAdmin|pma|myadmin|adminer|mysqladmin|dbadmin)(/|\.php|$)", re.I
    ),
    re.compile(
        r"^/(\.env|\.git|\.svn|\.hg|\.htaccess|\.htpasswd|\.aws|\.ssh|\.docker|"
        r"\.idea|\.vscode)(/|$|\.)",
        re.I,
    ),
    re.compile(
        r"/(config|configuration|backup|old|database|db|dump|site|www|web|html|public_html)"
        r"\.(sql|zip|bak|tar|tar\.gz|tgz|rar|7z)(\?|$)",
        re.I,
    ),
    re.compile(
        r"/(shell|c99|r57|webshell|cmd|alfa|wso|b374k|mini|up|upload|x)"
        r"\.(php|asp|aspx|jsp)(\?|$)",
        re.I,
    ),
    re.compile(r"\.(php[3-8]?|phtml|asp|aspx|jsp|jspx|cgi|cfm|pl)(\?|$)", re.I),
    re.compile(
        r"^/(vendor/phpunit|laravel|telescope|_ignition|solr|struts|weblogic|"
        r"jenkins|actuator|console|manager/html|hudson|owa|ecp|autodiscover)(/|$)",
        re.I,
    ),
    re.compile(r"^/(cgi-bin|fckeditor|ckfinder|elfinder|filemanager)(/|$)", re.I),
]

# Body fields never scanned: the value is a secret, so a pattern is meaningless
# and logging a fragment of it would be worse than the attack.
_SKIP_FIELD_RX = re.compile(
    r"(password|passwd|pwd|token|csrf|secret|signature|hash|otp|code)", re.I
)

MAX_BODY_SCAN_BYTES = 64 * 1024


def _decode(text: str) -> str:
    """Percent-decode once (``+`` becomes a space).

    Double-encoded leftovers are covered by dedicated patterns rather than by
    decoding repeatedly, which would itself become an amplification vector.
    """
    if not text:
        return ""
    try:
        return unquote_plus(text)
    except Exception:  # noqa: BLE001
        return text


def _check_text(text: str):
    """Scan text against every pattern group.

    Returns ``(reason_code, severity, payload_snippet)`` or None.
    """
    if not text:
        return None
    if (match := any_match(text, _SQLI_PATTERNS)):
        return ("waf_sqli", 30, match)
    if (match := any_match(text, _XSS_PATTERNS)):
        return ("waf_xss", 30, match)
    if (match := any_match(text, _PATH_TRAVERSAL_PATTERNS)):
        return ("waf_path", 30, match)
    if (match := any_match(text, _CMD_INJECTION_PATTERNS)):
        return ("waf_cmd", 40, match)
    return None


def check_url(full_path: str):
    """Scan the decoded path and query string."""
    return _check_text(_decode(full_path))


def check_body(request):
    """Scan a request body: form fields one by one, JSON as raw text."""
    content_type = (request.META.get("CONTENT_TYPE") or "").lower()
    if "multipart/form-data" in content_type:
        return None
    try:
        raw = request.body[:MAX_BODY_SCAN_BYTES]
    except Exception:  # noqa: BLE001  (RequestDataTooBig and friends)
        return None
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    if "application/x-www-form-urlencoded" in content_type or (
        "json" not in content_type and "=" in text and "&" in text and "{" not in text
    ):
        for pair in text.split("&"):
            if not pair:
                continue
            key, _, value = pair.partition("=")
            if _SKIP_FIELD_RX.search(_decode(key)):
                continue
            result = _check_text(_decode(value))
            if result:
                return result
        return None
    return _check_text(text)


class WAFMiddleware:
    """Pattern-based WAF using high-confidence signatures only."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if is_static_path(path) or is_exempt_path(path):
            return self.get_response(request)

        layer_mode = policy.layer_mode(policy.LAYER_WAF)
        if layer_mode == policy.MODE_OFF:
            return self.get_response(request)
        enforcing = layer_mode == policy.MODE_ENFORCE

        from django_bouncer.models import SecurityEvent

        # 1) Known scanner paths — log and 404 (honeypot_url policy).
        if (match := any_match(policy.strip_lang_prefix(path), _SUSPICIOUS_PATH_PATTERNS)):
            ip = get_client_ip(request)
            if is_privileged(request, ip):
                return self.get_response(request)
            log_event(
                request,
                reason=SecurityEvent.REASON_HONEYPOT_URL,
                severity=SecurityEvent.SEVERITY_MEDIUM,
                payload=match,
                blocked=enforcing,
                throttle_seconds=10,
                throttle_key=path[:200],
            )
            if not enforcing:
                return self.get_response(request)
            self._tally_violation(
                request, ip, policy_name="honeypot_url", ban_reason="scanner_path"
            )
            return block_response(request, reason="suspicious_path", status=404, ip=ip)

        # 2) URL and query string (decoded)
        result = check_url(request.get_full_path())

        # 3) Body, for methods that carry one and endpoints that opted in
        if (
            result is None
            and request.method in ("POST", "PUT", "PATCH")
            and path not in policy.waf_body_scan_excluded_paths()
        ):
            try:
                result = check_body(request)
            except Exception:  # noqa: BLE001
                result = None

        if result:
            reason, severity, payload = result
            ip = get_client_ip(request)
            if is_privileged(request, ip):
                # Staff editing HTML or an embed in the admin must not trip it.
                return self.get_response(request)
            # One row per path per five seconds; distinct paths stay distinct
            # because the ban policy requires at least two of them.
            log_event(
                request,
                reason=reason,
                severity=severity,
                payload=payload,
                blocked=enforcing,
                throttle_seconds=5,
                throttle_key=path[:200],
            )
            if not enforcing:
                return self.get_response(request)
            self._tally_violation(request, ip, policy_name="waf", ban_reason=reason)
            return block_response(request, reason=reason, ip=ip)

        return self.get_response(request)

    @staticmethod
    def _tally_violation(request, ip, *, policy_name: str, ban_reason: str):
        """Hand the persisted event to the central, guarded ban policy."""
        from django_bouncer.ban_policy import evaluate_auto_ban

        evaluate_auto_ban(ip, policy_name, reason=ban_reason, request=request)
