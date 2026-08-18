# django-bouncer

**A second line of defence for Django — IP bans, WAF signatures, bot classification, honeypots and rate limits, built so that it never locks out the people it protects.**

[![CI](https://github.com/ahmet6141/django-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmet6141/django-bouncer/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Django 4.2+](https://img.shields.io/badge/django-4.2%20%7C%205.x-092E20)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇹🇷 [Türkçe README](README.tr.md)

---

A CDN in front of your site is the first line of defence, and it is a good one. It is also
not always on, not always right, and not aware of your URLs: it does not know that
`/cart/apply-discount/` deserves 15 requests a minute while `/api/` deserves 240, and it
cannot tell you *why* a particular visitor stopped being able to sign in.

django-bouncer is the layer underneath. Seven small middleware classes, two tables, four
management commands — and a set of rules about when an address may be banned that were
written after watching a naïve version ban real customers.

## The problem this package is actually about

Writing a rule that blocks an attack is easy. Writing one that blocks an attack *and* never
blocks a mobile customer is the hard part, and it is where most home-grown security layers
quietly fail:

| Trap | What django-bouncer does |
|---|---|
| One `/wp-login.php` probe bans an address | A probe is 404'd. A **ban** needs three *distinct* scanner paths in ten minutes — real scanners enumerate, curious humans do not. |
| A search for `drop table lamp` trips the WAF | Signatures never match natural language. 90+ benign strings are asserted to pass in the test suite. |
| Banning a CGNAT address takes out a whole neighbourhood | A signed-in user is never IP-banned for a "soft" signal (WAF, rate limit). Accounts are traceable; shared addresses are not. |
| `curl` in a User-Agent bans the developer's office | User-Agent detections **never** produce a global ban. The request is rejected; sustained abuse is caught by volume instead. |
| A 5xx storm looks like an attack | Rate-limit violations are counted once per minute bucket, not once per retried request. |
| You ban your own address | Sign in: a staff login lifts the ban and trusts the address for a week. Temporary bans leave the login page reachable for exactly this reason. |
| A forwarded header is trusted blindly | The client address comes from an explicit, deployment-owned proxy count, and fails closed to the socket peer. |
| Enabling it is a leap of faith | `BOUNCER_MODE=observe` detects and logs everything while blocking nothing. Bans are off by default, twice over. |

## What is in the box

Middleware, in the order they run:

| Middleware | Does | Can it ban? |
|---|---|---|
| `ClientIPMiddleware` | Resolves the trusted client address once and publishes `request.bouncer_ip`. | — |
| `IPBanMiddleware` | 403 for a banned address, one log line a minute. Login stays open under a temporary ban. | — |
| `HoneypotMiddleware` | `/wp-login.php`, `/.env`, `/phpmyadmin/` … → 404. Hidden form field filled → 403. | 3 distinct paths / 10 min → 30 min |
| `JSONRequestValidationMiddleware` | Bounds and parses JSON bodies; publishes `request.json_body`. | — |
| `WAFMiddleware` | High-confidence SQLi / XSS / traversal / command-injection signatures over the decoded URL, query and body. | 5 events across ≥2 endpoints / 10 min → 60 min |
| `BotDetectorMiddleware` | Classifies scanners, HTTP libraries, headless browsers and empty User-Agents; allows the known good bots. | **never** |
| `RateLimitMiddleware` | Per-address, per-minute limits by path prefix, plus a brute-force login lock. | 5 violation minutes / 10 min → 15 min |

Plus: an audit log and ban list in the admin, four operator commands, and startup checks
that catch the configuration mistakes this kind of package usually fails silently on.

## Install

```bash
pip install git+https://github.com/ahmet6141/django-bouncer.git
```

```python
# settings.py
INSTALLED_APPS = [..., "django_bouncer"]

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
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    ...
]
```

```bash
python manage.py migrate
python manage.py check --deploy      # verifies the wiring, not just Django's own settings
python manage.py bouncer_status      # prints what is actually in effect
```

Three settings are worth getting right before anything else:

```python
# How many proxies YOU operate, counted from the right of X-Forwarded-For.
# 0 (the default) ignores forwarded headers entirely. An nginx that rewrites
# the header is 1 — including when Cloudflare sits in front of that nginx.
BOUNCER_TRUSTED_PROXY_COUNT = 1

# Endpoints with their own signature check (payment callbacks, webhooks).
# They arrive with empty or library User-Agents; blocking one loses a payment.
BOUNCER_EXEMPT_PATHS = "/payments/callback/,/webhooks/"

# Your address, and anything else that must never be touched.
BOUNCER_TRUSTED_IPS = "203.0.113.7,10.0.0.0/8"
```

Every setting can also come from the environment under the same name, so an operator can
widen a limit with a restart instead of a deploy. Full list: **[docs/SETTINGS.md](docs/SETTINGS.md)**.

## Rolling it out without breaking your site

The defaults are already conservative — nothing is banned until you say so — but the
honest order is:

```bash
# 1. Watch. Everything is detected and logged, nothing is blocked.
BOUNCER_MODE=observe

# 2. Read what it would have done, for a few days.
python manage.py bouncer_report --hours 72

# 3. Enforce per-request blocking, still without any ban.
BOUNCER_MODE=enforce

# 4. Let detectors write bans, but keep them inert (audit only).
BOUNCER_AUTO_BAN=1

# 5. When the ban list looks right, make bans real.
BOUNCER_BAN_ENFORCEMENT=1
```

A single layer can lag behind the rest — useful when you add your own signatures:

```python
BOUNCER_LAYER_MODES = {"waf": "observe"}   # or "off"
```

## When something is blocked and you need to know why

```console
$ python manage.py bouncer_report --ip 203.0.113.44

--- 203.0.113.44 ---
BannedIP: active=True reason=scanner_path hits=3 expires=2026-08-18 17:40 note=Automatic honeypot_url policy: at least 3 signals within 10 minutes
cache ban='e:1755528000.0' staff_trust=False login_lock=None

Last 6 event(s):
  08-18 16:58:11 BLOCK honeypot_url    GET   /wp-login.php    /wp-login.php
  08-18 16:58:12 BLOCK honeypot_url    GET   /.env            /.env
  08-18 16:58:14 BLOCK honeypot_url    GET   /phpmyadmin/     /phpmyadmin
```

Four commands, all of them safe to run in production:

| Command | For |
|---|---|
| `bouncer_status [--json]` | What configuration is in effect, right now, in this process. |
| `bouncer_report [--ip X] [--hours N]` | Why an address was blocked; what is happening overall. |
| `bouncer_unban <ip> [--trust]` | Recovery from the shell when you cannot reach the admin. |
| `bouncer_prune [--days N] [--dry-run]` | Retention. The audit table is append-only; run this from cron. |

Locked yourself out? In order of convenience: **sign in** (a staff login lifts the ban on
that address and trusts it for a week) → admin → *Banned IPs* → "lift and trust" →
`python manage.py bouncer_unban <ip> --trust` over SSH.

## Startup checks

`manage.py check` reports the mistakes that otherwise show up as mysterious behaviour
weeks later:

- middleware missing, or in an order that defeats it (`bouncer.E001`, `E002`);
- an unparseable trusted address, mode, layer name or rate rule — all of which would
  otherwise be silently ignored (`E003`–`E006`);
- a `DummyCache` (no counter works) or a `LocMemCache` (each worker counts separately, so
  the real limit is your limit × worker count) (`W002`, `W003`);
- auto-ban on while enforcement is off, or enforcement on with no way back in
  (`W005`, `W006`);
- `--deploy` only: a proxied deployment with a proxy count of 0 — the case where every
  visitor shares one bucket and one ban hits everyone (`W008`).

## The honeypot form field

```django
{% load bouncer %}
<form method="post">{% csrf_token %}
  ...
  {% bouncer_honeypot %}
</form>
```

Give it a name your own forms would never use, so browser autofill cannot trip it:

```python
BOUNCER_HONEYPOT_FIELD_NAME = "acme_hp_check"
```

## CSP violation reports (optional)

```python
# urls.py
path("bouncer/", include("django_bouncer.urls")),
# settings.py — a report legitimately quotes the markup that was blocked,
# which is exactly what the WAF looks for.
BOUNCER_WAF_BODY_SCAN_EXCLUDED_PATHS = "/bouncer/csp-report/"
```

Reports are bounded three ways — body size, one row per identical report per hour, and a
per-address hourly cap — because a report endpoint is an attacker-controlled write path.

## What this package deliberately does not do

- **It is not a replacement for a CDN/WAF.** It is the layer that knows your URLs.
- **It does not do CAPTCHA, JS challenges or fingerprinting.** Those need a frontend
  contract; this is middleware.
- **It does not do GeoIP blocking.** Country is a poor proxy for intent and needs a
  database this package will not ship.
- **It does not try to be clever about "suspicious" behaviour.** Sub-second navigation
  and missing browser headers are logged, never blocked: tab restore and link prefetch
  produce the same signature.

## Compatibility

Python 3.10–3.13 · Django 4.2, 5.0, 5.1, 5.2 · any cache backend (Redis or Memcached in
production; see `bouncer.W003`) · any database Django supports.

English and Turkish are bundled; the visitor-facing pages go through `gettext`, so adding
a language is a `.po` file.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

344 tests, no database server and no Redis required — sqlite in memory and the local
cache. The suite is organised around the claims in this README: `test_ban_safety.py`
verifies the false-ban guarantees against a real database, `test_signatures.py` asserts
that ordinary text does not match, and `test_layer_modes.py` checks that observe mode
detects exactly what enforce mode blocks.

## Licence

MIT — see [LICENSE](LICENSE).
