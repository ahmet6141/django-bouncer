# Settings reference

Every knob is read through `django_bouncer.policy` with one precedence rule:

```
settings.BOUNCER_X   >   os.environ["BOUNCER_X"]   >   built-in default
```

Values are re-read on every request, so an environment change takes effect on the next
process restart — no deploy, no migration. Lists accept either a Python list or a
comma-separated string, which is what makes the environment fallback usable.

`python manage.py bouncer_status` prints the resolved values for the running process.
Anything malformed is reported by `python manage.py check` rather than silently ignored.

---

## Modes

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_MODE` | `enforce` | `enforce`, `observe` or `off` for every layer at once. `observe` detects and logs (`blocked=False`) but never blocks and never bans. `off` skips detection entirely. |
| `BOUNCER_LAYER_MODES` | `{}` | Per-layer override: `{"waf": "observe", "bot": "off"}`, or `"waf=observe,bot=off"` from the environment. Layers: `ip_ban`, `honeypot`, `json`, `waf`, `bot`, `rate_limit`. |

## Client address

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_TRUSTED_PROXY_COUNT` | `0` | Number of proxies **you operate**, counted from the right of `X-Forwarded-For`. `0` ignores forwarded headers entirely. An nginx that rewrites the header is `1`, including when a CDN sits in front of it. Too high lets a visitor spoof an address; too low collapses every visitor into one bucket. |
| `BOUNCER_SHADOW_PROXY_COUNT` | `0` | A second count, resolved and logged on mismatch but never acted on. Use it to validate a change against live traffic before switching. |

The resolved address is published as `request.bouncer_ip` and is safe to use in your own
views (`from django_bouncer.client_ip import get_client_ip`).

## Bans

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_BAN_ENFORCEMENT` | `False` | Whether existing ban rows may block anyone. Off means the ban list is audit-only — this is the recovery switch. |
| `BOUNCER_AUTO_BAN` | `False` | Whether detectors may create new automatic bans at all. |
| `BOUNCER_TRUSTED_IPS` | `()` | Addresses/CIDRs that bypass every layer. Loopback is always included. |

Thresholds themselves live in `django_bouncer.ban_policy.POLICIES`; they are code, not
settings, because changing them safely requires understanding the distinct-path and
soft-policy guards around them.

## Staff bypass

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_STAFF_BYPASS` | `True` | A live staff session (read from the session cookie, before `AuthenticationMiddleware` runs) is never blocked or banned. |
| `BOUNCER_STAFF_TRUST_DAYS` | `7` | How long an address a staff user signed in from stays trusted. |

## Rate limiting

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_RATE_LIMIT_RULES` | see below | Ordered rules, first matching prefix wins. `("/prefix", per_minute)`, `("/prefix", per_minute, burst_factor)`, `{"prefix": ..., "limit": ..., "burst": ...}`, or `"/api/=240,/=120"` from the environment. A `/` catch-all is appended if you leave it out. |
| `BOUNCER_RATE_MULTIPLIER` | `1.0` | Scales every limit. The fastest way to relieve pressure during an incident. |

Defaults: the login path (from `LOGIN_URL`) and `/admin/login` at 10/min, `/admin/` at
120, `/api/` at 240, everything else at 240. The effective ceiling is
`limit × burst_factor (1.5) × multiplier` — the burst factor is what stops a page that
loads twelve resources from tripping its own limit.

Declare your own set as soon as you know your URLs:

```python
BOUNCER_RATE_LIMIT_RULES = [
    ("/accounts/login", 10),
    ("/accounts/register", 5),
    ("/cart/apply-discount/", 15),      # discount-code guessing
    ("/accounts/api/", 120),            # polling endpoints
    ("/api/", 240),
    ("/", 240),
]
```

## Paths

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_EXEMPT_PATHS` | `()` | Prefixes that skip **every** layer, added to the built-ins (`/.well-known/`, `/robots.txt`, `/sitemap`, `/sw.js`, `/manifest.json`, `/ads.txt`). Put your payment callbacks and webhooks here: they authenticate with their own signature and arrive with empty or library User-Agents. |
| `BOUNCER_LOGIN_PATHS` | derived | Paths a temporarily banned address may still reach. Derived from `LOGIN_URL`, `LOGOUT_URL` and `/admin/login/` when unset. |
| `BOUNCER_API_PREFIXES` | `("/api/",)` | Where programmatic clients are expected: library User-Agents are allowed and errors are returned as JSON. |

Language prefixes from `i18n_patterns` (`/en/…`) are stripped before every rule match, so
a translated URL cannot be used to slip past a prefix rule.

## Honeypots

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_HONEYPOT_FIELD_NAME` | `bouncer_hp_check` | Hidden form field name. Choose something your own forms never use, so browser autofill for a real `website` field cannot trip it. |
| `BOUNCER_HONEYPOT_PATHS` | `()` | Extra scanner paths, added to the built-in list. |

## Bot classification

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_ALLOWED_UA_TOKENS` | `()` | Substrings that mark a first-party client — your Electron app, your mobile SDK — and skip classification entirely. |
| `BOUNCER_SCANNER_UAS` | `()` | Extra scanner tokens. |
| `BOUNCER_GOOD_BOT_UAS` | `()` | Extra always-allowed crawler tokens. |

## Request bodies

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_JSON_MAX_BYTES` | `262144` | Maximum JSON body. Larger bodies are rejected with `413` and a stable error code. |
| `BOUNCER_WAF_BODY_SCAN_EXCLUDED_PATHS` | `()` | Endpoints whose body is not scanned — a CSP report collector legitimately quotes blocked markup. |

## Reporting and retention

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_CSP_REPORTS_PER_IP_PER_HOUR` | `60` | Cap on stored CSP reports per address per hour. Excess is accepted with `204` and dropped. |
| `BOUNCER_EVENT_RETENTION_DAYS` | `90` | Used by `bouncer_prune`. `0` disables event pruning. |

## Presentation

| Setting | Default | Meaning |
|---|---|---|
| `BOUNCER_SUPPORT_URL` | `""` | Contact link on the block page (`mailto:` or `https:`). Empty hides the line. |
| `BOUNCER_BLOCK_HEADER` | `X-Bouncer-Block` | Response header naming the rule that fired. Useful in access logs. |

---

## A worked production example

```python
BOUNCER_MODE = "enforce"
BOUNCER_TRUSTED_PROXY_COUNT = 1            # nginx rewrites X-Forwarded-For
BOUNCER_TRUSTED_IPS = env("BOUNCER_TRUSTED_IPS", "")
BOUNCER_EXEMPT_PATHS = "/payments/callback/,/webhooks/,/health/"
BOUNCER_RATE_LIMIT_RULES = [
    ("/accounts/login", 10),
    ("/accounts/register", 5),
    ("/api/", 240),
    ("/", 240),
]
BOUNCER_HONEYPOT_FIELD_NAME = "acme_hp_check"
BOUNCER_SUPPORT_URL = "mailto:support@example.com"
BOUNCER_AUTO_BAN = env.bool("BOUNCER_AUTO_BAN", False)
BOUNCER_BAN_ENFORCEMENT = env.bool("BOUNCER_BAN_ENFORCEMENT", False)
```

Keep the last two in the environment rather than in code: they are the switches you want
to flip from a shell at three in the morning without a deploy.
