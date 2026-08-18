# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [0.1.0] — 2026-08-18

First public release. The layer was extracted from a production Django marketplace that
had been running it behind a CDN, then generalised, de-branded and documented.

### Added

- Seven middleware classes: client-IP resolution, IP ban enforcement, URL/form honeypots,
  JSON request validation, a signature WAF, User-Agent classification and per-address
  rate limiting.
- `SecurityEvent` and `BannedIP` models with a cache-first ban lookup, admin screens and
  a migration.
- A conservative automatic ban policy: distinct-path thresholds, soft policies that never
  IP-ban a signed-in user, and no ban at all from a User-Agent signal.
- Layer modes — `enforce`, `observe`, `off` — globally via `BOUNCER_MODE` and per layer
  via `BOUNCER_LAYER_MODES`, so a rollout can be watched before it blocks anything.
- Startup checks (`bouncer.E001`–`E006`, `W001`–`W010`) covering middleware order, cache
  backend, unparseable settings, incoherent switch combinations and proxy configuration.
- Four management commands: `bouncer_status`, `bouncer_report`, `bouncer_unban`,
  `bouncer_prune`.
- A bounded CSP violation report endpoint.
- English source strings with a bundled Turkish catalogue for everything a visitor sees.
- 344 tests that run without a database server or Redis.

### Changed from the internal version

- Settings moved to a single `BOUNCER_*` namespace, each readable from the environment.
- Rate-limit rules, exempt paths, login paths, the honeypot field name, honeypot paths,
  API prefixes and User-Agent lists became configuration instead of hard-coded values.
- The user model reference became `settings.AUTH_USER_MODEL`.
- `SECURITY_AUTO_BAN_ENABLED` defaulted to `True` in code while the documentation and the
  host project both said off. The default is now `False` in one place, matching what the
  documentation promises.
- Duplicate rate-limit rows (`/admin/login` and `/admin/login/`) are collapsed when the
  defaults are derived from `LOGIN_URL`.
- Static-path detection reads `STATIC_URL` and `MEDIA_URL` instead of assuming `/static/`
  and `/media/`.

[0.1.0]: https://github.com/ahmet6141/django-bouncer/releases/tag/v0.1.0
