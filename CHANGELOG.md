# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-13

The package now runs on [`ruvelo/security-advisories`](https://github.com/Ruvelo/security-advisories) ^1.1, the core shared by Ruvelo's security packages, instead of its own copy of the lockfile reading, sources, matching and reconciling. A change to how results are built now needs a core release or a Valtry deploy, not a release of this package.

**Upgrading:** nothing to do. Stored alerts are recognised, so nothing is sent again. By default a check now asks Valtry's Advisory API (package names only, never versions; signed answers) and falls back to the public feeds automatically. To never contact Valtry, set `SECURITY_ALERTS_SOURCE=public`.

### Added

- Valtry's signed Advisory API as the default source, with automatic fallback to Packagist, OSV and CISA KEV. Config `source` (`SECURITY_ALERTS_SOURCE`, `valtry` or `public`) and `valtry_url`; `RUVELO_ADVISORIES_SOURCE=public` in the environment also opts out.
- The data source in the output: the command summary ("Checked 67 Composer and 38 npm packages via Valtry, signed" or "via public feeds"), `source` and `sources` in `--json`, and the demo's report.
- `SecurityAlerts::sourceLabel()` and `SecurityAlerts::toArray()`.
- Bind a PSR-18 client to `Psr\Http\Client\ClientInterface` to use your own for HTTP.

### Changed

- Finding identity is stable across sources: a stored alert is matched by its key, its CVE and its aliases, so the same vulnerability reported under another id is neither new nor resolved. Alerts stored by 1.0 are recognised the same way.
- HTTP goes through Guzzle (PSR-18), the cache through PSR-16. `http.timeout` and `http.tries` still apply to the public feeds; Valtry gets 5 seconds.
- `Finding::$version` is `installed` and `$dev` is `isDev`; `Severity::Unknown` is `NotRated`; `KevEntry` dates are `DateTimeImmutable`. The classes moved to the core, and the old `Ruvelo\SecurityAlerts\...` class names still resolve. `--json` keeps `version` beside `installed`. The table still stores unrated severities as `unknown`.
- Wording of some `problems` and of the invalid `--fail-on` message comes from the core. An incomplete check (any problem) now resolves nothing, where 1.0 still resolved ecosystems that had been checked in full.
- `sources.kev.enabled = false` only skips downloading CISA's catalogue; Valtry's answers carry the exploited verdict.

### Removed

- The package's own lockfile readers, Packagist, OSV and KEV clients, version matching and report classes (now in the core).

## [1.0.0] - 2026-10-12

First release.

### Added

- `SecurityAlerts::scan()`: reads `composer.lock` and `package-lock.json` (lockfile versions 1 to 3), asks Packagist's security advisories API (Composer) and OSV.dev (npm), and returns a `Report` of `Finding`s, exploited first, then by severity. Missing or broken lockfiles and unreachable feeds become `$report->problems` instead of errors.
- CISA Known Exploited Vulnerabilities: findings whose CVE is in the catalogue are marked exploited, with the date added, the due date and known ransomware use.
- Fixed versions worked out from advisory ranges with `composer/semver`, including ranges split by minor version and "last affected" bounds (`>2.10.1`), and from OSV's ranges for npm.
- `SecurityAlerts::check()`: remembers findings in a `security_alerts` table, fires `VulnerabilityFound`, `VulnerabilityExploited` and `VulnerabilityResolved`, and sends one `VulnerabilitiesFound` notification for everything new or newly exploited. Each finding is sent once; unsent alerts wait for the next check; incomplete checks never resolve anything.
- Mail (`SECURITY_ALERTS_MAIL`), Slack webhooks (`SECURITY_ALERTS_SLACK_WEBHOOK`, with `laravel/slack-notification-channel`) and the app's own notifiables through `SecurityAlerts::notifyUsing()`. `notify.min_severity`; exploited findings are always sent.
- A daily scheduled check (07:00 by default, configurable or off) and an optional `WeeklyDigest` (`security-alerts:digest`).
- `php artisan security-alerts:check` with `--fail-on=exploited|critical|high|medium|any`, `--json`, `--notify` and `--fresh`; exit code 2 when the check was incomplete.
- Cached feeds, with a configurable store and lifetimes; configurable feed URLs for mirrors.
- `SecurityAlerts::open()` and `SecurityAlerts::lastCheck()`, which read the database only.
- Optional integrations: a Laravel Pulse card, a spatie/laravel-health check, and a read-only `list_security_alerts` MCP tool with laravel/mcp.
- `SecurityAlert` model factory with `exploited()`, `severity()`, `forPackage()`, `resolved()` and `pending()` states.
- Exceptions extending `SecurityAlertsException`: `NotInstalled`, `LockfileUnreadable`, `SourceUnavailable`, `InvalidThreshold`.
- Laravel Boost guidelines (`resources/boost/guidelines/core.blade.php`).

[Unreleased]: https://github.com/Ruvelo/laravel-security-alerts/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Ruvelo/laravel-security-alerts/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Ruvelo/laravel-security-alerts/releases/tag/v1.0.0
