# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Ruvelo/laravel-security-alerts/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Ruvelo/laravel-security-alerts/releases/tag/v1.0.0
