## ruvelo/laravel-security-alerts

Watches the app's installed Composer and npm packages for published security advisories (Packagist, the source `composer audit` uses, and OSV.dev for `package-lock.json`), and marks the ones CISA lists as exploited in the wild. A daily scheduled check remembers what it has seen in the `security_alerts` table and alerts once per new finding, and once more if a known finding becomes exploited.

### Checking from the command line

@verbatim
<code-snippet name="Check for vulnerabilities" lang="bash">
php artisan security-alerts:check                      # table, exploited first; changes nothing
php artisan security-alerts:check --fail-on=exploited  # exit 1 in CI when an installed flaw is exploited (or: critical, high, medium, any)
php artisan security-alerts:check --json               # the report as JSON
php artisan security-alerts:check --notify             # what the scheduler runs: remember findings and send alerts for new ones
php artisan security-alerts:check --fresh              # skip the cached feeds
</code-snippet>
@endverbatim

Exit codes: `0` fine, `1` a finding reached `--fail-on`, `2` a lockfile or feed couldn't be read, so the answer is incomplete. After updating a dependency, run `security-alerts:check` to confirm the finding is gone. Fix exploited findings first; `fixed_in` is the version to update to (`>2.10.1` means "the first release after 2.10.1").

### PHP API

Use the static `Ruvelo\SecurityAlerts\SecurityAlerts` class. Don't call Packagist, OSV or CISA yourself, and don't parse `composer.lock` by hand.

@verbatim
<code-snippet name="Scan, check and read alerts" lang="php">
use Ruvelo\SecurityAlerts\SecurityAlerts;

$report = SecurityAlerts::scan();          // Report: findings worst first; saves and sends nothing
$report->exploited();                      // list<Finding> in CISA's catalogue
$report->isComplete();                     // false if a lockfile or feed couldn't be read; see $report->problems

$result = SecurityAlerts::check();         // scan + remember + events + one notification for what's new
$result->found; $result->exploited; $result->resolved;   // collections of SecurityAlert models

SecurityAlerts::open();                    // open SecurityAlert models, exploited first; database only, no network
SecurityAlerts::lastCheck();               // ['checked_at' => CarbonImmutable, 'findings' => 13, ...] or null
</code-snippet>
@endverbatim

- A `Finding` has `package`, `version`, `ecosystem` (`Ecosystem::Composer|Npm`), `advisoryId`, `title`, `severity` (`Severity::Critical|High|Medium|Low|Unknown`), `cve`, `link`, `fixedIn`, `dev`, and `exploited` (a `KevEntry` with `dateAdded`, `dueDate`, `ransomware`, or null). `isExploited()`.
- `Ruvelo\SecurityAlerts\Models\SecurityAlert` rows are written only by `SecurityAlerts::check()`. Never insert or update them yourself: that would break "alert once". Scopes: `open()`, `exploited()`, `worstFirst()`.
- Exceptions extend `Ruvelo\SecurityAlerts\Exceptions\SecurityAlertsException`: `NotInstalled` (run the migration), `LockfileUnreadable`, `SourceUnavailable`, `InvalidThreshold`. `scan()` turns lockfile and feed failures into `$report->problems` instead of throwing.

### Notifications and events

Mail and Slack are configured in `.env`; no code needed:

@verbatim
<code-snippet name="Who hears about it" lang="php">
// .env
// SECURITY_ALERTS_MAIL=ops@example.com,cto@example.com
// SECURITY_ALERTS_SLACK_WEBHOOK=https://hooks.slack.com/services/...   (needs laravel/slack-notification-channel)

// AppServiceProvider::boot(): also notify your own notifiables, through config('security-alerts.notify.via')
SecurityAlerts::notifyUsing(fn () => User::where('is_admin', true)->get());

// React to anything with events (each fires once per change)
Event::listen(\Ruvelo\SecurityAlerts\Events\VulnerabilityExploited::class, fn ($event) => Pager::page($event->alert->package));
</code-snippet>
@endverbatim

Events carry `$event->alert` (a `SecurityAlert`): `VulnerabilityFound` (new), `VulnerabilityExploited` (newly known to be exploited, new or not), `VulnerabilityResolved` (no longer installed). The notifications are `Notifications\VulnerabilitiesFound` and `Notifications\WeeklyDigest` (opt-in, `SECURITY_ALERTS_DIGEST=true`).

### Scheduling

The package schedules `security-alerts:check --notify` daily at `07:00` itself (`SECURITY_ALERTS_TIME`, or `SECURITY_ALERTS_SCHEDULE=false` to turn it off). Don't add it to `routes/console.php` again. Laravel's scheduler must be running.

### Optional integrations

- Laravel Pulse: add `<livewire:security-alerts cols="4" rows="2" />` to `resources/views/vendor/pulse/dashboard.blade.php`.
- spatie/laravel-health: `Health::checks([\Ruvelo\SecurityAlerts\Integrations\Health\SecurityAlertsCheck::new()])`; fails on exploited, warns from high (`->warnFrom('medium')`, `->failFrom('critical')`) and when no check ran for 48 hours.
- laravel/mcp: with `SECURITY_ALERTS_MCP=true`, agents get a read-only `list_security_alerts` tool (`php artisan mcp:start security-alerts`).

### Tests

Never let tests reach the feeds: fake them with `Http::fake()` (URLs under `packagist.org/api/security-advisories/`, `api.osv.dev/v1/`, `www.cisa.gov/`). For code that reads alerts, use the factory:

@verbatim
<code-snippet name="Alerts in tests" lang="php">
use Ruvelo\SecurityAlerts\Models\SecurityAlert;

SecurityAlert::factory()->exploited()->forPackage('livewire/livewire', '3.6.2')->create();
SecurityAlert::factory()->severity(\Ruvelo\SecurityAlerts\Severity::High)->create();
SecurityAlert::factory()->resolved()->create();
SecurityAlert::factory()->pending()->create();   // not yet notified
</code-snippet>
@endverbatim

Config (`config/security-alerts.php`, publish with `--tag=security-alerts-config`): `notify.*` (`mail`, `slack`, `via`, `min_severity`), `schedule.*`, `digest.*`, `composer.*` and `npm.*` (`lockfile`, `include_dev`), `sources.*.url`, `sources.kev.enabled`, `cache.*`, `http.*`, `table`, `run_migrations`, `mcp.*`.
