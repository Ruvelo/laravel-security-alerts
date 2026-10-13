<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAlerts\Exceptions\NotInstalled;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;

/**
 * The package's API.
 *
 *     SecurityAlerts::scan();       // what's vulnerable right now; changes nothing
 *     SecurityAlerts::check();      // scan, remember, fire events, notify: what the scheduler runs
 *     SecurityAlerts::open();       // open alerts as of the last check, worst first; no network
 */
final class SecurityAlerts
{
    public const LAST_CHECK_KEY = 'security-alerts:last-check';

    /**
     * Reads the lockfiles and asks the advisory sources. Saves nothing and
     * sends nothing, so it's safe anywhere, CI included.
     */
    public static function scan(bool $fresh = false): Report
    {
        return app(Scanner::class)->scan($fresh);
    }

    /**
     * Scans, records what changed since the last check, fires
     * VulnerabilityFound, VulnerabilityExploited and VulnerabilityResolved,
     * and sends one notification for everything new.
     *
     * @throws NotInstalled When the migration hasn't run
     */
    public static function check(bool $fresh = false, bool $notify = true): CheckResult
    {
        $report = self::scan($fresh);
        $changes = app(Recorder::class)->record($report);
        $notified = $notify ? app(Notifier::class)->sendPending() : 0;

        self::rememberLastCheck($report);

        return new CheckResult($report, $changes['found'], $changes['exploited'], $changes['resolved'], $notified);
    }

    /**
     * Open alerts as of the last check, exploited first. Reads the database
     * only: fast enough for a dashboard or a health check.
     *
     * @return Collection<int, SecurityAlert>
     */
    public static function open(): Collection
    {
        return SecurityAlert::query()->open()->worstFirst()->get();
    }

    /**
     * Sends the weekly digest of open alerts now.
     *
     * @return Collection<int, SecurityAlert> The alerts it listed
     */
    public static function sendDigest(): Collection
    {
        return app(Notifier::class)->sendDigest();
    }

    /**
     * Who else hears about alerts, besides the configured mail and Slack:
     *
     *     SecurityAlerts::notifyUsing(fn () => User::where('is_admin', true)->get());
     *
     * They're sent through the channels in `security-alerts.notify.via`.
     *
     * @param  (Closure(): iterable<object>)|null  $callback
     */
    public static function notifyUsing(?Closure $callback): void
    {
        Notifier::using($callback);
    }

    /**
     * The report as JSON-ready data: the core's shape, plus `version` (the
     * installed version, as 1.0 called it) on each finding.
     *
     * @return array<string, mixed>
     */
    public static function toArray(Report $report): array
    {
        $data = $report->toArray();
        $data['findings'] = array_map(fn (array $finding): array => ['version' => $finding['installed']] + $finding, $data['findings']);

        return $data;
    }

    /**
     * Where a report's advisories came from, in words: "Valtry, signed" or
     * "public feeds" (both when ecosystems differed). With $via, "via ..." for a sentence.
     */
    public static function sourceLabel(Report $report, bool $via = false): string
    {
        $label = match ($report->source) {
            'valtry' => 'Valtry, signed',
            'mixed' => 'Valtry, signed, and public feeds',
            default => 'public feeds',
        };

        return $via ? 'via '.$label : $label;
    }

    /**
     * When the last check ran and what it found, or null if it never has
     * (or the cache was cleared since).
     *
     * @return array{checked_at: CarbonImmutable, packages: int, findings: int, exploited: int, complete: bool}|null
     */
    public static function lastCheck(): ?array
    {
        $data = self::cache()->get(self::LAST_CHECK_KEY);

        if (! is_array($data) || ! is_string($data['checked_at'] ?? null)) {
            return null;
        }

        return [
            'checked_at' => CarbonImmutable::parse($data['checked_at']),
            'packages' => (int) ($data['packages'] ?? 0),
            'findings' => (int) ($data['findings'] ?? 0),
            'exploited' => (int) ($data['exploited'] ?? 0),
            'complete' => (bool) ($data['complete'] ?? false),
        ];
    }

    private static function cache(): Repository
    {
        $store = config('security-alerts.cache.store');

        return Cache::store(is_string($store) && $store !== '' ? $store : null);
    }

    private static function rememberLastCheck(Report $report): void
    {
        self::cache()->forever(self::LAST_CHECK_KEY, [
            'checked_at' => CarbonImmutable::now()->toIso8601String(),
            'packages' => $report->packageCount(),
            'findings' => count($report->findings),
            'exploited' => count($report->exploited()),
            'complete' => $report->isComplete(),
        ]);
    }
}
