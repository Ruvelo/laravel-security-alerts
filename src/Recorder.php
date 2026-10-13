<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Carbon\CarbonImmutable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAlerts\Events\VulnerabilityExploited;
use Ruvelo\SecurityAlerts\Events\VulnerabilityFound;
use Ruvelo\SecurityAlerts\Events\VulnerabilityResolved;
use Ruvelo\SecurityAlerts\Exceptions\NotInstalled;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;

/**
 * The one place alerts are written: compares a report with what was seen
 * before, saves the difference and fires the events.
 *
 * @internal Use SecurityAlerts::check()
 */
class Recorder
{
    /**
     * @return array{found: Collection<int, SecurityAlert>, exploited: Collection<int, SecurityAlert>, resolved: Collection<int, SecurityAlert>}
     *
     * @throws NotInstalled
     */
    public function record(Report $report): array
    {
        $model = new SecurityAlert;

        if (! Schema::connection($model->getConnectionName())->hasTable($model->getTable())) {
            throw NotInstalled::table($model->getTable());
        }

        $now = CarbonImmutable::now();

        /** @var Collection<int, SecurityAlert> $found */
        $found = new Collection;
        /** @var Collection<int, SecurityAlert> $exploited */
        $exploited = new Collection;
        /** @var Collection<int, SecurityAlert> $resolved */
        $resolved = new Collection;

        DB::connection($model->getConnectionName())->transaction(function () use ($report, $now, $found, $exploited, $resolved): void {
            // What the table says is known: the open rows, by the key each was first stored under.
            $open = SecurityAlert::query()->open()->get()->keyBy('key');
            $known = $open->map(fn (SecurityAlert $alert): bool => $alert->isExploited())->all();
            $lastSeen = $open->map(fn (SecurityAlert $alert): array => $alert->toFinding()->toArray())->all();

            // The core decides what is news, whichever source named the advisory this time.
            $reconciler = new Reconciler;
            $changes = $reconciler->reconcile($known, $report, $lastSeen);
            $next = $reconciler->next($known, $report, [], $lastSeen);
            $seen = $reconciler->lastSeen($lastSeen, $report, $next);

            $current = [];
            foreach ($report->findings as $finding) {
                $current[$finding->key()] = $finding;
            }
            $isNew = array_flip(array_map(fn (Finding $finding): string => $finding->key(), $changes->new));

            foreach (array_keys($next) as $key) {
                $finding = $current[$seen[$key]['key'] ?? ''] ?? null;

                if ($finding === null) {
                    continue; // not vouched for this time: left as it was
                }

                // Back after a fix (a downgrade, a revert) is a row to reopen.
                /** @var SecurityAlert $alert */
                $alert = $open->get($key) ?? SecurityAlert::query()->where('key', $key)->first() ?? new SecurityAlert(['key' => $key, 'first_seen_at' => $now]);
                $new = isset($isNew[$finding->key()]);
                $wasExploited = $alert->isExploited();

                $alert->fill([
                    'ecosystem' => $finding->ecosystem,
                    'package' => $finding->package,
                    'version' => $finding->installed,
                    'advisory_id' => $finding->advisoryId,
                    'title' => $finding->title,
                    'severity' => $finding->severity,
                    'link' => $finding->link,
                    'cve' => $finding->cve,
                    'fixed_in' => $finding->fixedIn,
                    'affected_versions' => $finding->affectedVersions,
                    'dev' => $finding->isDev,
                    'last_seen_at' => $now,
                ]);

                if ($new) {
                    $alert->fill(['resolved_at' => null, 'notified_at' => null, 'first_seen_at' => $now]);
                }

                // CISA rarely withdraws an entry; once exploited, it stays so.
                if ($finding->exploited !== null && ! $wasExploited) {
                    $alert->fill([
                        'exploited_at' => $finding->exploited->dateAdded,
                        'kev_due_date' => $finding->exploited->dueDate,
                        'ransomware' => $finding->exploited->ransomware,
                        'exploited_notified_at' => null,
                    ]);
                }

                $alert->save();

                if ($new) {
                    $found->push($alert);
                }
                if ($finding->exploited !== null && ! $wasExploited) {
                    $exploited->push($alert);
                }
            }

            foreach ($open as $key => $alert) {
                if (in_array($key, $changes->resolved, true)) {
                    $alert->forceFill(['resolved_at' => $now])->save();
                    $resolved->push($alert);
                } elseif (! array_key_exists($key, $next)) {
                    // Two rows for one vulnerability collapsed into the first: close the other quietly.
                    $alert->forceFill(['resolved_at' => $now])->save();
                }
            }
        });

        $found->each(fn (SecurityAlert $alert) => VulnerabilityFound::dispatch($alert));
        $exploited->each(fn (SecurityAlert $alert) => VulnerabilityExploited::dispatch($alert));
        $resolved->each(fn (SecurityAlert $alert) => VulnerabilityResolved::dispatch($alert));

        return ['found' => $found, 'exploited' => $exploited, 'resolved' => $resolved];
    }
}
