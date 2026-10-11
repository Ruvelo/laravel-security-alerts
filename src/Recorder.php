<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Carbon\CarbonImmutable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
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
            $keys = array_map(fn (Finding $finding): string => $finding->key(), $report->findings);
            $known = SecurityAlert::query()->whereIn('key', $keys)->get()->keyBy('key');

            foreach ($report->findings as $finding) {
                /** @var SecurityAlert|null $alert */
                $alert = $known->get($finding->key());
                $isNew = $alert === null || ! $alert->isOpen();
                $wasExploited = $alert?->isExploited() ?? false;

                $alert ??= new SecurityAlert(['key' => $finding->key(), 'first_seen_at' => $now]);

                $alert->fill([
                    'ecosystem' => $finding->ecosystem,
                    'package' => $finding->package,
                    'version' => $finding->version,
                    'advisory_id' => $finding->advisoryId,
                    'title' => $finding->title,
                    'severity' => $finding->severity,
                    'link' => $finding->link,
                    'cve' => $finding->cve,
                    'fixed_in' => $finding->fixedIn,
                    'affected_versions' => $finding->affectedVersions,
                    'dev' => $finding->dev,
                    'last_seen_at' => $now,
                ]);

                if ($isNew) {
                    // Back after a fix (a downgrade, a revert): a new alert again.
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

                if ($isNew) {
                    $found->push($alert);
                }
                if ($finding->exploited !== null && ! $wasExploited) {
                    $exploited->push($alert);
                }
            }

            // Only ecosystems checked in full can say a finding is gone.
            $checked = array_map(fn (Ecosystem $e): string => $e->value, $report->checked);

            if ($checked !== []) {
                SecurityAlert::query()->open()
                    ->whereIn('ecosystem', $checked)
                    ->whereNotIn('key', $keys)
                    ->get()
                    ->each(function (SecurityAlert $alert) use ($now, $resolved): void {
                        $alert->forceFill(['resolved_at' => $now])->save();
                        $resolved->push($alert);
                    });
            }
        });

        $found->each(fn (SecurityAlert $alert) => VulnerabilityFound::dispatch($alert));
        $exploited->each(fn (SecurityAlert $alert) => VulnerabilityExploited::dispatch($alert));
        $resolved->each(fn (SecurityAlert $alert) => VulnerabilityResolved::dispatch($alert));

        return ['found' => $found, 'exploited' => $exploited, 'resolved' => $resolved];
    }
}
