<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Ruvelo\SecurityAlerts\Database\Factories\SecurityAlertFactory;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Finding;
use Ruvelo\SecurityAlerts\KevEntry;
use Ruvelo\SecurityAlerts\Severity;

/**
 * A finding the package has seen, remembered so the same alert is never
 * sent twice. Open while the vulnerable version is installed; resolved
 * once a check no longer finds it.
 *
 * Written only by SecurityAlerts::check().
 *
 * @property int $id
 * @property string $key
 * @property Ecosystem $ecosystem
 * @property string $package
 * @property string $version
 * @property string $advisory_id
 * @property string $title
 * @property Severity $severity
 * @property string|null $link
 * @property string|null $cve
 * @property string|null $fixed_in
 * @property string|null $affected_versions
 * @property bool $dev
 * @property CarbonImmutable|null $exploited_at
 * @property CarbonImmutable|null $kev_due_date
 * @property bool $ransomware
 * @property CarbonImmutable $first_seen_at
 * @property CarbonImmutable $last_seen_at
 * @property CarbonImmutable|null $notified_at
 * @property CarbonImmutable|null $exploited_notified_at
 * @property CarbonImmutable|null $resolved_at
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 */
class SecurityAlert extends Model
{
    /** @use HasFactory<SecurityAlertFactory> */
    use HasFactory;

    protected $guarded = ['id'];

    public function getTable(): string
    {
        $table = config('security-alerts.table', 'security_alerts');

        return is_string($table) && $table !== '' ? $table : 'security_alerts';
    }

    protected function casts(): array
    {
        return [
            'ecosystem' => Ecosystem::class,
            'severity' => Severity::class,
            'dev' => 'boolean',
            'ransomware' => 'boolean',
            'exploited_at' => 'immutable_date',
            'kev_due_date' => 'immutable_date',
            'first_seen_at' => 'immutable_datetime',
            'last_seen_at' => 'immutable_datetime',
            'notified_at' => 'immutable_datetime',
            'exploited_notified_at' => 'immutable_datetime',
            'resolved_at' => 'immutable_datetime',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }

    protected static function newFactory(): SecurityAlertFactory
    {
        return SecurityAlertFactory::new();
    }

    /**
     * Still installed, as of the last check.
     *
     * @param  Builder<self>  $query
     */
    public function scopeOpen(Builder $query): void
    {
        $query->whereNull('resolved_at');
    }

    /**
     * @param  Builder<self>  $query
     */
    public function scopeExploited(Builder $query): void
    {
        $query->whereNotNull('exploited_at');
    }

    /**
     * Exploited first, then by severity, then by package.
     *
     * @param  Builder<self>  $query
     */
    public function scopeWorstFirst(Builder $query): void
    {
        $query->orderByRaw('case when exploited_at is null then 1 else 0 end')
            ->orderByRaw("case severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'unknown' then 3 else 4 end")
            ->orderByDesc('exploited_at')
            ->orderBy('package')
            ->orderBy('advisory_id');
    }

    public function isOpen(): bool
    {
        return $this->resolved_at === null;
    }

    public function isExploited(): bool
    {
        return $this->exploited_at !== null;
    }

    /**
     * The finding as a check would report it today.
     */
    public function toFinding(): Finding
    {
        return new Finding(
            ecosystem: $this->ecosystem,
            package: $this->package,
            version: $this->version,
            advisoryId: $this->advisory_id,
            title: $this->title,
            severity: $this->severity,
            link: $this->link,
            cve: $this->cve,
            fixedIn: $this->fixed_in,
            affectedVersions: $this->affected_versions,
            exploited: $this->exploited_at !== null
                ? new KevEntry((string) $this->cve, $this->title, $this->exploited_at, $this->kev_due_date, (bool) $this->ransomware)
                : null,
            dev: $this->dev,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function present(): array
    {
        return [
            ...$this->toFinding()->toArray(),
            'first_seen_at' => $this->first_seen_at->toIso8601String(),
            'last_seen_at' => $this->last_seen_at->toIso8601String(),
            'resolved_at' => $this->resolved_at?->toIso8601String(),
        ];
    }
}
