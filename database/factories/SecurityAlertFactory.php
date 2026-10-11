<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\Severity;

/**
 * Open, already-notified alerts for host-app tests: a Pulse dashboard, a
 * health check, a page that lists them.
 *
 * @extends Factory<SecurityAlert>
 */
class SecurityAlertFactory extends Factory
{
    protected $model = SecurityAlert::class;

    public function definition(): array
    {
        $package = 'acme/'.Str::lower(Str::random(8));
        $advisory = 'PKSA-'.Str::lower(Str::random(4)).'-'.Str::lower(Str::random(4)).'-'.Str::lower(Str::random(4));

        return [
            'key' => 'composer:'.$package.':'.$advisory,
            'ecosystem' => Ecosystem::Composer,
            'package' => $package,
            'version' => '1.2.0',
            'advisory_id' => $advisory,
            'title' => 'Cross-site scripting in the admin panel',
            'severity' => Severity::Medium,
            'link' => 'https://github.com/advisories/GHSA-'.Str::lower(Str::random(4)).'-'.Str::lower(Str::random(4)).'-'.Str::lower(Str::random(4)),
            'cve' => 'CVE-2026-'.random_int(10000, 99999),
            'fixed_in' => '1.2.1',
            'affected_versions' => '<1.2.1',
            'dev' => false,
            'ransomware' => false,
            'first_seen_at' => now(),
            'last_seen_at' => now(),
            'notified_at' => now(),
        ];
    }

    public function severity(Severity $severity): static
    {
        return $this->state(['severity' => $severity]);
    }

    /**
     * In CISA's catalogue of vulnerabilities exploited in the wild.
     */
    public function exploited(string $added = '2026-09-30', ?string $due = '2026-10-21'): static
    {
        return $this->state([
            'severity' => Severity::Critical,
            'exploited_at' => $added,
            'kev_due_date' => $due,
            'exploited_notified_at' => now(),
        ]);
    }

    public function resolved(): static
    {
        return $this->state(['resolved_at' => now()]);
    }

    /**
     * Not yet sent to anyone: the next check will notify about it.
     */
    public function pending(): static
    {
        return $this->state(['notified_at' => null, 'exploited_notified_at' => null]);
    }

    public function forPackage(string $package, string $version = '1.2.0', Ecosystem $ecosystem = Ecosystem::Composer): static
    {
        return $this->state(fn (array $attributes) => [
            'ecosystem' => $ecosystem,
            'package' => $package,
            'version' => $version,
            'key' => $ecosystem->value.':'.$package.':'.$attributes['advisory_id'],
        ]);
    }
}
