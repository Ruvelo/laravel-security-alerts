<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Integrations\Health;

use Illuminate\Support\Str;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Spatie\Health\Checks\Check;
use Spatie\Health\Checks\Result;

/**
 * A spatie/laravel-health check: fails while an installed package has a
 * vulnerability exploited in the wild, warns on high and critical ones,
 * and warns when the daily check hasn't run lately. Reads the table the
 * check fills; never calls a feed.
 *
 *     Health::checks([SecurityAlertsCheck::new()]);
 */
class SecurityAlertsCheck extends Check
{
    protected Severity $warnFrom = Severity::High;

    protected ?Severity $failFrom = null;

    protected int $staleAfterHours = 48;

    /**
     * Warn from this severity up (high by default). Exploited always fails.
     */
    public function warnFrom(Severity|string $severity): self
    {
        $this->warnFrom = $severity instanceof Severity ? $severity : Severity::parse($severity);

        return $this;
    }

    /**
     * Also fail, not just warn, from this severity up.
     */
    public function failFrom(Severity|string $severity): self
    {
        $this->failFrom = $severity instanceof Severity ? $severity : Severity::parse($severity);

        return $this;
    }

    /**
     * How long since the last check before warning that it isn't running.
     */
    public function staleAfterHours(int $hours): self
    {
        $this->staleAfterHours = $hours;

        return $this;
    }

    public function run(): Result
    {
        $alerts = SecurityAlerts::open();
        $exploited = $alerts->filter(fn (SecurityAlert $alert): bool => $alert->isExploited());
        $failing = $this->failFrom === null ? collect() : $alerts->filter(fn (SecurityAlert $alert): bool => $alert->severity->atLeast($this->failFrom));
        $warning = $alerts->filter(fn (SecurityAlert $alert): bool => $alert->severity->atLeast($this->warnFrom));
        $lastCheck = SecurityAlerts::lastCheck();

        $result = Result::make()
            ->meta([
                'open' => $alerts->count(),
                'exploited' => $exploited->count(),
                'checked_at' => $lastCheck !== null ? $lastCheck['checked_at']->toIso8601String() : null,
            ])
            ->shortSummary($exploited->isNotEmpty() ? $exploited->count().' exploited' : Str::plural('open alert', $alerts->count(), true));

        if ($exploited->isNotEmpty()) {
            return $result->failed('Exploited in the wild: '.$this->names($exploited->all()).'. Update today.');
        }

        if ($failing->isNotEmpty()) {
            return $result->failed('Vulnerable: '.$this->names($failing->all()).'.');
        }

        if ($warning->isNotEmpty()) {
            return $result->warning('Vulnerable: '.$this->names($warning->all()).'.');
        }

        if ($lastCheck === null || $lastCheck['checked_at']->diffInHours(now(), true) > $this->staleAfterHours) {
            return $result->warning('Packages haven\'t been checked for vulnerabilities in the last '.$this->staleAfterHours.' hours. Is the scheduler running?');
        }

        return $result->ok();
    }

    /**
     * @param  array<int, SecurityAlert>  $alerts
     */
    private function names(array $alerts): string
    {
        return implode(', ', array_unique(array_map(fn (SecurityAlert $alert): string => $alert->package.' '.$alert->version, $alerts)));
    }
}
