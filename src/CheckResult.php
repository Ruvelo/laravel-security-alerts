<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Illuminate\Support\Collection;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;

/**
 * What a check changed: the scan's report, plus the alerts it opened,
 * escalated and closed, and how many were sent.
 */
final readonly class CheckResult
{
    /**
     * @param  Collection<int, SecurityAlert>  $found  New since the last check
     * @param  Collection<int, SecurityAlert>  $exploited  Newly known to be exploited in the wild (new or not)
     * @param  Collection<int, SecurityAlert>  $resolved  No longer installed
     * @param  int  $notified  Alerts included in the notification sent by this check
     */
    public function __construct(
        public Report $report,
        public Collection $found,
        public Collection $exploited,
        public Collection $resolved,
        public int $notified = 0,
    ) {}

    public function changed(): bool
    {
        return $this->found->isNotEmpty() || $this->exploited->isNotEmpty() || $this->resolved->isNotEmpty();
    }
}
