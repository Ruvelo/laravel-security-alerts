<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Notifications;

/**
 * Everything still open, once a week, even if nothing changed. Off by
 * default: turn it on with SECURITY_ALERTS_DIGEST=true.
 */
class WeeklyDigest extends AlertsNotification
{
    public function subject(): string
    {
        return $this->appName().': '.($this->alerts->isEmpty()
            ? 'no known vulnerabilities this week'
            : $this->alerts->count().' open '.($this->alerts->count() === 1 ? 'vulnerability' : 'vulnerabilities').' this week');
    }

    protected function heading(): string
    {
        return $this->alerts->isEmpty()
            ? 'No known vulnerabilities'
            : self::plural($this->alerts->count(), 'One open vulnerability', 'open vulnerabilities');
    }

    protected function intro(): string
    {
        if ($this->alerts->isEmpty()) {
            return 'The last check found no published advisory for the packages '.$this->appName().' has installed.';
        }

        $exploited = $this->exploited()->count();

        return 'Still installed in '.$this->appName().' as of the last check'
            .($exploited > 0 ? ', '.self::plural($exploited, 'one of them', 'of them').' exploited in the wild' : '').'.';
    }
}
