<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Notifications;

/**
 * Sent after a check that found new vulnerabilities, or learned that known
 * ones are now exploited in the wild. Each alert is sent once.
 */
class VulnerabilitiesFound extends AlertsNotification
{
    public function subject(): string
    {
        $exploited = $this->exploited();

        if ($exploited->isNotEmpty()) {
            return $this->appName().': '.($exploited->count() === 1
                ? 'exploited vulnerability in '.$exploited->value('package').', patch today'
                : $exploited->count().' exploited vulnerabilities, patch today');
        }

        return $this->appName().': '.($this->alerts->count() === 1
            ? 'new vulnerability in '.$this->alerts->value('package')
            : $this->alerts->count().' new vulnerabilities in your dependencies');
    }

    protected function heading(): string
    {
        $exploited = $this->exploited()->count();

        return $exploited > 0
            ? self::plural($exploited, 'A vulnerability', 'vulnerabilities').' in '.$this->appName().' '.($exploited === 1 ? 'is' : 'are').' being exploited'
            : self::plural($this->alerts->count(), 'A new vulnerability', 'new vulnerabilities').' in '.$this->appName();
    }

    protected function intro(): string
    {
        $exploited = $this->exploited()->count();
        $others = $this->others()->count();

        $text = $exploited > 0
            ? 'Attackers are using '.($exploited === 1 ? 'this flaw' : 'these flaws').' in the wild, according to CISA\'s catalogue of known exploited vulnerabilities. Update today.'
            : 'A package '.$this->appName().' has installed has a published security advisory.';

        if ($exploited > 0 && $others > 0) {
            $text .= ' '.self::plural($others, 'One other new advisory', 'other new advisories').' below.';
        }

        return $text;
    }

    protected function footer(): string
    {
        return 'You\'ll hear about each of these once. Run php artisan security-alerts:check to see every open alert.';
    }
}
