<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Integrations\Pulse;

use Illuminate\Contracts\Support\Renderable;
use Illuminate\Support\Facades\View;
use Laravel\Pulse\Livewire\Card;
use Livewire\Attributes\Lazy;
use Ruvelo\SecurityAlerts\SecurityAlerts;

/**
 * Open security alerts on the Pulse dashboard, exploited first. Reads the
 * table the daily check fills; never calls a feed.
 *
 * In resources/views/vendor/pulse/dashboard.blade.php:
 *
 *     <livewire:security-alerts cols="4" rows="2" />
 */
#[Lazy]
class SecurityAlertsCard extends Card
{
    public function render(): Renderable
    {
        return View::make('security-alerts::pulse.card', [
            'alerts' => SecurityAlerts::open(),
            'lastCheck' => SecurityAlerts::lastCheck(),
        ]);
    }

    protected function css(): string
    {
        return __DIR__.'/../../../resources/css/pulse-card.css';
    }
}
