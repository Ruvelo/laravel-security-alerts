<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature\Integrations;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Pulse\PulseServiceProvider;
use Livewire\Livewire;
use Livewire\LivewireServiceProvider;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Integrations\Pulse\SecurityAlertsCard;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\SecurityAlertsServiceProvider;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class PulseCardTest extends TestCase
{
    use RefreshDatabase;

    protected function getPackageProviders($app): array
    {
        return [LivewireServiceProvider::class, PulseServiceProvider::class, SecurityAlertsServiceProvider::class];
    }

    public function test_the_card_is_registered_with_livewire(): void
    {
        $this->assertSame(SecurityAlertsCard::class, app('livewire')->new('security-alerts')::class);
    }

    public function test_open_alerts_exploited_first(): void
    {
        $this->fakeFeeds();
        $this->checkedAt('2026-10-12 07:00:00');
        $this->travelTo('2026-10-12 09:00:00');
        SecurityAlert::factory()->severity(Severity::Medium)->forPackage('guzzlehttp/guzzle', '7.15.1')->create(['title' => 'Cookie scope']);
        SecurityAlert::factory()->exploited('2026-03-20')->forPackage('livewire/livewire', '3.6.2')->create(['title' => 'Remote command execution', 'fixed_in' => '3.6.4']);
        SecurityAlert::factory()->resolved()->forPackage('old/fixed')->create();

        Livewire::withoutLazyLoading()->test(SecurityAlertsCard::class)
            ->assertSee('Security alerts')
            ->assertSee('checked 2 hours ago')
            ->assertSeeInOrder(['livewire/livewire 3.6.2', 'Remote command execution', '3.6.4', 'Exploited', 'guzzlehttp/guzzle 7.15.1', 'Medium'])
            ->assertDontSee('old/fixed');
    }

    public function test_an_empty_card(): void
    {
        Livewire::withoutLazyLoading()->test(SecurityAlertsCard::class)
            ->assertSee('not checked yet')
            ->assertDontSee('Fixed in');
    }

    public function test_titles_are_escaped(): void
    {
        SecurityAlert::factory()->create(['title' => '<img src=x onerror=alert(1)>']);

        Livewire::withoutLazyLoading()->test(SecurityAlertsCard::class)
            ->assertDontSeeHtml('<img src=x')
            ->assertSeeHtml('&lt;img src=x onerror=alert(1)&gt;');
    }

    private function checkedAt(string $at): void
    {
        $this->travelTo($at);
        config()->set('security-alerts.npm.enabled', false);
        $this->lockfile('composer', ['packages' => []]);
        SecurityAlerts::check(notify: false);
    }
}
