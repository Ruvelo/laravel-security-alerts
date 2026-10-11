<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature\Integrations;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\Fluent\AssertableJson;
use Laravel\Mcp\Server\McpServiceProvider;
use Laravel\Mcp\Server\Registrar;
use Ruvelo\SecurityAlerts\Mcp\SecurityAlertsServer;
use Ruvelo\SecurityAlerts\Mcp\Tools\ListSecurityAlerts;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\SecurityAlertsServiceProvider;
use Ruvelo\SecurityAlerts\Severity;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class McpTest extends TestCase
{
    use RefreshDatabase;

    protected function getPackageProviders($app): array
    {
        return [McpServiceProvider::class, SecurityAlertsServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('security-alerts.mcp.enabled', true);
        $app['config']->set('security-alerts.mcp.path', 'mcp/security-alerts');
        $app['config']->set('security-alerts.mcp.middleware', ['auth']);
    }

    public function test_the_tool_is_offered_locally_and_over_http(): void
    {
        SecurityAlertsServer::tools()->assertRegistered([ListSecurityAlerts::class]);
        $this->assertArrayHasKey('security-alerts', $this->app->make(Registrar::class)->servers());
        $this->assertTrue(app('router')->has('security-alerts.mcp'));
        $this->postJson('/mcp/security-alerts', [])->assertUnauthorized();
    }

    public function test_open_alerts_exploited_first(): void
    {
        SecurityAlert::factory()->severity(Severity::Low)->forPackage('laravel/framework', '12.61.0')->create();
        SecurityAlert::factory()->exploited('2026-03-20', '2026-04-03')->forPackage('livewire/livewire', '3.6.2')->create(['fixed_in' => '3.6.4']);
        SecurityAlert::factory()->resolved()->create();

        SecurityAlertsServer::tool(ListSecurityAlerts::class)
            ->assertOk()
            ->assertHasNoErrors()
            ->assertStructuredContent(fn (AssertableJson $json) => $json
                ->where('count', 2)
                ->where('exploited', 1)
                ->where('checked_at', null)
                ->has('alerts', 2)
                ->has('alerts.0', fn (AssertableJson $alert) => $alert
                    ->where('package', 'livewire/livewire')
                    ->where('version', '3.6.2')
                    ->where('fixed_in', '3.6.4')
                    ->where('exploited', true)
                    ->where('kev.date_added', '2026-03-20')
                    ->where('kev.due_date', '2026-04-03')
                    ->where('resolved_at', null)
                    ->etc())
                ->where('alerts.1.package', 'laravel/framework'));
    }

    public function test_filters(): void
    {
        SecurityAlert::factory()->severity(Severity::Low)->create();
        SecurityAlert::factory()->severity(Severity::High)->create();
        SecurityAlert::factory()->exploited()->severity(Severity::Low)->create();

        SecurityAlertsServer::tool(ListSecurityAlerts::class, ['exploited_only' => true])
            ->assertStructuredContent(fn (AssertableJson $json) => $json->where('count', 1)->etc());
        SecurityAlertsServer::tool(ListSecurityAlerts::class, ['min_severity' => 'high'])
            ->assertStructuredContent(fn (AssertableJson $json) => $json->where('count', 2)->etc());
        SecurityAlertsServer::tool(ListSecurityAlerts::class, ['min_severity' => 'severe'])
            ->assertHasErrors(['The selected min severity is invalid.']);
    }
}
