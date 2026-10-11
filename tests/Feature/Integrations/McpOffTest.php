<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature\Integrations;

use Laravel\Mcp\Server\McpServiceProvider;
use Laravel\Mcp\Server\Registrar;
use Ruvelo\SecurityAlerts\SecurityAlertsServiceProvider;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class McpOffTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [McpServiceProvider::class, SecurityAlertsServiceProvider::class];
    }

    public function test_nothing_is_registered_by_default(): void
    {
        $this->assertSame([], $this->app->make(Registrar::class)->servers());
        $this->assertFalse(app('router')->has('security-alerts.mcp'));
    }

    public function test_enabled_without_a_path_is_local_only(): void
    {
        config()->set('security-alerts.mcp.enabled', true);
        (new SecurityAlertsServiceProvider($this->app))->boot();

        $this->assertArrayHasKey('security-alerts', $this->app->make(Registrar::class)->servers());
        $this->assertFalse(app('router')->has('security-alerts.mcp'));
    }
}
