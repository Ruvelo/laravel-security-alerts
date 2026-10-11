<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Mcp;

use Composer\InstalledVersions;
use Laravel\Mcp\Server;
use Ruvelo\SecurityAlerts\Mcp\Tools\ListSecurityAlerts;

/**
 * Open security alerts for AI agents, read-only.
 *
 * Registered for you when `security-alerts.mcp.enabled` is true. To mount it
 * yourself, in routes/ai.php: `Mcp::local('security-alerts', SecurityAlertsServer::class);`
 */
class SecurityAlertsServer extends Server
{
    protected array $tools = [
        ListSecurityAlerts::class,
    ];

    protected function boot(): void
    {
        $this->name = 'Security alerts';
        $this->version = InstalledVersions::isInstalled('ruvelo/laravel-security-alerts')
            ? (InstalledVersions::getPrettyVersion('ruvelo/laravel-security-alerts') ?? $this->version)
            : $this->version;

        $this->instructions = 'Known vulnerabilities in the Composer and npm packages this Laravel app has installed, as of the last daily check. '
            .'Use list_security_alerts before upgrading dependencies or when asked about security. '
            .'Fix exploited ones first: attackers are using them in the wild. Suggest updating to fixed_in or later; '
            .'after changing composer.lock or package-lock.json, run `php artisan security-alerts:check` to confirm.';
    }
}
