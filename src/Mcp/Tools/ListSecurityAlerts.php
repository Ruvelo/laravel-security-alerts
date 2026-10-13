<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Mcp\Tools;

use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\SecurityAlerts;

#[IsReadOnly]
class ListSecurityAlerts extends Tool
{
    protected string $name = 'list_security_alerts';

    protected string $title = 'List security alerts';

    protected string $description = 'List known vulnerabilities in the packages this app has installed, as of the last check, exploited in the wild first. Each has the package, installed version, fixed_in version, severity, CVE, advisory link and, if exploited, when CISA listed it.';

    public function schema(JsonSchema $schema): array
    {
        return [
            'exploited_only' => $schema->boolean()->default(false)->description('Only vulnerabilities known to be exploited in the wild.'),
            'min_severity' => $schema->string()->enum(['critical', 'high', 'medium', 'low'])->description('Leave out less severe findings. Exploited ones are always included.'),
        ];
    }

    public function handle(Request $request): ResponseFactory
    {
        $data = $request->validate([
            'exploited_only' => ['nullable', 'boolean'],
            'min_severity' => ['nullable', 'string', 'in:critical,high,medium,low'],
        ]);

        $minimum = is_string($data['min_severity'] ?? null) ? Severity::from($data['min_severity']) : null;

        $alerts = SecurityAlerts::open()
            ->filter(fn (SecurityAlert $alert): bool => $alert->isExploited()
                || (! ($data['exploited_only'] ?? false) && ($minimum === null || $alert->severity->atLeast($minimum))))
            ->values();

        $lastCheck = SecurityAlerts::lastCheck();

        return Response::structured([
            'checked_at' => $lastCheck !== null ? $lastCheck['checked_at']->toIso8601String() : null,
            'count' => $alerts->count(),
            'exploited' => $alerts->filter(fn (SecurityAlert $alert): bool => $alert->isExploited())->count(),
            'alerts' => $alerts->map(fn (SecurityAlert $alert): array => $alert->present())->all(),
        ]);
    }
}
