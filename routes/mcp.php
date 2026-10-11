<?php

declare(strict_types=1);

use Laravel\Mcp\Facades\Mcp;
use Ruvelo\SecurityAlerts\Mcp\SecurityAlertsServer;

// The MCP endpoint for AI agents. Off by default: set SECURITY_ALERTS_MCP=true,
// security-alerts.mcp.path, and install laravel/mcp.
Mcp::web((string) config('security-alerts.mcp.path'), SecurityAlertsServer::class)
    ->name('security-alerts.mcp')
    ->middleware(config('security-alerts.mcp.middleware', ['auth:sanctum']));
