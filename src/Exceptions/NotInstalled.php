<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Exceptions;

/**
 * The security_alerts table is missing, so findings can't be remembered.
 */
class NotInstalled extends SecurityAlertsException
{
    public static function table(string $table): self
    {
        return new self("The {$table} table doesn't exist yet. Run: php artisan migrate");
    }
}
