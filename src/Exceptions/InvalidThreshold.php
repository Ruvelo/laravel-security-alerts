<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Exceptions;

/**
 * An unknown value for --fail-on.
 */
class InvalidThreshold extends SecurityAlertsException
{
    public static function for(string $value): self
    {
        return new self("Unknown threshold \"{$value}\". Use exploited, critical, high, medium or any.");
    }
}
