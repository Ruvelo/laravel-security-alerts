<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Exceptions;

/**
 * A lockfile exists but isn't valid JSON in the expected shape.
 */
class LockfileUnreadable extends SecurityAlertsException
{
    public static function at(string $path, string $reason): self
    {
        return new self("Couldn't read {$path}: {$reason}.");
    }
}
