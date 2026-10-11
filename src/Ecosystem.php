<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

/**
 * Where a package comes from, and so which lockfile and advisory source cover it.
 */
enum Ecosystem: string
{
    case Composer = 'composer';
    case Npm = 'npm';

    public function label(): string
    {
        return match ($this) {
            self::Composer => 'Composer',
            self::Npm => 'npm',
        };
    }
}
