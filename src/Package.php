<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

/**
 * One installed package, as a lockfile records it.
 */
final readonly class Package
{
    public function __construct(
        public Ecosystem $ecosystem,
        public string $name,
        public string $version,
        public bool $dev = false,
    ) {}
}
