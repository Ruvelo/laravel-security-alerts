<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

/**
 * A published security advisory for one package, from Packagist or OSV,
 * in the same shape whichever source it came from.
 */
final readonly class Advisory
{
    /**
     * @param  string|null  $affectedVersions  A Composer constraint (Packagist); null when the source matched the version itself (OSV)
     * @param  string|null  $fixedIn  The version that fixes it, when the source says so directly
     */
    public function __construct(
        public string $id,
        public Ecosystem $ecosystem,
        public string $package,
        public string $title,
        public ?string $link = null,
        public ?string $cve = null,
        public Severity $severity = Severity::Unknown,
        public ?string $affectedVersions = null,
        public ?string $fixedIn = null,
        public ?string $reportedAt = null,
    ) {}
}
