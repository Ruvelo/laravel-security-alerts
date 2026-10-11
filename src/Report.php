<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Carbon\CarbonImmutable;
use JsonSerializable;

/**
 * The result of a scan: every finding, worst first, and what was checked.
 */
final readonly class Report implements JsonSerializable
{
    /** @var list<Finding> */
    public array $findings;

    /**
     * @param  list<Finding>  $findings
     * @param  array<string, int>  $packages  Packages checked, by ecosystem value
     * @param  list<Ecosystem>  $checked  Ecosystems whose advisories were fetched in full; only these can mark alerts as fixed
     * @param  list<string>  $problems  What couldn't be checked, in plain words
     * @param  bool  $kevChecked  Whether the exploited-in-the-wild catalogue was read
     */
    public function __construct(
        array $findings,
        public array $packages = [],
        public array $checked = [],
        public array $problems = [],
        public bool $kevChecked = true,
        public ?CarbonImmutable $checkedAt = null,
    ) {
        usort($findings, Finding::compare(...));
        $this->findings = $findings;
    }

    public function isClean(): bool
    {
        return $this->findings === [];
    }

    public function isComplete(): bool
    {
        return $this->problems === [];
    }

    /**
     * @return list<Finding>
     */
    public function exploited(): array
    {
        return array_values(array_filter($this->findings, fn (Finding $finding): bool => $finding->isExploited()));
    }

    /**
     * @return list<Finding>
     */
    public function failing(Threshold $threshold): array
    {
        return array_values(array_filter($this->findings, fn (Finding $finding): bool => $threshold->isMetBy($finding)));
    }

    public function packageCount(?Ecosystem $ecosystem = null): int
    {
        return $ecosystem === null ? array_sum($this->packages) : ($this->packages[$ecosystem->value] ?? 0);
    }

    /**
     * Counts for a one-line summary: exploited first, then each severity
     * among the rest. Zero counts are left out.
     *
     * @return array<string, int>
     */
    public function counts(): array
    {
        $counts = ['exploited' => 0] + array_fill_keys(array_map(fn (Severity $s): string => $s->value, Severity::cases()), 0);

        foreach ($this->findings as $finding) {
            $counts[$finding->isExploited() ? 'exploited' : $finding->severity->value]++;
        }

        return array_filter($counts);
    }

    /**
     * @return list<string> Affected package names, worst first, each once
     */
    public function affectedPackages(): array
    {
        return array_values(array_unique(array_map(fn (Finding $finding): string => $finding->package, $this->findings)));
    }

    /**
     * @return array{checked_at: string|null, clean: bool, complete: bool, packages: array<string, int>, counts: array<string, int>, problems: list<string>, findings: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'checked_at' => $this->checkedAt?->toIso8601String(),
            'clean' => $this->isClean(),
            'complete' => $this->isComplete(),
            'packages' => $this->packages,
            'counts' => $this->counts(),
            'problems' => $this->problems,
            'findings' => array_map(fn (Finding $finding): array => $finding->toArray(), $this->findings),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
