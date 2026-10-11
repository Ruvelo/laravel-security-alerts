<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use JsonSerializable;

/**
 * An advisory that applies to a package this app has installed.
 */
final readonly class Finding implements JsonSerializable
{
    public function __construct(
        public Ecosystem $ecosystem,
        public string $package,
        public string $version,
        public string $advisoryId,
        public string $title,
        public Severity $severity = Severity::Unknown,
        public ?string $link = null,
        public ?string $cve = null,
        public ?string $fixedIn = null,
        public ?string $affectedVersions = null,
        public ?string $reportedAt = null,
        public ?KevEntry $exploited = null,
        public bool $dev = false,
    ) {}

    public static function make(Package $package, Advisory $advisory, ?string $fixedIn, ?KevEntry $exploited): self
    {
        return new self(
            ecosystem: $package->ecosystem,
            package: $package->name,
            version: $package->version,
            advisoryId: $advisory->id,
            title: $advisory->title,
            severity: $advisory->severity,
            link: $advisory->link,
            cve: $advisory->cve,
            fixedIn: $fixedIn,
            affectedVersions: $advisory->affectedVersions,
            reportedAt: $advisory->reportedAt,
            exploited: $exploited,
            dev: $package->dev,
        );
    }

    /**
     * What identifies this finding across checks: the same advisory on the
     * same package is the same finding, whichever affected version is installed.
     */
    public function key(): string
    {
        return $this->ecosystem->value.':'.$this->package.':'.$this->advisoryId;
    }

    public function isExploited(): bool
    {
        return $this->exploited !== null;
    }

    /**
     * Sorts findings worst first: exploited in the wild, then by severity,
     * then the most recently exploited, then by package name.
     */
    public static function compare(self $a, self $b): int
    {
        return [$b->isExploited(), $b->severity->rank(), $b->exploited?->dateAdded->getTimestamp() ?? 0, $a->package, $a->advisoryId]
            <=> [$a->isExploited(), $a->severity->rank(), $a->exploited?->dateAdded->getTimestamp() ?? 0, $b->package, $b->advisoryId];
    }

    /**
     * @return array{key: string, ecosystem: string, package: string, version: string, dev: bool, advisory_id: string, title: string, severity: string, link: string|null, cve: string|null, fixed_in: string|null, affected_versions: string|null, reported_at: string|null, exploited: bool, kev: array{cve: string, name: string, date_added: string, due_date: string|null, ransomware: bool}|null}
     */
    public function toArray(): array
    {
        return [
            'key' => $this->key(),
            'ecosystem' => $this->ecosystem->value,
            'package' => $this->package,
            'version' => $this->version,
            'dev' => $this->dev,
            'advisory_id' => $this->advisoryId,
            'title' => $this->title,
            'severity' => $this->severity->value,
            'link' => $this->link,
            'cve' => $this->cve,
            'fixed_in' => $this->fixedIn,
            'affected_versions' => $this->affectedVersions,
            'reported_at' => $this->reportedAt,
            'exploited' => $this->isExploited(),
            'kev' => $this->exploited?->toArray(),
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
