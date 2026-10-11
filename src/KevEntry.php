<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Carbon\CarbonImmutable;

/**
 * An entry in CISA's Known Exploited Vulnerabilities catalogue: proof that
 * attackers are using this flaw in the wild.
 */
final readonly class KevEntry
{
    public function __construct(
        public string $cve,
        public string $name,
        public CarbonImmutable $dateAdded,
        public ?CarbonImmutable $dueDate = null,
        public bool $ransomware = false,
    ) {}

    /**
     * @param  array<string, mixed>  $data  An item of the catalogue's "vulnerabilities" list
     */
    public static function fromCatalogue(array $data): ?self
    {
        $cve = $data['cveID'] ?? null;
        $added = $data['dateAdded'] ?? null;

        if (! is_string($cve) || ! is_string($added) || ($dateAdded = self::date($added)) === null) {
            return null;
        }

        return new self(
            cve: strtoupper(trim($cve)),
            name: is_string($data['vulnerabilityName'] ?? null) ? trim($data['vulnerabilityName']) : $cve,
            dateAdded: $dateAdded,
            dueDate: is_string($data['dueDate'] ?? null) ? self::date($data['dueDate']) : null,
            ransomware: strtolower((string) (is_string($data['knownRansomwareCampaignUse'] ?? null) ? $data['knownRansomwareCampaignUse'] : '')) === 'known',
        );
    }

    /**
     * @return array{cve: string, name: string, date_added: string, due_date: string|null, ransomware: bool}
     */
    public function toArray(): array
    {
        return [
            'cve' => $this->cve,
            'name' => $this->name,
            'date_added' => $this->dateAdded->toDateString(),
            'due_date' => $this->dueDate?->toDateString(),
            'ransomware' => $this->ransomware,
        ];
    }

    /**
     * @param  array<string, mixed>  $data  What toArray() gave
     */
    public static function fromArray(array $data): ?self
    {
        return self::fromCatalogue([
            'cveID' => $data['cve'] ?? null,
            'vulnerabilityName' => $data['name'] ?? null,
            'dateAdded' => $data['date_added'] ?? null,
            'dueDate' => $data['due_date'] ?? null,
            'knownRansomwareCampaignUse' => ($data['ransomware'] ?? false) === true ? 'Known' : 'Unknown',
        ]);
    }

    private static function date(string $value): ?CarbonImmutable
    {
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) !== 1) {
            return null;
        }

        return CarbonImmutable::createFromFormat('!Y-m-d', $value, 'UTC') ?: null;
    }
}
