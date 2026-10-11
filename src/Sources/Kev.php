<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Sources;

use Illuminate\Http\Client\ConnectionException;
use Ruvelo\SecurityAlerts\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAlerts\KevEntry;

/**
 * CISA's Known Exploited Vulnerabilities catalogue: CVEs attackers are
 * using in the wild right now. Nothing is sent; the whole list is
 * downloaded and cached.
 */
class Kev extends Source
{
    public const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    /**
     * @param  list<string>  $cves
     * @return array<string, KevEntry> The CVEs that are in the catalogue, keyed by CVE
     *
     * @throws SourceUnavailable
     */
    public function lookup(array $cves, bool $fresh = false): array
    {
        if ($cves === []) {
            return [];
        }

        $catalogue = $this->catalogue($fresh);
        $found = [];

        foreach ($cves as $cve) {
            $cve = strtoupper($cve);
            if (isset($catalogue[$cve]) && ($entry = KevEntry::fromArray($catalogue[$cve])) !== null) {
                $found[$cve] = $entry;
            }
        }

        return $found;
    }

    /**
     * The catalogue, trimmed to what the alerts use, keyed by CVE.
     *
     * @return array<string, array<string, mixed>>
     */
    public function catalogue(bool $fresh = false): array
    {
        return $this->remember('kev', 'kev_ttl', 21600, $fresh, function (): array {
            try {
                $response = $this->request()->get($this->url('kev', self::URL));
            } catch (ConnectionException $e) {
                throw SourceUnavailable::because('CISA KEV', $e->getMessage(), $e);
            }

            $items = $response->json('vulnerabilities');

            if (! $response->successful() || ! is_array($items)) {
                throw SourceUnavailable::because('CISA KEV', 'it answered HTTP '.$response->status());
            }

            $catalogue = [];
            foreach ($items as $item) {
                if (is_array($item) && ($entry = KevEntry::fromCatalogue($item)) !== null) {
                    $catalogue[$entry->cve] = $entry->toArray();
                }
            }

            return $catalogue;
        });
    }
}
