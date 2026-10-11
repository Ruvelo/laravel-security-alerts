<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Sources;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Pool;
use Illuminate\Http\Client\Response;
use Ruvelo\SecurityAlerts\Advisory;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAlerts\Package;
use Ruvelo\SecurityAlerts\Severity;
use Ruvelo\SecurityAlerts\Versions;
use Throwable;

/**
 * OSV.dev, Google's open vulnerability database, for npm packages. One
 * batch query says which advisories apply to which name and version, then
 * each advisory is fetched once (and cached until it changes).
 */
class Osv extends Source
{
    public const URL = 'https://api.osv.dev/v1';

    /** OSV's limit per batch query. */
    public const BATCH = 1000;

    /**
     * @param  list<Package>  $packages
     * @return list<array{0: Package, 1: Advisory}>
     *
     * @throws SourceUnavailable
     */
    public function advisories(array $packages, bool $fresh = false): array
    {
        $base = rtrim($this->url('osv', self::URL), '/');
        $matches = [];

        foreach (array_chunk($packages, self::BATCH) as $batch) {
            $results = $this->remember(
                'osv:'.sha1(implode(',', array_map(fn (Package $p): string => $p->name.'@'.$p->version, $batch))),
                'advisories_ttl', 3600, $fresh,
                fn (): array => $this->query($base, $batch),
            );

            foreach ($batch as $i => $package) {
                foreach ($results[$i] ?? [] as [$id, $modified]) {
                    $matches[] = [$package, $id, $modified];
                }
            }
        }

        $details = $this->details($base, array_values(array_unique(array_map(fn (array $m): string => $m[1].'|'.$m[2], $matches))), $fresh);

        $found = [];
        foreach ($matches as [$package, $id, $modified]) {
            $vuln = $details[$id.'|'.$modified] ?? null;
            if ($vuln !== null) {
                $found[] = [$package, self::advisory($vuln, $package)];
            }
        }

        return $found;
    }

    /**
     * @param  list<Package>  $batch
     * @return array<int, list<array{0: string, 1: string}>> Advisory ids and modified dates, by index in the batch
     */
    private function query(string $base, array $batch): array
    {
        $queries = array_map(fn (Package $p): array => [
            'package' => ['name' => $p->name, 'ecosystem' => 'npm'],
            'version' => $p->version,
        ], $batch);

        try {
            $response = $this->request()->post($base.'/querybatch', ['queries' => $queries]);
        } catch (ConnectionException $e) {
            throw SourceUnavailable::because('OSV', $e->getMessage(), $e);
        }

        $results = $response->json('results');

        if (! $response->successful() || ! is_array($results)) {
            throw SourceUnavailable::because('OSV', 'it answered HTTP '.$response->status());
        }

        $ids = [];
        foreach (array_values($results) as $i => $result) {
            foreach (is_array($result) && is_array($result['vulns'] ?? null) ? $result['vulns'] : [] as $vuln) {
                if (is_array($vuln) && is_string($vuln['id'] ?? null)) {
                    $ids[$i][] = [$vuln['id'], is_string($vuln['modified'] ?? null) ? $vuln['modified'] : ''];
                }
            }
        }

        return $ids;
    }

    /**
     * @param  list<string>  $keys  "id|modified"
     * @return array<string, array<string, mixed>>
     */
    private function details(string $base, array $keys, bool $fresh): array
    {
        $details = [];
        $missing = [];

        foreach ($keys as $key) {
            $cached = $fresh ? null : $this->cache()->get('security-alerts:osv-vuln:'.sha1($key));
            is_array($cached) ? $details[$key] = $cached : $missing[] = $key;
        }

        foreach (array_chunk($missing, 10) as $chunk) {
            try {
                $responses = $this->http->pool(fn (Pool $pool) => array_map(
                    fn (string $key) => $pool->as($key)->withUserAgent(self::USER_AGENT)->acceptJson()->timeout(max(1, (int) config('security-alerts.http.timeout', 15)))
                        ->get($base.'/vulns/'.rawurlencode(explode('|', $key)[0])),
                    $chunk,
                ));
            } catch (Throwable $e) {
                throw SourceUnavailable::because('OSV', $e->getMessage(), $e);
            }

            foreach ($chunk as $key) {
                $response = $responses[$key] ?? null;

                if (! $response instanceof Response || ! $response->successful() || ! is_array($vuln = $response->json())) {
                    throw SourceUnavailable::because('OSV', 'details for '.explode('|', $key)[0].' couldn\'t be fetched');
                }

                /** @var array<string, mixed> $vuln */
                $details[$key] = $vuln;
                // Keyed by the modified date, so a changed advisory is fetched again.
                $this->cache()->put('security-alerts:osv-vuln:'.sha1($key), $vuln, (int) config('security-alerts.cache.osv_details_ttl', 604800));
            }
        }

        return $details;
    }

    /**
     * @param  array<string, mixed>  $vuln  An OSV record
     */
    public static function advisory(array $vuln, Package $package): Advisory
    {
        $id = is_string($vuln['id'] ?? null) ? $vuln['id'] : 'unknown';
        $aliases = array_values(array_filter(is_array($vuln['aliases'] ?? null) ? $vuln['aliases'] : [], 'is_string'));
        $cve = array_values(array_filter([$id, ...$aliases], fn (string $alias): bool => preg_match('/^CVE-\d{4}-\d+$/i', $alias) === 1))[0] ?? null;
        $ghsa = array_values(array_filter([$id, ...$aliases], fn (string $alias): bool => str_starts_with($alias, 'GHSA-')))[0] ?? null;
        $severity = is_array($vuln['database_specific'] ?? null) && is_string($vuln['database_specific']['severity'] ?? null)
            ? $vuln['database_specific']['severity']
            : null;
        $summary = is_string($vuln['summary'] ?? null) && trim($vuln['summary']) !== '' ? trim($vuln['summary']) : null;

        return new Advisory(
            id: $id,
            ecosystem: Ecosystem::Npm,
            package: $package->name,
            title: $summary ?? $id,
            link: $ghsa !== null ? 'https://github.com/advisories/'.$ghsa : 'https://osv.dev/vulnerability/'.rawurlencode($id),
            cve: $cve !== null ? strtoupper($cve) : null,
            severity: Severity::parse($severity),
            fixedIn: Versions::fixedInOsv(is_array($vuln['affected'] ?? null) ? $vuln['affected'] : [], $package->name, $package->version),
            reportedAt: is_string($vuln['published'] ?? null) ? $vuln['published'] : null,
        );
    }
}
