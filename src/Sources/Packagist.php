<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Sources;

use Illuminate\Http\Client\ConnectionException;
use Ruvelo\SecurityAlerts\Advisory;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAlerts\Severity;

/**
 * Packagist's security advisories API: the one `composer audit` reads,
 * fed by the GitHub Advisory Database and FriendsOfPHP. Only package
 * names are sent.
 */
class Packagist extends Source
{
    public const URL = 'https://packagist.org/api/security-advisories/';

    /** Names per request. The API takes many in one POST; this keeps bodies modest. */
    public const BATCH = 200;

    /**
     * @param  list<string>  $names
     * @return array<string, list<Advisory>> Keyed by package name; packages without advisories are left out
     *
     * @throws SourceUnavailable
     */
    public function advisories(array $names, bool $fresh = false): array
    {
        $names = array_values(array_unique(array_map('strtolower', $names)));
        sort($names);

        $found = [];

        foreach (array_chunk($names, self::BATCH) as $batch) {
            $raw = $this->remember('packagist:'.sha1(implode(',', $batch)), 'advisories_ttl', 3600, $fresh, fn (): array => $this->fetch($batch));

            foreach ($raw as $name => $list) {
                foreach ($list as $item) {
                    if (($advisory = self::advisory((string) $name, $item)) !== null) {
                        $found[$advisory->package][] = $advisory;
                    }
                }
            }
        }

        return $found;
    }

    /**
     * @param  list<string>  $names
     * @return array<string, list<array<string, mixed>>>
     */
    private function fetch(array $names): array
    {
        try {
            $response = $this->request()->asForm()->post($this->url('packagist', self::URL), ['packages' => $names]);
        } catch (ConnectionException $e) {
            throw SourceUnavailable::because('Packagist', $e->getMessage(), $e);
        }

        $advisories = $response->json('advisories');

        if (! $response->successful() || ! is_array($advisories)) {
            throw SourceUnavailable::because('Packagist', 'it answered HTTP '.$response->status());
        }

        $clean = [];
        foreach ($advisories as $name => $list) {
            if (is_string($name) && is_array($list)) {
                $clean[$name] = array_values(array_filter($list, 'is_array'));
            }
        }

        /** @var array<string, list<array<string, mixed>>> $clean */
        return $clean;
    }

    /**
     * @param  array<string, mixed>  $item
     */
    public static function advisory(string $package, mixed $item): ?Advisory
    {
        if (! is_array($item)) {
            return null;
        }

        $id = self::string($item['advisoryId'] ?? null);
        $constraint = self::string($item['affectedVersions'] ?? null);

        if ($id === null || $constraint === null) {
            return null;
        }

        $cve = self::string($item['cve'] ?? null);
        $cve = $cve !== null && preg_match('/^CVE-\d{4}-\d+$/i', $cve) === 1 ? strtoupper($cve) : null;
        $title = self::string($item['title'] ?? null) ?? $id;

        // Some titles repeat the CVE ("CVE-2026-48736: IpUtils..."); it's shown on its own.
        if ($cve !== null && stripos($title, $cve.':') === 0) {
            $title = ltrim(substr($title, strlen($cve) + 1)) ?: $title;
        }

        return new Advisory(
            id: $id,
            ecosystem: Ecosystem::Composer,
            package: strtolower(self::string($item['packageName'] ?? null) ?? $package),
            title: $title,
            link: self::string($item['link'] ?? null),
            cve: $cve,
            severity: Severity::parse(self::string($item['severity'] ?? null)),
            affectedVersions: $constraint,
            reportedAt: self::string($item['reportedAt'] ?? null),
        );
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
