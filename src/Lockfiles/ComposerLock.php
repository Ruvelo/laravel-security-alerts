<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Lockfiles;

use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Exceptions\LockfileUnreadable;
use Ruvelo\SecurityAlerts\Package;

/**
 * Reads the exact versions Composer installed from composer.lock.
 */
final class ComposerLock
{
    /**
     * @return list<Package>|null Null when there is no composer.lock
     *
     * @throws LockfileUnreadable
     */
    public static function read(string $path, bool $includeDev = false): ?array
    {
        $data = Lockfile::json($path);

        if ($data === null) {
            return null;
        }

        if (! is_array($data['packages'] ?? null)) {
            throw LockfileUnreadable::at($path, 'it has no "packages" list');
        }

        $packages = self::packages($data['packages'], false);

        if ($includeDev && is_array($data['packages-dev'] ?? null)) {
            $packages = [...$packages, ...self::packages($data['packages-dev'], true)];
        }

        return $packages;
    }

    /**
     * @param  array<mixed>  $entries
     * @return list<Package>
     */
    private static function packages(array $entries, bool $dev): array
    {
        $packages = [];

        foreach ($entries as $entry) {
            if (! is_array($entry) || ! is_string($entry['name'] ?? null) || ! is_string($entry['version'] ?? null)) {
                continue;
            }

            // "v3.6.2" and "3.6.2" are the same release; show it the way advisories do.
            $version = (string) preg_replace('/^v(?=\d)/i', '', $entry['version']);

            $packages[] = new Package(Ecosystem::Composer, strtolower($entry['name']), $version, $dev);
        }

        return $packages;
    }
}
