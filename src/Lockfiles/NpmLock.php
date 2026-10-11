<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Lockfiles;

use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Exceptions\LockfileUnreadable;
use Ruvelo\SecurityAlerts\Package;

/**
 * Reads the exact versions npm installed from package-lock.json, lockfile
 * versions 1 to 3, including packages nested under other packages.
 */
final class NpmLock
{
    /**
     * @return list<Package>|null Null when there is no package-lock.json
     *
     * @throws LockfileUnreadable
     */
    public static function read(string $path, bool $includeDev = true): ?array
    {
        $data = Lockfile::json($path);

        if ($data === null) {
            return null;
        }

        if (is_array($data['packages'] ?? null)) {
            $found = self::fromPackages($data['packages']);
        } elseif (is_array($data['dependencies'] ?? null)) {
            $found = self::fromDependencies($data['dependencies']);
        } else {
            throw LockfileUnreadable::at($path, 'it has neither "packages" nor "dependencies"');
        }

        // The same version can sit in several places in node_modules: check it once,
        // and count it as a production dependency if any copy is one.
        $unique = [];
        foreach ($found as $package) {
            $key = $package->name.'@'.$package->version;
            if (! isset($unique[$key]) || ! $package->dev) {
                $unique[$key] = $package;
            }
        }

        return array_values(array_filter($unique, fn (Package $package): bool => $includeDev || ! $package->dev));
    }

    /**
     * Lockfile v2 and v3: a flat map of install paths.
     *
     * @param  array<mixed>  $entries
     * @return list<Package>
     */
    private static function fromPackages(array $entries): array
    {
        $packages = [];

        foreach ($entries as $path => $entry) {
            if (! is_string($path) || $path === '' || ! is_array($entry) || ($entry['link'] ?? false) === true) {
                continue;
            }

            // Only what's under node_modules: other paths are the app's own workspaces.
            $fromPath = self::nameFromPath($path);
            $name = is_string($entry['name'] ?? null) ? $entry['name'] : $fromPath;
            $version = $entry['version'] ?? null;

            if ($fromPath === null || $name === null || ! is_string($version) || $version === '') {
                continue;
            }

            $packages[] = new Package(Ecosystem::Npm, $name, $version, ($entry['dev'] ?? false) === true);
        }

        return $packages;
    }

    /**
     * Lockfile v1: dependencies nested in dependencies.
     *
     * @param  array<mixed>  $entries
     * @return list<Package>
     */
    private static function fromDependencies(array $entries): array
    {
        $packages = [];

        foreach ($entries as $name => $entry) {
            if (! is_string($name) || ! is_array($entry)) {
                continue;
            }

            if (is_string($entry['version'] ?? null) && $entry['version'] !== '' && ! str_contains($entry['version'], ':')) {
                $packages[] = new Package(Ecosystem::Npm, $name, $entry['version'], ($entry['dev'] ?? false) === true);
            }

            if (is_array($entry['dependencies'] ?? null)) {
                $packages = [...$packages, ...self::fromDependencies($entry['dependencies'])];
            }
        }

        return $packages;
    }

    /**
     * "node_modules/a/node_modules/@scope/b" is "@scope/b".
     */
    private static function nameFromPath(string $path): ?string
    {
        $at = strrpos($path, 'node_modules/');

        return $at === false ? null : substr($path, $at + strlen('node_modules/'));
    }
}
