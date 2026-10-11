<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Composer\Semver\Comparator;
use Composer\Semver\Semver;
use Composer\Semver\VersionParser;
use Throwable;

/**
 * Version arithmetic for advisories, on top of composer/semver: whether an
 * installed version is affected, and which release fixes it.
 */
final class Versions
{
    /**
     * Whether a constraint like ">=3.0.0,<3.6.4|<2.5.8" covers the version.
     * Versions or constraints Composer can't parse (a "dev-main" branch) are
     * never matched rather than guessed.
     */
    public static function affects(string $version, string $constraint): bool
    {
        if (! self::comparable($version)) {
            return false;
        }

        try {
            return Semver::satisfies($version, $constraint);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * The first release above the installed version that the constraint no
     * longer covers, read from its "<x.y.z" bounds. When the advisory only
     * names the last affected release ("<=2.10.1"), it's ">2.10.1". Null when
     * it can't be told (">=1.0", "=2.4.9").
     */
    public static function fixedIn(string $version, string $constraint): ?string
    {
        if (! self::affects($version, $constraint)) {
            return null;
        }

        $groups = array_values(array_filter(array_map('trim', preg_split('/\s*\|\|?\s*/', $constraint) ?: [])));
        $candidate = $version;

        // Ranges are sometimes split by minor version (">=8.1,<8.2|>=8.2,<8.3"):
        // walk up until the bound is a release that isn't affected.
        for ($step = 0; $step < 50; $step++) {
            $bound = null;

            foreach ($groups as $group) {
                if (! self::affects($candidate, $group)) {
                    continue;
                }

                if (preg_match('/<\s*(?!=)v?(\d[^,\s|]*)/', $group, $m) === 1) {
                    $bound = $m[1];
                } elseif (preg_match('/<=\s*v?(\d[^,\s|]*)/', $group, $m) === 1 && self::comparable($m[1])) {
                    // Only the last affected release is known: the fix is whatever came after it.
                    return '>'.$m[1];
                }
                break;
            }

            if ($bound === null || ! self::comparable($bound)) {
                return null;
            }

            if (! self::affects($bound, $constraint)) {
                return $bound;
            }

            $candidate = $bound;
        }

        return null;
    }

    /**
     * The fixing version from OSV's "affected" list: the "fixed" event of
     * the range that contains the installed version.
     *
     * @param  array<mixed>  $affected
     */
    public static function fixedInOsv(array $affected, string $package, string $version): ?string
    {
        if (! self::comparable($version)) {
            return null;
        }

        foreach ($affected as $entry) {
            if (! is_array($entry) || ! is_array($entry['package'] ?? null) || ($entry['package']['name'] ?? null) !== $package || ! is_array($entry['ranges'] ?? null)) {
                continue;
            }

            foreach ($entry['ranges'] as $range) {
                if (! is_array($range) || ! in_array($range['type'] ?? null, ['SEMVER', 'ECOSYSTEM'], true) || ! is_array($range['events'] ?? null)) {
                    continue;
                }

                $introduced = null;

                foreach ($range['events'] as $event) {
                    if (! is_array($event)) {
                        continue;
                    }

                    if (is_string($event['introduced'] ?? null)) {
                        $introduced = $event['introduced'];
                    } elseif (is_string($event['fixed'] ?? null) && $introduced !== null) {
                        if (self::between($version, $introduced, $event['fixed'])) {
                            return $event['fixed'];
                        }
                        $introduced = null;
                    }
                }
            }
        }

        return null;
    }

    public static function comparable(string $version): bool
    {
        try {
            (new VersionParser)->normalize($version);
        } catch (Throwable) {
            return false;
        }

        return ! str_starts_with(strtolower($version), 'dev-') && ! str_ends_with(strtolower($version), '-dev');
    }

    private static function between(string $version, string $introduced, string $fixed): bool
    {
        if (! self::comparable($fixed) || ($introduced !== '0' && ! self::comparable($introduced))) {
            return false;
        }

        return ($introduced === '0' || Comparator::greaterThanOrEqualTo($version, $introduced))
            && Comparator::lessThan($version, $fixed);
    }
}
