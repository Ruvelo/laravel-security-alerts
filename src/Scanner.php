<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Carbon\CarbonImmutable;
use Ruvelo\SecurityAlerts\Exceptions\LockfileUnreadable;
use Ruvelo\SecurityAlerts\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAlerts\Lockfiles\ComposerLock;
use Ruvelo\SecurityAlerts\Lockfiles\NpmLock;
use Ruvelo\SecurityAlerts\Sources\Kev;
use Ruvelo\SecurityAlerts\Sources\Osv;
use Ruvelo\SecurityAlerts\Sources\Packagist;

/**
 * Reads the lockfiles, asks the advisory sources about the installed
 * versions and marks what's exploited in the wild. Changes nothing: see
 * SecurityAlerts::check() for remembering and notifying.
 */
class Scanner
{
    public function __construct(
        private Packagist $packagist,
        private Osv $osv,
        private Kev $kev,
    ) {}

    public function scan(bool $fresh = false): Report
    {
        $findings = [];
        $packages = [];
        $checked = [];
        $problems = [];
        $pending = [];

        // Composer, through Packagist.
        try {
            $installed = ComposerLock::read($this->path('composer'), (bool) config('security-alerts.composer.include_dev', false));

            if ($installed === null) {
                $problems[] = 'No composer.lock at '.$this->path('composer').', so PHP packages weren\'t checked.';
            } else {
                $packages[Ecosystem::Composer->value] = count($installed);
                $byName = $this->packagist->advisories(array_map(fn (Package $p): string => $p->name, $installed), $fresh);

                foreach ($installed as $package) {
                    foreach ($byName[$package->name] ?? [] as $advisory) {
                        if (Versions::affects($package->version, (string) $advisory->affectedVersions)) {
                            $pending[] = [$package, $advisory, Versions::fixedIn($package->version, (string) $advisory->affectedVersions)];
                        }
                    }
                }
                $checked[] = Ecosystem::Composer;
            }
        } catch (LockfileUnreadable|SourceUnavailable $e) {
            $problems[] = $e->getMessage().' PHP packages weren\'t checked.';
        }

        // npm, through OSV. A missing package-lock.json is normal: not every app has one.
        if (config('security-alerts.npm.enabled', true)) {
            try {
                $installed = NpmLock::read($this->path('npm'), (bool) config('security-alerts.npm.include_dev', true));

                if ($installed !== null) {
                    $packages[Ecosystem::Npm->value] = count($installed);
                    foreach ($this->osv->advisories($installed, $fresh) as [$package, $advisory]) {
                        $pending[] = [$package, $advisory, $advisory->fixedIn];
                    }
                    $checked[] = Ecosystem::Npm;
                }
            } catch (LockfileUnreadable|SourceUnavailable $e) {
                $problems[] = $e->getMessage().' npm packages weren\'t checked.';
            }
        }

        // Exploited in the wild, through CISA KEV.
        $exploited = [];
        $kevChecked = false;
        if (config('security-alerts.sources.kev.enabled', true)) {
            try {
                $cves = array_values(array_unique(array_filter(array_map(fn (array $p): ?string => $p[1]->cve, $pending))));
                $exploited = $this->kev->lookup($cves, $fresh);
                $kevChecked = true;
            } catch (SourceUnavailable $e) {
                $problems[] = $e->getMessage().' Findings aren\'t marked as exploited this time.';
            }
        }

        $seen = [];
        foreach ($pending as [$package, $advisory, $fixedIn]) {
            $finding = Finding::make($package, $advisory, $fixedIn, $advisory->cve !== null ? ($exploited[$advisory->cve] ?? null) : null);

            // The same advisory can match two installed copies (npm): report it once.
            if (! isset($seen[$finding->key()])) {
                $seen[$finding->key()] = true;
                $findings[] = $finding;
            }
        }

        return new Report($findings, $packages, $checked, $problems, $kevChecked, CarbonImmutable::now());
    }

    private function path(string $ecosystem): string
    {
        $path = config("security-alerts.{$ecosystem}.lockfile");
        $default = $ecosystem === 'composer' ? 'composer.lock' : 'package-lock.json';

        return is_string($path) && $path !== '' ? $path : base_path($default);
    }
}
