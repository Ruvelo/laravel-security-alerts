<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Illuminate\Support\Facades\Cache;
use Psr\Http\Client\ClientInterface;
use Psr\SimpleCache\CacheInterface;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Packages\NpmLockReader;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner as Core;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\OsvSource;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;

/**
 * Wires ruvelo/security-advisories to this app: the lockfiles from the
 * config, Guzzle for HTTP (or a PSR-18 client bound to
 * Psr\Http\Client\ClientInterface), the Laravel cache. Everything else,
 * reading, asking, matching, is the core's. Changes nothing: see
 * SecurityAlerts::check() for remembering and notifying.
 */
class Scanner
{
    public const USER_AGENT = 'ruvelo/laravel-security-alerts (+https://github.com/Ruvelo/laravel-security-alerts)';

    public function scan(bool $fresh = false): Report
    {
        return $this->core()->scan($fresh);
    }

    private function core(): Core
    {
        $factory = new HttpFactory;
        $http = new JsonClient($this->client((float) config('security-alerts.http.timeout', 15)), $factory, $factory, self::USER_AGENT, max(1, (int) config('security-alerts.http.tries', 2)));
        $cache = new ResponseCache($this->cache(), new Ttls(
            (int) config('security-alerts.cache.advisories_ttl', 3600),
            (int) config('security-alerts.cache.kev_ttl', 21600),
            (int) config('security-alerts.cache.osv_details_ttl', 604800),
        ));

        $readers = [new ComposerLockReader($this->path('composer'), (bool) config('security-alerts.composer.include_dev', false))];
        $public = [new PackagistAdvisorySource($http, $cache, $this->url('packagist', PackagistAdvisorySource::URL))];

        // A missing package-lock.json is normal: not every app has one.
        if (config('security-alerts.npm.enabled', true)) {
            $readers[] = new NpmLockReader($this->path('npm'), (bool) config('security-alerts.npm.include_dev', true));
            $public[] = new OsvSource($http, $cache, $this->url('osv', OsvSource::URL));
        }

        $source = config('security-alerts.source');
        $viaValtry = Core::source(is_string($source) ? $source : null) === Core::SOURCE_VALTRY;

        $advisories = $viaValtry
            ? [new FallbackAdvisorySource(
                new ValtryAdvisorySource(
                    new JsonClient($this->client(ValtryAdvisorySource::DEADLINE), $factory, $factory, self::USER_AGENT, 1),
                    $cache,
                    $this->url('valtry', ValtryAdvisorySource::URL),
                    $this->valtryKeys(),
                ),
                $public,
            )]
            : $public;

        $kev = config('security-alerts.sources.kev.enabled', true) ? new KevCatalogue($http, $cache, $this->url('kev', KevCatalogue::URL)) : null;

        return new Core($readers, $advisories, $kev);
    }

    /**
     * The keys Valtry's answers are verified against: null for the ones the
     * core pins. Only tests, which sign their own answers, say otherwise.
     *
     * @return array<string, string>|null
     */
    protected function valtryKeys(): ?array
    {
        return null;
    }

    /**
     * Bind a PSR-18 client to Psr\Http\Client\ClientInterface to use your own
     * (a proxy, say); otherwise a Guzzle client with the configured timeout.
     */
    private function client(float $timeout): ClientInterface
    {
        return app()->bound(ClientInterface::class)
            ? app(ClientInterface::class)
            : new Client(['timeout' => max(1.0, $timeout), 'connect_timeout' => min(5.0, max(1.0, $timeout)), 'http_errors' => false]);
    }

    private function cache(): CacheInterface
    {
        $store = config('security-alerts.cache.store');

        return Cache::store(is_string($store) && $store !== '' ? $store : null);
    }

    private function path(string $ecosystem): string
    {
        $path = config("security-alerts.{$ecosystem}.lockfile");
        $default = $ecosystem === 'composer' ? 'composer.lock' : 'package-lock.json';

        return is_string($path) && $path !== '' ? $path : base_path($default);
    }

    private function url(string $source, string $default): string
    {
        $url = config($source === 'valtry' ? 'security-alerts.valtry_url' : "security-alerts.sources.{$source}.url");

        return is_string($url) && $url !== '' ? $url : $default;
    }
}
