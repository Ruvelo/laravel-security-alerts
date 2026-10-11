<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Sources;

use Closure;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Cache;

/**
 * What the feeds share: one configured HTTP client and the cache.
 *
 * @internal
 */
abstract class Source
{
    public const USER_AGENT = 'ruvelo/laravel-security-alerts (+https://github.com/Ruvelo/laravel-security-alerts)';

    public function __construct(protected Factory $http) {}

    protected function request(): PendingRequest
    {
        return $this->http
            ->withUserAgent(self::USER_AGENT)
            ->acceptJson()
            ->timeout(max(1, (int) config('security-alerts.http.timeout', 15)))
            ->connectTimeout(5)
            ->retry(max(1, (int) config('security-alerts.http.tries', 2)), 500, throw: false);
    }

    protected function cache(): Repository
    {
        $store = config('security-alerts.cache.store');

        return Cache::store(is_string($store) && $store !== '' ? $store : null);
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $fetch
     * @return T
     */
    protected function remember(string $key, string $ttlKey, int $defaultTtl, bool $fresh, Closure $fetch): mixed
    {
        $key = 'security-alerts:'.$key;
        $ttl = (int) config("security-alerts.cache.{$ttlKey}", $defaultTtl);

        if (! $fresh && $ttl > 0 && ($cached = $this->cache()->get($key)) !== null) {
            return $cached;
        }

        $value = $fetch();

        if ($ttl > 0) {
            $this->cache()->put($key, $value, $ttl);
        }

        return $value;
    }

    protected function url(string $source, string $default): string
    {
        $url = config("security-alerts.sources.{$source}.url");

        return is_string($url) && $url !== '' ? $url : $default;
    }
}
