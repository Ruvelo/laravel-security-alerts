<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests;

use Illuminate\Http\Client\Request;
use Illuminate\Notifications\SlackChannelServiceProvider;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase as Orchestra;
use Ruvelo\SecurityAlerts\Notifier;
use Ruvelo\SecurityAlerts\SecurityAlertsServiceProvider;

abstract class TestCase extends Orchestra
{
    public const FIXTURES = __DIR__.'/fixtures';

    protected function setUp(): void
    {
        parent::setUp();

        // No test may reach Packagist, OSV or CISA.
        Http::preventStrayRequests();

        // Retries wait between tries; tests don't.
        Sleep::fake();
    }

    protected function tearDown(): void
    {
        Notifier::using(null);

        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [SlackChannelServiceProvider::class, SecurityAlertsServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('s', 32)));
        $app['config']->set('app.name', 'Halyard');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('security-alerts.composer.lockfile', self::FIXTURES.'/composer.lock');
        $app['config']->set('security-alerts.npm.lockfile', self::FIXTURES.'/package-lock.json');
        $app['config']->set('security-alerts.notify.mail', []);
        $app['config']->set('security-alerts.notify.slack', null);
    }

    /** @var array<string, mixed> URL pattern => response, first match wins */
    protected array $feeds = [];

    /**
     * Answers every feed from tests/fixtures: real responses recorded for
     * the Halyard lockfiles. Pass replacements to change one feed.
     *
     * @param  array<string, mixed>  $overrides  URL pattern => response
     */
    protected function fakeFeeds(array $overrides = []): void
    {
        $this->feeds = $overrides + [
            'packagist.org/api/security-advisories/*' => fn () => Http::response(self::fixture('packagist.json')),
            'api.osv.dev/v1/querybatch' => fn (Request $request) => Http::response(self::osvBatch($request)),
            'api.osv.dev/v1/vulns/*' => fn (Request $request) => Http::response(self::fixture('osv/'.basename($request->url()).'.json')),
            'www.cisa.gov/*' => fn () => Http::response(self::fixture('kev.json')),
        ];

        Http::fake(function (Request $request, array $options) {
            foreach ($this->feeds as $pattern => $response) {
                if (Str::is(Str::start($pattern, '*'), $request->url())) {
                    return is_callable($response) ? $response($request, $options) : $response;
                }
            }

            return null;
        });
    }

    /**
     * Changes one feed's answer from now on.
     */
    protected function feed(string $pattern, mixed $response): void
    {
        $this->feeds = [$pattern => $response] + $this->feeds;
    }

    /**
     * @return array<string, mixed>
     */
    public static function fixture(string $name): array
    {
        $data = json_decode((string) file_get_contents(self::FIXTURES.'/'.$name), true, 512, JSON_THROW_ON_ERROR);

        return is_array($data) ? $data : [];
    }

    /**
     * The recorded batch answer, re-aligned to the queries actually sent, so
     * tests that change the lockfile still get the right advisories.
     *
     * @return array{results: list<array<string, mixed>>}
     */
    public static function osvBatch(Request $request): array
    {
        $recorded = self::fixture('osv-querybatch.json')['results'];
        $lock = self::fixture('package-lock.json')['packages'];
        $byPackage = [];
        $i = 0;
        foreach ($lock as $path => $entry) {
            if ($path === '') {
                continue;
            }
            $byPackage[substr($path, strlen('node_modules/')).'@'.$entry['version']] = $recorded[$i++] ?? [];
        }

        return ['results' => array_map(
            fn (array $query): array => $byPackage[$query['package']['name'].'@'.$query['version']] ?? (object) [],
            $request['queries'],
        )];
    }

    /**
     * Writes a lockfile to a temporary path and points the config at it.
     *
     * @param  array<string, mixed>  $data
     */
    protected function lockfile(string $ecosystem, array $data): string
    {
        $path = tempnam(sys_get_temp_dir(), 'lock');
        file_put_contents($path, json_encode($data));
        config()->set("security-alerts.{$ecosystem}.lockfile", $path);

        return $path;
    }
}
