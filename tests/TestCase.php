<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests;

use Closure;
use Illuminate\Http\Client\Request;
use Illuminate\Notifications\SlackChannelServiceProvider;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase as Orchestra;
use Psr\Http\Client\ClientInterface;
use Ruvelo\SecurityAlerts\Notifier;
use Ruvelo\SecurityAlerts\Scanner;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\SecurityAlertsServiceProvider;
use Ruvelo\SecurityAlerts\Tests\Support\HttpFacadeClient;

abstract class TestCase extends Orchestra
{
    public const FIXTURES = __DIR__.'/fixtures';

    protected function setUp(): void
    {
        parent::setUp();

        // No test may reach Valtry, Packagist, OSV or CISA: the package's HTTP goes through the Http facade.
        Http::preventStrayRequests();
        $this->app->instance(ClientInterface::class, new HttpFacadeClient);

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
        // The Halyard fixtures are the public feeds' answers; the Valtry path has its own tests.
        $app['config']->set('security-alerts.source', 'public');
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
     * Valtry's Advisory API, faked: it serves what the Halyard fixtures say
     * (read through the public path first), signed with a key made for this
     * test, which the package is told to trust. $tamper can break the answer.
     * Switches the package to the Valtry source.
     *
     * @param  (Closure(string, string): array{0: string, 1: string})|null  $tamper  Gets the body and the signature header, returns both
     */
    protected function fakeValtry(?Closure $tamper = null, ?int $status = null): void
    {
        $this->fakeFeeds();

        $pair = sodium_crypto_sign_keypair();
        $keys = ['test-1' => base64_encode(sodium_crypto_sign_publickey($pair))];
        $data = [];
        foreach (SecurityAlerts::scan(fresh: true)->findings as $finding) {
            $data[$finding->ecosystem->value.':'.strtolower($finding->package)][] = [
                'id' => $finding->advisoryId, 'source' => 'test', 'title' => $finding->title, 'link' => $finding->link,
                'cve' => $finding->cve, 'aliases' => $finding->aliases, 'severity' => $finding->severity->value === 'not_rated' ? null : $finding->severity->value,
                'affected' => $finding->affectedVersions ?? $finding->installed, 'fixed_in' => [],
                'exploited' => $finding->isExploited(), 'kev' => $finding->exploited?->toArray(),
                'published_at' => $finding->reportedAt, 'updated_at' => null, 'attribution' => null,
            ];
        }

        $this->app->singleton(Scanner::class, fn () => new class($keys) extends Scanner
        {
            /** @param array<string, string> $keys */
            public function __construct(private array $keys) {}

            protected function valtryKeys(): array
            {
                return $this->keys;
            }
        });

        $this->feed('valtry.co.uk/*', function (Request $request) use ($pair, $data, $tamper, $status) {
            if ($status !== null) {
                return Http::response('', $status);
            }

            $advisories = [];
            foreach ($request['packages'] as $package) {
                $key = $package['ecosystem'].':'.$package['name'];
                $advisories[$key] = $data[$key] ?? [];
            }

            $body = (string) json_encode(['v' => 1, 'nonce' => $request['nonce'], 'advisories' => (object) $advisories, 'stale' => false, 'stale_ecosystems' => []], JSON_UNESCAPED_SLASHES);
            $header = 'ed25519='.base64_encode(sodium_crypto_sign_detached($body, sodium_crypto_sign_secretkey($pair))).'; kid=test-1';
            [$body, $header] = $tamper !== null ? $tamper($body, $header) : [$body, $header];

            return Http::response($body, 200, ['X-Valtry-Signature' => $header, 'Content-Type' => 'application/json']);
        });
        config()->set('security-alerts.source', 'valtry');
        config()->set('security-alerts.cache.advisories_ttl', 0);
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
