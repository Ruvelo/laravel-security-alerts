<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Finding;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\Severity;
use Ruvelo\SecurityAlerts\Sources\Packagist;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class ScanTest extends TestCase
{
    public function test_it_finds_the_halyard_vulnerabilities_exploited_first(): void
    {
        $this->fakeFeeds();

        $report = SecurityAlerts::scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame(['composer' => 67, 'npm' => 38], $report->packages);
        $this->assertSame([Ecosystem::Composer, Ecosystem::Npm], $report->checked);
        $this->assertCount(13, $report->findings);
        $this->assertSame(['exploited' => 1, 'critical' => 2, 'high' => 4, 'medium' => 5, 'low' => 1], $report->counts());

        $first = $report->findings[0];
        $this->assertSame('livewire/livewire', $first->package);
        $this->assertSame('3.6.2', $first->version);
        $this->assertSame('3.6.4', $first->fixedIn);
        $this->assertSame('CVE-2025-54068', $first->cve);
        $this->assertSame(Severity::Critical, $first->severity);
        $this->assertTrue($first->isExploited());
        $this->assertSame('2026-03-20', $first->exploited?->dateAdded->toDateString());
        $this->assertSame('2026-04-03', $first->exploited?->dueDate?->toDateString());
        $this->assertSame('https://github.com/advisories/GHSA-29cq-5w36-x7w3', $first->link);

        $this->assertSame(
            ['livewire/livewire', 'form-data', 'predis/predis', 'form-data', 'guzzlehttp/guzzle', 'maatwebsite/excel', 'vite', 'guzzlehttp/guzzle', 'laravel/framework', 'livewire/livewire', 'symfony/http-foundation', 'vite', 'laravel/framework'],
            array_map(fn (Finding $f) => $f->package, $report->findings),
        );

        $formData = $report->findings[1];
        $this->assertSame(Ecosystem::Npm, $formData->ecosystem);
        $this->assertSame('4.0.4', $formData->fixedIn);
        $this->assertTrue($formData->dev);
        $this->assertFalse($formData->isExploited());
    }

    public function test_only_package_names_and_versions_are_sent(): void
    {
        $this->fakeFeeds();

        SecurityAlerts::scan();

        Http::assertSent(function (Request $request): bool {
            if (! str_contains($request->url(), 'packagist.org')) {
                return false;
            }
            $this->assertSame('POST', $request->method());
            $this->assertSame(['packages'], array_keys($request->data()));
            $this->assertContains('livewire/livewire', $request['packages']);
            $this->assertNotContains('phpunit/phpunit', $request['packages'], 'Dev packages are left out by default');
            $this->assertStringStartsWith('ruvelo/laravel-security-alerts', $request->header('User-Agent')[0]);

            return true;
        });

        Http::assertSent(function (Request $request): bool {
            if (! str_ends_with($request->url(), '/querybatch')) {
                return false;
            }
            foreach ($request['queries'] as $query) {
                $this->assertSame(['package', 'version'], array_keys($query));
                $this->assertSame(['name', 'ecosystem'], array_keys($query['package']));
            }

            return true;
        });

        Http::assertSent(fn (Request $request) => $request->method() === 'GET' && str_contains($request->url(), 'cisa.gov'));
        Http::assertSentCount(1 + 1 + 4 + 1);
    }

    public function test_composer_dev_packages_when_configured(): void
    {
        config()->set('security-alerts.composer.include_dev', true);
        $this->fakeFeeds();

        $report = SecurityAlerts::scan();

        $phpunit = array_values(array_filter($report->findings, fn (Finding $f) => $f->package === 'phpunit/phpunit'));
        $this->assertCount(1, $phpunit);
        $this->assertTrue($phpunit[0]->dev);
        $this->assertSame('11.5.50', $phpunit[0]->fixedIn);
    }

    public function test_npm_can_be_left_out(): void
    {
        config()->set('security-alerts.npm.enabled', false);
        $this->fakeFeeds();

        $report = SecurityAlerts::scan();

        $this->assertSame(['composer' => 67], $report->packages);
        $this->assertCount(9, $report->findings);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'osv.dev'));
    }

    public function test_npm_production_only(): void
    {
        config()->set('security-alerts.npm.include_dev', false);
        $this->fakeFeeds();

        $report = SecurityAlerts::scan();

        $this->assertSame(3, $report->packageCount(Ecosystem::Npm));
        $this->assertSame([], array_filter($report->findings, fn (Finding $f) => $f->ecosystem === Ecosystem::Npm));
    }

    public function test_no_package_lock_is_normal(): void
    {
        config()->set('security-alerts.npm.lockfile', '/nowhere/package-lock.json');
        $this->fakeFeeds();

        $report = SecurityAlerts::scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame([Ecosystem::Composer], $report->checked);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'osv.dev'));
    }

    public function test_no_composer_lock_is_reported(): void
    {
        config()->set('security-alerts.composer.lockfile', '/nowhere/composer.lock');
        $this->fakeFeeds();

        $report = SecurityAlerts::scan();

        $this->assertFalse($report->isComplete());
        $this->assertSame(['No composer.lock at /nowhere/composer.lock, so PHP packages weren\'t checked.'], $report->problems);
        $this->assertSame([Ecosystem::Npm], $report->checked);
        $this->assertCount(4, $report->findings);
    }

    public function test_a_broken_lockfile_is_reported(): void
    {
        $this->lockfile('composer', ['nope' => true]);
        $this->fakeFeeds();

        $report = SecurityAlerts::scan();

        $this->assertStringContainsString('it has no "packages" list. PHP packages weren\'t checked.', $report->problems[0]);
    }

    public function test_packagist_down(): void
    {
        $this->fakeFeeds(['packagist.org/*' => Http::response('Bad gateway', 502)]);

        $report = SecurityAlerts::scan();

        $this->assertFalse($report->isComplete());
        $this->assertSame(['Packagist couldn\'t be reached: it answered HTTP 502. PHP packages weren\'t checked.'], $report->problems);
        $this->assertSame([Ecosystem::Npm], $report->checked);
        $this->assertSame(['composer' => 67, 'npm' => 38], $report->packages);
    }

    public function test_packagist_unreachable(): void
    {
        $this->fakeFeeds(['packagist.org/*' => Http::failedConnection()]);

        $report = SecurityAlerts::scan();

        $this->assertStringStartsWith('Packagist couldn\'t be reached', $report->problems[0]);
    }

    public function test_a_failed_request_is_tried_again(): void
    {
        $this->fakeFeeds(['packagist.org/*' => Http::sequence()->push('Busy', 503)->push(self::fixture('packagist.json'))]);

        $report = SecurityAlerts::scan();

        $this->assertTrue($report->isComplete());
        $this->assertCount(13, $report->findings);
    }

    public function test_osv_down(): void
    {
        $this->fakeFeeds(['api.osv.dev/v1/vulns/*' => Http::response([], 500)]);

        $report = SecurityAlerts::scan();

        $this->assertSame(['OSV couldn\'t be reached: details for GHSA-fjxv-7rqg-78g4 couldn\'t be fetched. npm packages weren\'t checked.'], $report->problems);
        $this->assertSame([Ecosystem::Composer], $report->checked);
    }

    public function test_kev_down_still_reports_but_says_so(): void
    {
        $this->fakeFeeds(['www.cisa.gov/*' => Http::response('<html>Access denied</html>', 403)]);

        $report = SecurityAlerts::scan();

        $this->assertCount(13, $report->findings);
        $this->assertSame([], $report->exploited());
        $this->assertFalse($report->kevChecked);
        $this->assertSame(['CISA KEV couldn\'t be reached: it answered HTTP 403. Findings aren\'t marked as exploited this time.'], $report->problems);
    }

    public function test_kev_can_be_turned_off(): void
    {
        config()->set('security-alerts.sources.kev.enabled', false);
        $this->fakeFeeds();

        $report = SecurityAlerts::scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame([], $report->exploited());
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'cisa.gov'));
    }

    public function test_feeds_are_cached_and_fresh_skips_the_cache(): void
    {
        $this->fakeFeeds();

        SecurityAlerts::scan();
        Http::assertSentCount(7);

        $again = SecurityAlerts::scan();
        Http::assertSentCount(7);
        $this->assertCount(13, $again->findings);

        SecurityAlerts::scan(fresh: true);
        Http::assertSentCount(14);
    }

    public function test_a_changed_osv_advisory_is_fetched_again(): void
    {
        $modified = null;
        $this->fakeFeeds(['api.osv.dev/v1/querybatch' => function (Request $request) use (&$modified) {
            $batch = self::osvBatch($request);
            if ($modified !== null) {
                $batch['results'][1]['vulns'][0]['modified'] = $modified;
            }

            return Http::response($batch);
        }]);
        config()->set('security-alerts.cache.advisories_ttl', 0);

        SecurityAlerts::scan();
        Http::assertSentCount(7);

        $modified = '2026-10-11T00:00:00Z';
        SecurityAlerts::scan();

        Http::assertSentCount(7 + 3);
        $this->assertCount(2, Http::recorded(fn (Request $request) => str_ends_with($request->url(), '/vulns/GHSA-fjxv-7rqg-78g4')));
        $this->assertCount(1, Http::recorded(fn (Request $request) => str_ends_with($request->url(), '/vulns/GHSA-hmw2-7cc7-3qxx')));
    }

    public function test_many_packages_are_batched(): void
    {
        $packages = array_map(fn (int $i) => ['name' => "acme/package-{$i}", 'version' => '1.0.0'], range(1, Packagist::BATCH + 50));
        $this->lockfile('composer', ['packages' => $packages]);
        config()->set('security-alerts.npm.enabled', false);
        Http::fake([
            'packagist.org/*' => Http::response(['advisories' => ['acme/package-7' => [[
                'advisoryId' => 'PKSA-7', 'packageName' => 'acme/package-7', 'title' => 'Seven', 'affectedVersions' => '<1.0.1', 'cve' => null, 'severity' => 'low',
            ]]]]),
            'www.cisa.gov/*' => Http::response(self::fixture('kev.json')),
        ]);

        $report = SecurityAlerts::scan();

        Http::assertSentCount(2);
        $this->assertCount(1, $report->findings, 'The same advisory answered twice is one finding');
        $this->assertSame('1.0.1', $report->findings[0]->fixedIn);
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'cisa.gov'));
    }

    public function test_a_mirror_can_be_configured(): void
    {
        config()->set('security-alerts.sources.packagist.url', 'https://repo.example.com/api/security-advisories/');
        $this->fakeFeeds(['repo.example.com/*' => Http::response(['advisories' => []])]);

        $report = SecurityAlerts::scan();

        Http::assertSent(fn (Request $request) => str_starts_with($request->url(), 'https://repo.example.com/'));
        Http::assertNotSent(fn (Request $request) => str_contains($request->url(), 'packagist.org'));
        $this->assertCount(4, $report->findings);
    }
}
