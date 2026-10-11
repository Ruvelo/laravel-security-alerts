<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Events\VulnerabilityExploited;
use Ruvelo\SecurityAlerts\Events\VulnerabilityFound;
use Ruvelo\SecurityAlerts\Events\VulnerabilityResolved;
use Ruvelo\SecurityAlerts\Exceptions\NotInstalled;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\Severity;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class CheckTest extends TestCase
{
    use RefreshDatabase;

    private const EVENTS = [VulnerabilityFound::class, VulnerabilityExploited::class, VulnerabilityResolved::class];

    private function assertNoAlertEvents(): void
    {
        foreach (self::EVENTS as $event) {
            Event::assertNotDispatched($event);
        }
    }

    public function test_the_first_check_remembers_every_finding_and_fires_events(): void
    {
        Event::fake(self::EVENTS);
        $this->fakeFeeds();

        $result = SecurityAlerts::check();

        $this->assertCount(13, $result->found);
        $this->assertCount(1, $result->exploited);
        $this->assertCount(0, $result->resolved);
        $this->assertTrue($result->changed());
        $this->assertSame(13, SecurityAlert::query()->count());

        Event::assertDispatchedTimes(VulnerabilityFound::class, 13);
        Event::assertDispatchedTimes(VulnerabilityExploited::class, 1);
        Event::assertDispatched(VulnerabilityExploited::class, fn (VulnerabilityExploited $e) => $e->alert->package === 'livewire/livewire');
        Event::assertNotDispatched(VulnerabilityResolved::class);

        $alert = SecurityAlert::query()->where('package', 'livewire/livewire')->where('cve', 'CVE-2025-54068')->sole();
        $this->assertSame(Ecosystem::Composer, $alert->ecosystem);
        $this->assertSame(Severity::Critical, $alert->severity);
        $this->assertSame('3.6.2', $alert->version);
        $this->assertSame('3.6.4', $alert->fixed_in);
        $this->assertSame('2026-03-20', $alert->exploited_at?->toDateString());
        $this->assertSame('2026-04-03', $alert->kev_due_date?->toDateString());
        $this->assertTrue($alert->isOpen());
        $this->assertTrue($alert->isExploited());
        $this->assertSame($result->report->findings[0]->key(), $alert->toFinding()->key());
        $this->assertSame('2026-03-20', $alert->toFinding()->exploited?->dateAdded->toDateString());
    }

    public function test_the_same_findings_are_never_reported_twice(): void
    {
        $this->fakeFeeds();
        SecurityAlerts::check();

        Event::fake(self::EVENTS);
        $result = SecurityAlerts::check(fresh: true);

        $this->assertFalse($result->changed());
        $this->assertNoAlertEvents();
        $this->assertSame(13, SecurityAlert::query()->count());
    }

    public function test_an_update_resolves_the_alert(): void
    {
        $this->fakeFeeds();
        SecurityAlerts::check();

        $lock = self::fixture('composer.lock');
        foreach ($lock['packages'] as &$package) {
            if ($package['name'] === 'livewire/livewire') {
                $package['version'] = 'v3.8.3';
            }
        }
        $this->lockfile('composer', $lock);

        Event::fake(self::EVENTS);
        $result = SecurityAlerts::check();

        $this->assertSame(['livewire/livewire', 'livewire/livewire'], $result->resolved->pluck('package')->all());
        Event::assertDispatchedTimes(VulnerabilityResolved::class, 2);
        Event::assertNotDispatched(VulnerabilityFound::class);
        $this->assertSame(11, SecurityAlerts::open()->count());
        $this->assertNotNull(SecurityAlert::query()->where('package', 'livewire/livewire')->first()?->resolved_at);
    }

    public function test_a_known_finding_that_becomes_exploited(): void
    {
        $this->fakeFeeds();
        SecurityAlerts::check();
        SecurityAlert::query()->update(['notified_at' => now(), 'exploited_notified_at' => now()]);

        // CISA adds the Predis flaw to its catalogue.
        $kev = self::fixture('kev.json');
        $kev['vulnerabilities'][] = ['cveID' => 'CVE-2026-84372', 'vulnerabilityName' => 'Predis CRLF Injection Vulnerability', 'dateAdded' => '2026-10-10', 'dueDate' => '2026-10-31', 'knownRansomwareCampaignUse' => 'Unknown'];
        $this->feed('www.cisa.gov/*', Http::response($kev));
        config()->set('security-alerts.cache.kev_ttl', 0);

        Event::fake(self::EVENTS);
        $result = SecurityAlerts::check(fresh: true);

        $this->assertSame(['predis/predis'], $result->exploited->pluck('package')->all());
        $this->assertCount(0, $result->found);
        Event::assertDispatchedTimes(VulnerabilityExploited::class, 1);
        Event::assertNotDispatched(VulnerabilityFound::class);

        $predis = SecurityAlert::query()->where('package', 'predis/predis')->sole();
        $this->assertSame('2026-10-10', $predis->exploited_at?->toDateString());
        $this->assertNull($predis->exploited_notified_at, 'Waiting to be sent');
        $this->assertNotNull($predis->notified_at);
    }

    public function test_exploited_stays_exploited_when_cisa_is_unreachable(): void
    {
        $this->fakeFeeds();
        SecurityAlerts::check();

        config()->set('security-alerts.cache.kev_ttl', 0);
        $this->feed('www.cisa.gov/*', Http::response('', 500));

        Event::fake(self::EVENTS);
        SecurityAlerts::check(fresh: true);

        $this->assertNoAlertEvents();
        $this->assertTrue(SecurityAlert::query()->where('cve', 'CVE-2025-54068')->sole()->isExploited());
    }

    public function test_a_finding_that_comes_back_is_new_again(): void
    {
        $this->fakeFeeds();
        SecurityAlerts::check();
        SecurityAlert::query()->update(['notified_at' => now(), 'resolved_at' => now()->subDay()]);

        Event::fake(self::EVENTS);
        $result = SecurityAlerts::check();

        $this->assertCount(13, $result->found);
        Event::assertDispatchedTimes(VulnerabilityFound::class, 13);
        Event::assertNotDispatched(VulnerabilityExploited::class, 'Already known to be exploited');
        $this->assertSame(0, SecurityAlert::query()->whereNotNull('notified_at')->count());
        $this->assertSame(13, SecurityAlert::query()->count());
    }

    public function test_a_source_that_failed_resolves_nothing(): void
    {
        $this->fakeFeeds();
        SecurityAlerts::check();

        config()->set('security-alerts.cache.advisories_ttl', 0);
        $this->feed('api.osv.dev/*', Http::response('', 503));

        Event::fake(self::EVENTS);
        $result = SecurityAlerts::check(fresh: true);

        $this->assertFalse($result->report->isComplete());
        $this->assertCount(0, $result->resolved);
        Event::assertNotDispatched(VulnerabilityResolved::class);
        $this->assertSame(4, SecurityAlerts::open()->where('ecosystem', Ecosystem::Npm)->count());
    }

    public function test_it_remembers_when_it_last_checked(): void
    {
        $this->assertNull(SecurityAlerts::lastCheck());
        $this->fakeFeeds();
        $this->travelTo('2026-10-12 07:00:00');

        SecurityAlerts::check();

        $last = SecurityAlerts::lastCheck();
        $this->assertSame('2026-10-12 07:00:00', $last['checked_at']->toDateTimeString());
        $this->assertSame(105, $last['packages']);
        $this->assertSame(13, $last['findings']);
        $this->assertSame(1, $last['exploited']);
        $this->assertTrue($last['complete']);
    }

    public function test_open_alerts_are_listed_worst_first_without_the_network(): void
    {
        $this->fakeFeeds();
        SecurityAlerts::check();
        $sent = count(Http::recorded());

        $open = SecurityAlerts::open();

        $this->assertSame(count(Http::recorded()), $sent);
        $this->assertSame('livewire/livewire', $open->first()?->package);
        $this->assertSame(['critical', 'critical', 'high'], $open->slice(1, 3)->map(fn (SecurityAlert $a) => $a->severity->value)->values()->all());
        $this->assertSame('low', $open->last()?->severity->value);
    }

    public function test_without_the_migration_it_says_what_to_do(): void
    {
        $this->fakeFeeds();
        Schema::drop('security_alerts');

        $this->expectException(NotInstalled::class);
        $this->expectExceptionMessage('The security_alerts table doesn\'t exist yet. Run: php artisan migrate');

        SecurityAlerts::check();
    }

    public function test_the_table_name_is_configurable(): void
    {
        $this->assertSame('security_alerts', (new SecurityAlert)->getTable());
        config()->set('security-alerts.table', 'ops_security_alerts');
        $this->assertSame('ops_security_alerts', (new SecurityAlert)->getTable());
    }

    public function test_scanning_stores_nothing(): void
    {
        $this->fakeFeeds();

        SecurityAlerts::scan();

        $this->assertSame(0, SecurityAlert::query()->count());
        $this->assertNull(SecurityAlerts::lastCheck());
        Http::assertSent(fn (Request $request) => true);
    }
}
