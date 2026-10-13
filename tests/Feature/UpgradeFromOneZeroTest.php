<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Events\VulnerabilityExploited;
use Ruvelo\SecurityAlerts\Events\VulnerabilityFound;
use Ruvelo\SecurityAlerts\Events\VulnerabilityResolved;
use Ruvelo\SecurityAlerts\Exceptions\LockfileUnreadable;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\Tests\TestCase;
use Ruvelo\SecurityAlerts\Threshold;

/**
 * An app that ran 1.0 has a security_alerts table full of alerts already
 * sent. The first 1.1 check must recognise them, whichever source answers,
 * and send nothing again.
 */
class UpgradeFromOneZeroTest extends TestCase
{
    use RefreshDatabase;

    private const EVENTS = [VulnerabilityFound::class, VulnerabilityExploited::class, VulnerabilityResolved::class];

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('security-alerts.notify.mail', ['maya@halyard.test']);
    }

    /**
     * The table as 1.0 left it after its daily checks: one row per finding,
     * keyed ecosystem:package:advisory, everything already sent.
     */
    private function seedOneZeroRows(): void
    {
        $this->fakeFeeds();
        $sent = '2026-10-10 07:00:00';

        foreach (SecurityAlerts::scan(fresh: true)->findings as $finding) {
            DB::table('security_alerts')->insert([
                'key' => $finding->ecosystem->value.':'.$finding->package.':'.$finding->advisoryId,
                'ecosystem' => $finding->ecosystem->value,
                'package' => $finding->package,
                'version' => $finding->installed,
                'advisory_id' => $finding->advisoryId,
                'title' => $finding->title,
                'severity' => $finding->severity->value === 'not_rated' ? 'unknown' : $finding->severity->value,
                'link' => $finding->link,
                'cve' => $finding->cve,
                'fixed_in' => $finding->fixedIn,
                'affected_versions' => $finding->affectedVersions,
                'dev' => $finding->isDev,
                'exploited_at' => $finding->exploited?->dateAdded->format('Y-m-d'),
                'kev_due_date' => $finding->exploited?->dueDate?->format('Y-m-d'),
                'ransomware' => false,
                'first_seen_at' => $sent,
                'last_seen_at' => $sent,
                'notified_at' => $sent,
                'exploited_notified_at' => $finding->isExploited() ? $sent : null,
                'resolved_at' => null,
                'created_at' => $sent,
                'updated_at' => $sent,
            ]);
        }

        $this->assertSame(13, SecurityAlert::query()->count());
    }

    private function assertNothingNew(): void
    {
        Event::fake(self::EVENTS);
        Notification::fake();

        $result = SecurityAlerts::check(fresh: true);

        $this->assertTrue($result->report->isComplete());
        $this->assertCount(13, $result->report->findings);
        $this->assertFalse($result->changed());
        $this->assertSame(0, $result->notified);
        Event::assertNotDispatched(VulnerabilityFound::class);
        Event::assertNotDispatched(VulnerabilityExploited::class);
        Event::assertNotDispatched(VulnerabilityResolved::class);
        Notification::assertNothingSent();
        $this->assertSame(13, SecurityAlert::query()->count());
        $this->assertSame(13, SecurityAlert::query()->open()->count());
        $this->assertSame(0, SecurityAlert::query()->whereNull('notified_at')->count());
        $this->assertSame(1, SecurityAlert::query()->whereNotNull('exploited_notified_at')->count());
    }

    public function test_1_0_rows_are_known_to_the_public_path(): void
    {
        $this->seedOneZeroRows();

        $this->assertNothingNew();
    }

    public function test_1_0_rows_are_known_to_the_valtry_path(): void
    {
        $this->seedOneZeroRows();
        $this->fakeValtry();

        $this->assertNothingNew();
    }

    public function test_a_row_stored_under_another_id_is_recognised_by_its_cve(): void
    {
        $this->seedOneZeroRows();
        $this->fakeValtry();

        // 1.0 knew these two vulnerabilities under ids the answer no longer uses.
        $keys = [];
        foreach (['livewire/livewire' => 'CVE-2025-54068', 'form-data' => 'CVE-2025-7783'] as $package => $cve) {
            $alert = SecurityAlert::query()->where('package', $package)->where('cve', $cve)->sole();
            $keys[$alert->id] = $alert->key;
            $alert->forceFill(['key' => $alert->ecosystem->value.':'.$package.':OLD-ID-'.$alert->id, 'advisory_id' => 'OLD-ID-'.$alert->id])->save();
        }

        $this->assertNothingNew();

        foreach ($keys as $id => $original) {
            $alert = SecurityAlert::query()->findOrFail($id);
            $this->assertSame('OLD-ID-'.$id, explode(':', $alert->key)[2], 'The stored identity is kept');
            $this->assertNotSame('OLD-ID-'.$id, $alert->advisory_id, 'The row shows the advisory as the answer names it now');
            $this->assertSame(explode(':', $original, 3)[2], $alert->advisory_id);
        }
    }

    public function test_a_resolved_1_0_row_stays_resolved_and_a_gone_finding_is_still_resolved(): void
    {
        $this->seedOneZeroRows();
        SecurityAlert::query()->where('package', 'predis/predis')->update(['resolved_at' => '2026-10-11 07:00:00']);
        DB::table('security_alerts')->insert([
            'key' => 'composer:acme/removed:PKSA-gone', 'ecosystem' => 'composer', 'package' => 'acme/removed', 'version' => '1.0.0', 'advisory_id' => 'PKSA-gone',
            'title' => 'Fixed long ago', 'severity' => 'unknown', 'dev' => false, 'ransomware' => false,
            'first_seen_at' => '2026-10-01 07:00:00', 'last_seen_at' => '2026-10-10 07:00:00', 'notified_at' => '2026-10-01 07:00:00',
        ]);
        $this->fakeValtry();

        Event::fake(self::EVENTS);
        $result = SecurityAlerts::check(fresh: true);

        $this->assertSame(['acme/removed'], $result->resolved->pluck('package')->all());
        $this->assertSame(['predis/predis'], $result->found->pluck('package')->all(), 'Back after a fix is new again, as in 1.0');
        $this->assertCount(0, $result->exploited);
        $this->assertContainsOnlyInstancesOf(Finding::class, $result->report->findings);
    }

    public function test_an_unrated_severity_is_still_stored_as_unknown(): void
    {
        $alert = SecurityAlert::factory()->severity(Severity::NotRated)->create();

        $this->assertSame('unknown', DB::table('security_alerts')->where('id', $alert->id)->value('severity'));
        $this->assertSame(Severity::NotRated, $alert->fresh()?->severity);

        DB::table('security_alerts')->where('id', $alert->id)->update(['severity' => 'unknown']);
        $this->assertSame(Severity::NotRated, $alert->fresh()?->severity);
    }

    public function test_the_1_0_class_names_still_resolve(): void
    {
        $this->assertSame(Severity::High, \Ruvelo\SecurityAlerts\Severity::High);
        $this->assertSame(Ecosystem::Npm, \Ruvelo\SecurityAlerts\Ecosystem::Npm);
        $this->assertTrue(is_a(Threshold::parse('high'), \Ruvelo\SecurityAdvisories\Threshold::class));
        $this->assertTrue(class_exists(LockfileUnreadable::class));
    }
}
