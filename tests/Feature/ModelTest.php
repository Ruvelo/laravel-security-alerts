<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class ModelTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_factory_and_its_states(): void
    {
        $alert = SecurityAlert::factory()->forPackage('axios', '1.11.0', Ecosystem::Npm)->create();
        $exploited = SecurityAlert::factory()->exploited('2026-03-20', '2026-04-03')->create();
        $pending = SecurityAlert::factory()->pending()->create();
        $resolved = SecurityAlert::factory()->resolved()->create();

        $this->assertSame('npm:axios:'.$alert->advisory_id, $alert->key);
        $this->assertSame(Ecosystem::Npm, $alert->ecosystem);
        $this->assertTrue($alert->isOpen());
        $this->assertFalse($alert->isExploited());
        $this->assertNotNull($alert->notified_at);

        $this->assertTrue($exploited->isExploited());
        $this->assertSame(Severity::Critical, $exploited->severity);
        $this->assertSame('2026-04-03', $exploited->kev_due_date?->toDateString());

        $this->assertNull($pending->notified_at);
        $this->assertFalse($resolved->isOpen());
    }

    public function test_scopes(): void
    {
        SecurityAlert::factory()->severity(Severity::Low)->forPackage('a/low')->create();
        SecurityAlert::factory()->severity(Severity::NotRated)->forPackage('a/unknown')->create();
        SecurityAlert::factory()->severity(Severity::Critical)->forPackage('b/critical')->create();
        SecurityAlert::factory()->severity(Severity::High)->forPackage('a/high')->create();
        SecurityAlert::factory()->exploited('2026-01-01')->forPackage('z/old-exploit')->create();
        SecurityAlert::factory()->exploited('2026-09-01')->forPackage('z/new-exploit')->create();
        SecurityAlert::factory()->resolved()->forPackage('a/resolved')->create();

        $this->assertSame(
            ['z/new-exploit', 'z/old-exploit', 'b/critical', 'a/high', 'a/unknown', 'a/low'],
            SecurityAlert::query()->open()->worstFirst()->pluck('package')->all(),
        );
        $this->assertSame(3, SecurityAlert::query()->exploited()->count() + 1);
    }

    public function test_presentation(): void
    {
        $alert = SecurityAlert::factory()->exploited('2026-03-20')->forPackage('livewire/livewire', '3.6.2')->create(['cve' => 'CVE-2025-54068']);

        $present = $alert->present();

        $this->assertSame('livewire/livewire', $present['package']);
        $this->assertTrue($present['exploited']);
        $this->assertSame('CVE-2025-54068', $present['kev']['cve']);
        $this->assertNull($present['resolved_at']);
        $this->assertArrayHasKey('first_seen_at', $present);
    }
}
