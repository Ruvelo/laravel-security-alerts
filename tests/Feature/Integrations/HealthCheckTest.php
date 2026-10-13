<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature\Integrations;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Integrations\Health\SecurityAlertsCheck;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\Tests\TestCase;
use Spatie\Health\Enums\Status;

class HealthCheckTest extends TestCase
{
    use RefreshDatabase;

    public function test_ok_after_a_recent_clean_check(): void
    {
        $this->checkedNow();

        $result = SecurityAlertsCheck::new()->run();

        $this->assertSame(Status::ok()->value, $result->status->value);
        $this->assertSame('0 open alerts', $result->getShortSummary());
        $this->assertSame(0, $result->meta['open']);
    }

    public function test_a_check_that_never_ran_warns(): void
    {
        $result = SecurityAlertsCheck::new()->run();

        $this->assertSame(Status::warning()->value, $result->status->value);
        $this->assertStringContainsString('Is the scheduler running?', $result->notificationMessage);
    }

    public function test_a_stale_check_warns(): void
    {
        $this->checkedNow();
        $this->travel(3)->days();

        $this->assertSame(Status::warning()->value, SecurityAlertsCheck::new()->run()->status->value);
        $this->assertSame(Status::ok()->value, SecurityAlertsCheck::new()->staleAfterHours(100)->run()->status->value);
    }

    public function test_medium_findings_are_fine_by_default(): void
    {
        $this->checkedNow();
        SecurityAlert::factory()->severity(Severity::Medium)->create();

        $result = SecurityAlertsCheck::new()->run();

        $this->assertSame(Status::ok()->value, $result->status->value);
        $this->assertSame('1 open alert', $result->getShortSummary());
        $this->assertSame(Status::warning()->value, SecurityAlertsCheck::new()->warnFrom('medium')->run()->status->value);
    }

    public function test_high_findings_warn(): void
    {
        $this->checkedNow();
        SecurityAlert::factory()->severity(Severity::High)->forPackage('guzzlehttp/guzzle', '7.15.1')->create();

        $result = SecurityAlertsCheck::new()->run();

        $this->assertSame(Status::warning()->value, $result->status->value);
        $this->assertSame('Vulnerable: guzzlehttp/guzzle 7.15.1.', $result->notificationMessage);
        $this->assertSame(Status::failed()->value, SecurityAlertsCheck::new()->failFrom(Severity::High)->run()->status->value);
    }

    public function test_exploited_fails(): void
    {
        $this->checkedNow();
        SecurityAlert::factory()->exploited()->forPackage('livewire/livewire', '3.6.2')->create();
        SecurityAlert::factory()->resolved()->exploited()->create();

        $result = SecurityAlertsCheck::new()->run();

        $this->assertSame(Status::failed()->value, $result->status->value);
        $this->assertSame('1 exploited', $result->getShortSummary());
        $this->assertSame('Exploited in the wild: livewire/livewire 3.6.2. Update today.', $result->notificationMessage);
    }

    private function checkedNow(): void
    {
        $this->fakeFeeds();
        config()->set('security-alerts.npm.enabled', false);
        $this->lockfile('composer', ['packages' => []]);
        SecurityAlerts::check(notify: false);
    }
}
