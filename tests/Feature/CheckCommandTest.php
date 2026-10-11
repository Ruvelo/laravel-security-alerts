<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Schema;
use Ruvelo\SecurityAlerts\Console\CheckCommand;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\Notifications\VulnerabilitiesFound;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class CheckCommandTest extends TestCase
{
    use RefreshDatabase;

    public function test_a_table_exploited_first_and_a_summary(): void
    {
        $this->fakeFeeds();

        $code = Artisan::call('security-alerts:check');
        $output = Artisan::output();

        $this->assertSame(0, $code);
        $this->assertMatchesRegularExpression('/Exploited\s+│ livewire\/livewire\s+│ 3\.6\.2\s+│ 3\.6\.4/u', $output);
        $this->assertStringContainsString('In CISA KEV since 2026-03-20, patch by 2026-04-03', $output);
        $this->assertStringContainsString('form-data npm dev', $output);
        $this->assertStringContainsString('13 vulnerabilities in 8 packages: 1 exploited in the wild, 2 critical, 4 high, 5 medium, 1 low.', $output);
        $this->assertStringContainsString('Update livewire/livewire to 3.6.4 or later today.', $output);
        $this->assertStringContainsString('Checked 67 Composer and 38 npm packages.', $output);
        $this->assertLessThan(strpos($output, 'predis/predis'), strpos($output, 'livewire/livewire'));
        $this->assertStringNotContainsStringIgnoringCase('valtry', $output);
    }

    public function test_it_changes_nothing_without_notify(): void
    {
        $this->fakeFeeds();
        config()->set('security-alerts.notify.mail', ['maya@halyard.test']);
        Notification::fake();

        $this->artisan('security-alerts:check')->assertSuccessful();

        $this->assertSame(0, SecurityAlert::query()->count());
        Notification::assertNothingSent();
    }

    public function test_notify_remembers_and_sends(): void
    {
        $this->fakeFeeds();
        config()->set('security-alerts.notify.mail', ['maya@halyard.test']);
        Notification::fake();

        $this->artisan('security-alerts:check --notify')
            ->expectsOutputToContain('Sent an alert about 13 findings.')
            ->assertSuccessful();

        $this->assertSame(13, SecurityAlert::query()->count());
        Notification::assertSentOnDemandTimes(VulnerabilitiesFound::class, 1);

        $this->artisan('security-alerts:check --notify')->doesntExpectOutputToContain('Sent an alert')->assertSuccessful();
    }

    public function test_notify_without_the_migration(): void
    {
        $this->fakeFeeds();
        Schema::drop('security_alerts');

        $this->artisan('security-alerts:check --notify')
            ->expectsOutputToContain('Run: php artisan migrate')
            ->assertFailed();
    }

    public function test_fail_on_thresholds_for_ci(): void
    {
        $this->fakeFeeds();

        $this->artisan('security-alerts:check --fail-on=exploited')->assertExitCode(1);
        $this->artisan('security-alerts:check --fail-on=high')->assertExitCode(1);
        $this->artisan('security-alerts:check --fail-on=any')->assertExitCode(1);
    }

    public function test_fail_on_passes_when_nothing_reaches_it(): void
    {
        $this->fakeFeeds();
        config()->set('security-alerts.npm.enabled', false);
        $this->lockfile('composer', ['packages' => [['name' => 'symfony/http-foundation', 'version' => 'v7.4.12']]]);

        $this->artisan('security-alerts:check --fail-on=exploited')->assertExitCode(0);
        $this->artisan('security-alerts:check --fail-on=high')->assertExitCode(0);
        $this->artisan('security-alerts:check --fail-on=medium')->assertExitCode(1);
    }

    public function test_an_unknown_threshold(): void
    {
        $this->fakeFeeds();

        $this->artisan('security-alerts:check --fail-on=severe')
            ->expectsOutputToContain('Unknown threshold "severe"')
            ->assertExitCode(1);
        Http::assertNothingSent();
    }

    public function test_json(): void
    {
        $this->fakeFeeds();

        Artisan::call('security-alerts:check --json');
        $json = json_decode(Artisan::output(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertTrue($json['complete']);
        $this->assertSame(['composer' => 67, 'npm' => 38], $json['packages']);
        $this->assertSame(['exploited' => 1, 'critical' => 2, 'high' => 4, 'medium' => 5, 'low' => 1], $json['counts']);
        $this->assertCount(13, $json['findings']);
        $this->assertSame('livewire/livewire', $json['findings'][0]['package']);
        $this->assertTrue($json['findings'][0]['exploited']);
        $this->assertSame('2026-04-03', $json['findings'][0]['kev']['due_date']);
    }

    public function test_json_with_fail_on(): void
    {
        $this->fakeFeeds();

        $this->assertSame(1, Artisan::call('security-alerts:check --json --fail-on=exploited'));
        $this->assertJson(Artisan::output());
    }

    public function test_all_clear(): void
    {
        $this->fakeFeeds();
        config()->set('security-alerts.npm.enabled', false);
        $this->lockfile('composer', ['packages' => [['name' => 'laravel/framework', 'version' => 'v13.35.0'], ['name' => 'nesbot/carbon', 'version' => '3.14.2']]]);

        $this->artisan('security-alerts:check --fail-on=any')
            ->expectsOutputToContain('No known vulnerabilities in 2 Composer packages.')
            ->assertExitCode(0);
    }

    public function test_an_incomplete_check_exits_with_2(): void
    {
        $this->fakeFeeds(['api.osv.dev/*' => Http::response('', 503)]);

        $this->artisan('security-alerts:check')
            ->expectsOutputToContain('OSV couldn\'t be reached')
            ->assertExitCode(CheckCommand::INCOMPLETE);
    }

    public function test_a_failing_threshold_wins_over_incomplete(): void
    {
        $this->fakeFeeds(['api.osv.dev/*' => Http::response('', 503)]);

        $this->artisan('security-alerts:check --fail-on=exploited')->assertExitCode(1);
    }

    public function test_fresh_skips_the_cache(): void
    {
        $this->fakeFeeds();

        Artisan::call('security-alerts:check');
        Artisan::call('security-alerts:check');
        Http::assertSentCount(7);

        Artisan::call('security-alerts:check --fresh');
        Http::assertSentCount(14);
    }
}
