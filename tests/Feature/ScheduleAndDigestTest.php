<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature;

use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\Notifications\WeeklyDigest;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class ScheduleAndDigestTest extends TestCase
{
    use RefreshDatabase;

    public function test_a_daily_check_is_scheduled(): void
    {
        $events = $this->events();

        $this->assertCount(1, $events);
        $this->assertStringContainsString('security-alerts:check', (string) $events[0]->command);
        $this->assertStringContainsString('--notify', (string) $events[0]->command);
        $this->assertSame('0 7 * * *', $events[0]->expression);
        $this->assertTrue($events[0]->onOneServer);
        $this->assertTrue($events[0]->withoutOverlapping);
    }

    public function test_the_time_and_timezone_are_configurable(): void
    {
        config()->set('security-alerts.schedule.time', '05:30');
        config()->set('security-alerts.schedule.timezone', 'Europe/Brussels');

        $event = $this->events()[0];

        $this->assertSame('30 5 * * *', $event->expression);
        $this->assertSame('Europe/Brussels', $event->timezone);
    }

    public function test_a_bad_time_falls_back_to_the_default(): void
    {
        config()->set('security-alerts.schedule.time', '25:99');

        $this->assertSame('0 7 * * *', $this->events()[0]->expression);
    }

    public function test_the_schedule_can_be_turned_off(): void
    {
        config()->set('security-alerts.schedule.enabled', false);

        $this->assertSame([], $this->events());
    }

    public function test_the_weekly_digest_when_turned_on(): void
    {
        config()->set('security-alerts.digest.enabled', true);
        config()->set('security-alerts.digest.day', 'friday');
        config()->set('security-alerts.digest.time', '16:00');

        $events = $this->events();

        $this->assertCount(2, $events);
        $this->assertStringContainsString('security-alerts:digest', (string) $events[1]->command);
        $this->assertSame('0 16 * * 5', $events[1]->expression);
    }

    public function test_the_digest_lists_every_open_alert(): void
    {
        config()->set('security-alerts.notify.mail', ['maya@halyard.test']);
        Notification::fake();
        SecurityAlert::factory()->exploited()->forPackage('livewire/livewire', '3.6.2')->create();
        SecurityAlert::factory()->count(2)->create();
        SecurityAlert::factory()->resolved()->create();

        $this->artisan('security-alerts:digest')
            ->expectsOutputToContain('Sent the digest: 3 open alerts.')
            ->assertSuccessful();

        Notification::assertSentOnDemand(WeeklyDigest::class, function (WeeklyDigest $digest, array $channels, AnonymousNotifiable $notifiable) {
            $this->assertCount(3, $digest->alerts);
            $this->assertSame('livewire/livewire', $digest->alerts->first()?->package);
            $this->assertSame('Halyard: 3 open vulnerabilities this week', $digest->subject());
            $html = (string) $digest->toMail($notifiable)->render();
            $this->assertStringContainsString('3 open vulnerabilities', $html);
            $this->assertStringContainsString('one of them exploited in the wild', $html);

            return true;
        });
    }

    public function test_an_empty_digest_still_goes_out(): void
    {
        config()->set('security-alerts.notify.mail', ['maya@halyard.test']);
        Notification::fake();

        $this->artisan('security-alerts:digest')->expectsOutputToContain('no open alerts')->assertSuccessful();

        Notification::assertSentOnDemand(WeeklyDigest::class, fn (WeeklyDigest $d) => $d->subject() === 'Halyard: no known vulnerabilities this week');
    }

    public function test_a_digest_with_nobody_to_send_to(): void
    {
        Notification::fake();

        $this->artisan('security-alerts:digest')
            ->expectsOutputToContain('Nobody to send the digest to')
            ->assertFailed();

        Notification::assertNothingSent();
    }

    /**
     * @return list<Event>
     */
    private function events(): array
    {
        // The provider adds its events when the Schedule is resolved.
        $this->app->forgetInstance(Schedule::class);
        $schedule = $this->app->make(Schedule::class);

        return array_values(array_filter($schedule->events(), fn (Event $event) => str_contains((string) $event->command, 'security-alerts')));
    }
}
