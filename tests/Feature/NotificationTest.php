<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use RuntimeException;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\Notifications\VulnerabilitiesFound;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class NotificationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('security-alerts.notify.mail', ['maya@halyard.test', 'tom@halyard.test']);
        $this->fakeFeeds();
    }

    public function test_one_mail_for_everything_new_exploited_first(): void
    {
        Notification::fake();

        $result = SecurityAlerts::check();

        $this->assertSame(13, $result->notified);
        Notification::assertSentOnDemandTimes(VulnerabilitiesFound::class, 1);
        Notification::assertSentOnDemand(VulnerabilitiesFound::class, function (VulnerabilitiesFound $notification, array $channels, AnonymousNotifiable $notifiable) {
            $this->assertSame(['mail'], $channels);
            $this->assertSame(['maya@halyard.test', 'tom@halyard.test'], $notifiable->routes['mail']);
            $this->assertCount(13, $notification->alerts);
            $this->assertSame('livewire/livewire', $notification->alerts->first()?->package);
            $this->assertSame('Halyard: exploited vulnerability in livewire/livewire, patch today', $notification->subject());

            return true;
        });
        $this->assertSame(0, SecurityAlert::query()->whereNull('notified_at')->count());
        $this->assertSame(1, SecurityAlert::query()->whereNotNull('exploited_notified_at')->count());
    }

    public function test_nothing_is_sent_twice(): void
    {
        Notification::fake();
        SecurityAlerts::check();

        $result = SecurityAlerts::check(fresh: true);

        $this->assertSame(0, $result->notified);
        Notification::assertSentOnDemandTimes(VulnerabilitiesFound::class, 1);
    }

    public function test_becoming_exploited_is_sent_on_its_own(): void
    {
        Notification::fake();
        SecurityAlerts::check();

        $kev = self::fixture('kev.json');
        $kev['vulnerabilities'][] = ['cveID' => 'CVE-2026-84372', 'vulnerabilityName' => 'Predis CRLF Injection Vulnerability', 'dateAdded' => '2026-10-10', 'dueDate' => '2026-10-31'];
        $this->feed('www.cisa.gov/*', Http::response($kev));
        SecurityAlerts::check(fresh: true);

        Notification::assertSentOnDemandTimes(VulnerabilitiesFound::class, 2);
        $last = Notification::sentNotifications()[AnonymousNotifiable::class];
        $sent = array_values($last)[0][VulnerabilitiesFound::class];
        $notification = end($sent)['notification'];
        $this->assertSame(['predis/predis'], $notification->alerts->pluck('package')->all());
        $this->assertSame('Halyard: exploited vulnerability in predis/predis, patch today', $notification->subject());
    }

    public function test_new_findings_without_exploited_ones(): void
    {
        config()->set('security-alerts.sources.kev.enabled', false);
        Notification::fake();

        SecurityAlerts::check();

        Notification::assertSentOnDemand(VulnerabilitiesFound::class, fn (VulnerabilitiesFound $n) => $n->subject() === 'Halyard: 13 new vulnerabilities in your dependencies');
    }

    public function test_a_single_new_finding(): void
    {
        config()->set('security-alerts.npm.enabled', false);
        $this->lockfile('composer', ['packages' => [['name' => 'predis/predis', 'version' => 'v3.2.0']]]);
        Notification::fake();

        SecurityAlerts::check();

        Notification::assertSentOnDemand(VulnerabilitiesFound::class, fn (VulnerabilitiesFound $n) => $n->subject() === 'Halyard: new vulnerability in predis/predis');
    }

    public function test_minimum_severity_but_exploited_always(): void
    {
        config()->set('security-alerts.notify.min_severity', 'critical');
        Notification::fake();

        $result = SecurityAlerts::check();

        $this->assertSame(3, $result->notified);
        Notification::assertSentOnDemand(VulnerabilitiesFound::class, fn (VulnerabilitiesFound $n) => $n->alerts->pluck('package')->all() === ['livewire/livewire', 'form-data', 'predis/predis']);
        $this->assertSame(10, SecurityAlert::query()->whereNull('notified_at')->count(), 'The rest are kept, not sent');
    }

    public function test_with_nobody_to_tell_alerts_wait(): void
    {
        config()->set('security-alerts.notify.mail', []);
        Notification::fake();

        $this->assertSame(0, SecurityAlerts::check()->notified);
        Notification::assertNothingSent();
        $this->assertSame(13, SecurityAlert::query()->whereNull('notified_at')->count());

        config()->set('security-alerts.notify.mail', 'maya@halyard.test');
        $this->assertSame(13, SecurityAlerts::check()->notified);
        Notification::assertSentOnDemandTimes(VulnerabilitiesFound::class, 1);
    }

    public function test_a_failed_send_is_tried_again_with_the_next_check(): void
    {
        Notification::shouldReceive('send')->once()->andThrow(new RuntimeException('SMTP is down'));

        try {
            SecurityAlerts::check();
            $this->fail('No exception');
        } catch (RuntimeException $e) {
            $this->assertSame('SMTP is down', $e->getMessage());
        }

        $this->assertSame(13, SecurityAlert::query()->whereNull('notified_at')->count());
    }

    public function test_the_app_can_add_its_own_notifiables(): void
    {
        config()->set('security-alerts.notify.mail', []);
        $admin = new class
        {
            use Notifiable;

            public string $email = 'ines@halyard.test';

            public function getKey(): int
            {
                return 1;
            }
        };
        SecurityAlerts::notifyUsing(fn () => [$admin]);
        Notification::fake();

        SecurityAlerts::check();

        Notification::assertSentTo($admin, VulnerabilitiesFound::class, fn (VulnerabilitiesFound $n, array $channels) => $channels === ['mail']);
    }

    public function test_slack_by_webhook(): void
    {
        config()->set('security-alerts.notify.slack', 'https://hooks.slack.com/services/T000/B000/XXXX');
        Notification::fake();

        SecurityAlerts::check();

        Notification::assertSentOnDemand(VulnerabilitiesFound::class, function (VulnerabilitiesFound $notification, array $channels, AnonymousNotifiable $notifiable) {
            $this->assertSame(['mail', 'slack'], $channels);
            $this->assertSame('https://hooks.slack.com/services/T000/B000/XXXX', $notifiable->routes['slack']);

            $payload = $notification->toSlack($notifiable)->toArray();
            $this->assertSame('Halyard: exploited vulnerability in livewire/livewire, patch today', $payload['text']);
            $this->assertSame('header', $payload['blocks'][0]['type']);
            $this->assertSame('A vulnerability in Halyard is being exploited', $payload['blocks'][0]['text']['text']);
            $this->assertStringContainsString(':rotating_light: *Exploited in the wild* · *livewire/livewire* 3.6.2 · Critical', $payload['blocks'][2]['text']['text']);
            $this->assertStringContainsString('<https://github.com/advisories/GHSA-29cq-5w36-x7w3|Livewire is vulnerable', $payload['blocks'][2]['text']['text']);
            $this->assertStringContainsString('In CISA KEV since 2026-03-20, patch by 2026-04-03', $payload['blocks'][2]['text']['text']);
            $this->assertCount(2 + 13 + 1, $payload['blocks']);

            return true;
        });
    }

    public function test_slack_reaches_the_webhook(): void
    {
        config()->set('security-alerts.notify.mail', []);
        config()->set('security-alerts.notify.slack', 'https://hooks.slack.com/services/T000/B000/XXXX');
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'ok')]));
        $stack->push(Middleware::history($history));
        $this->app->instance(Client::class, new Client(['handler' => $stack]));

        SecurityAlerts::check();

        $this->assertCount(1, $history);
        $this->assertSame('https://hooks.slack.com/services/T000/B000/XXXX', (string) $history[0]['request']->getUri());
        $body = json_decode((string) $history[0]['request']->getBody(), true);
        $this->assertSame('header', $body['blocks'][0]['type']);
    }

    public function test_slack_text_is_escaped(): void
    {
        $alert = SecurityAlert::factory()->forPackage('acme/<b>&co</b>')->create(['title' => 'Flaw <@here> & more', 'link' => null]);

        $payload = (new VulnerabilitiesFound(collect([$alert])))->toSlack(new AnonymousNotifiable)->toArray();

        $text = $payload['blocks'][2]['text']['text'];
        $this->assertStringContainsString('*acme/&lt;b&gt;&amp;co&lt;/b&gt;*', $text);
        $this->assertStringContainsString('Flaw &lt;@here&gt; &amp; more', $text);
    }

    public function test_the_mail(): void
    {
        SecurityAlerts::check(notify: false);
        $alerts = SecurityAlerts::open();

        $mail = (new VulnerabilitiesFound($alerts))->toMail(new AnonymousNotifiable);
        $html = (string) $mail->render();
        file_put_contents(sys_get_temp_dir().'/sa-mail.html', $html);

        $this->assertSame('Halyard: exploited vulnerability in livewire/livewire, patch today', $mail->subject);
        $this->assertStringContainsString('A vulnerability in Halyard is being exploited', $html);
        $this->assertStringContainsString('Attackers are using this flaw in the wild', $html);
        $this->assertStringContainsString('12 other new advisories below.', $html);
        $text = html_entity_decode(strip_tags($html), ENT_QUOTES);
        $this->assertStringContainsString('In CISA\'s catalogue since 20 March 2026; US agencies must patch by 3 April 2026. Update to 3.6.4 or later.', $text);
        $this->assertStringContainsString('predis/predis 3.2.0 · Critical · update to 3.3.0 or later', $text);
        $this->assertStringContainsString('livewire/livewire 3.6.2 · Medium · fixed after 3.8.2', $text);
        $this->assertStringContainsString('href="https://github.com/advisories/GHSA-w6f5-v2h6-g786"', $html);
        $this->assertStringContainsString('vite: `server.fs.deny` bypass on Windows alternate paths · CVE-2026-53571 · Advisory', $text);
        $this->assertStringContainsString('</ul>', $html);
        $this->assertMatchesRegularExpression('#</ul>\s*<p[^>]*>You\'ll hear about each of these once.#', $html);
        $this->assertLessThan(strpos($html, 'predis/predis'), strpos($html, 'livewire/livewire'), 'Exploited first');
        $this->assertStringNotContainsStringIgnoringCase('valtry', $html);
    }

    public function test_advisory_text_cannot_inject_markup_into_the_mail(): void
    {
        $alert = SecurityAlert::factory()->create([
            'title' => '<script>alert(1)</script> [click](javascript:alert(1)) | **bold**',
            'package' => 'acme/thing',
        ]);

        $html = (string) (new VulnerabilitiesFound(collect([$alert])))->toMail(new AnonymousNotifiable)->render();

        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringNotContainsString('href="javascript:', $html);
        $this->assertStringNotContainsString('<strong>bold</strong>', $html);
    }

    public function test_a_hostile_link_cannot_break_out_of_the_mail_link(): void
    {
        $safe = SecurityAlert::factory()->create(['link' => 'https://example.com/a) <img src=x onerror=alert(1)> (']);
        $script = SecurityAlert::factory()->create(['link' => 'javascript:alert(1)']);

        $html = (string) (new VulnerabilitiesFound(collect([$safe, $script])))->toMail(new AnonymousNotifiable)->render();

        $this->assertStringNotContainsString('<img src=x', $html);
        $this->assertStringContainsString('href="https://example.com/a%29%20%3Cimg%20src=x%20onerror=alert%281%29%3E%20%28"', $html);
        $this->assertStringNotContainsString('javascript:', $html);
    }

    public function test_severity_labels_in_the_mail_table(): void
    {
        $alert = SecurityAlert::factory()->severity(Severity::Low)->create(['fixed_in' => null]);

        $html = (string) (new VulnerabilitiesFound(collect([$alert])))->toMail(new AnonymousNotifiable)->render();

        $this->assertStringContainsString('Low', $html);
        $this->assertStringContainsString('A package Halyard has installed has a published security advisory.', $html);
    }
}
