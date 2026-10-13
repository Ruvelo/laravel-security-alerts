<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Feature;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Ruvelo\SecurityAlerts\Scanner;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\Tests\TestCase;

class ValtrySourceTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('RUVELO_ADVISORIES_SOURCE');

        parent::tearDown();
    }

    private function valtryRequests(): int
    {
        return count(Http::recorded(fn (Request $request) => str_contains($request->url(), 'valtry.co.uk')));
    }

    public function test_valtry_is_the_default_source(): void
    {
        $config = require __DIR__.'/../../config/security-alerts.php';

        $this->assertSame('valtry', $config['source']);
        $this->assertSame('https://valtry.co.uk/api/advisories/v1/query', $config['valtry_url']);
    }

    public function test_a_signed_answer_gives_the_same_findings_as_the_public_feeds(): void
    {
        $this->fakeFeeds();
        $public = SecurityAlerts::scan(fresh: true);
        $this->assertSame('public', $public->source);

        $this->fakeValtry();
        $report = SecurityAlerts::scan(fresh: true);

        $this->assertSame('valtry', $report->source);
        $this->assertSame(['composer' => 'valtry', 'npm' => 'valtry'], $report->sources);
        $this->assertTrue($report->isComplete());
        $this->assertSame(
            array_map(fn ($finding) => $finding->key(), $public->findings),
            array_map(fn ($finding) => $finding->key(), $report->findings),
        );
        $this->assertSame(['exploited' => 1, 'critical' => 2, 'high' => 4, 'medium' => 5, 'low' => 1], $report->counts());
    }

    public function test_valtry_is_sent_package_names_and_never_versions(): void
    {
        $this->fakeValtry();

        SecurityAlerts::scan(fresh: true);

        $sent = Http::recorded(fn (Request $request) => str_contains($request->url(), 'valtry.co.uk'))->all();
        $this->assertNotEmpty($sent);
        foreach ($sent as [$request]) {
            $this->assertSame(['nonce', 'packages'], array_keys($request->data()));
            foreach ($request['packages'] as $package) {
                $this->assertSame(['ecosystem', 'name'], array_keys($package));
            }
            $this->assertStringStartsWith('ruvelo/laravel-security-alerts', $request->header('User-Agent')[0]);
        }
        $this->assertStringNotContainsString('3.6.2', json_encode(array_map(fn (array $pair) => $pair[0]->data(), $sent)));
    }

    public function test_nothing_goes_to_the_public_feeds_while_valtry_answers(): void
    {
        $this->fakeValtry();
        $before = count(Http::recorded());

        SecurityAlerts::scan(fresh: true);

        $after = Http::recorded();
        foreach (array_slice($after->all(), $before) as [$request]) {
            $this->assertStringContainsString('valtry.co.uk', $request->url(), 'Only Valtry is asked');
        }
    }

    public function test_it_falls_back_to_the_public_feeds_when_valtry_fails(): void
    {
        $this->fakeValtry(status: 503);

        $report = SecurityAlerts::scan(fresh: true);

        $this->assertSame('public', $report->source);
        $this->assertTrue($report->isComplete());
        $this->assertCount(13, $report->findings);
    }

    public function test_an_answer_with_a_bad_signature_is_refused(): void
    {
        $this->fakeValtry(tamper: fn (string $body, string $header) => [str_replace('"stale":false', '"stale":false,"x":1', $body), $header]);

        $report = SecurityAlerts::scan(fresh: true);

        $this->assertSame('public', $report->source);
        $this->assertCount(13, $report->findings);
    }

    public function test_an_answer_signed_by_an_unknown_key_is_refused(): void
    {
        $this->fakeValtry(tamper: fn (string $body, string $header) => [$body, str_replace('kid=test-1', 'kid=someone-else', $header)]);

        $this->assertSame('public', SecurityAlerts::scan(fresh: true)->source);
    }

    public function test_the_pinned_keys_are_used_unless_a_test_says_otherwise(): void
    {
        $this->fakeValtry();
        $this->app->forgetInstance(Scanner::class);
        $this->app->singleton(Scanner::class);

        $this->assertSame('public', SecurityAlerts::scan(fresh: true)->source, 'Signed with a key the package does not pin');
    }

    public function test_the_source_can_be_set_to_public(): void
    {
        $this->fakeValtry();
        config()->set('security-alerts.source', 'public');

        $report = SecurityAlerts::scan(fresh: true);

        $this->assertSame('public', $report->source);
        $this->assertSame(0, $this->valtryRequests(), 'Valtry is never contacted');
    }

    public function test_the_environment_wins_over_the_config(): void
    {
        $this->fakeValtry();
        putenv('RUVELO_ADVISORIES_SOURCE=public');

        $this->assertSame('public', SecurityAlerts::scan(fresh: true)->source);
    }

    public function test_the_command_says_where_the_answer_came_from(): void
    {
        $this->fakeValtry();

        $this->artisan('security-alerts:check')->expectsOutputToContain('Checked 67 Composer and 38 npm packages via Valtry, signed.');

        Artisan::call('security-alerts:check --json');
        $json = json_decode(Artisan::output(), true);
        $this->assertSame('valtry', $json['source']);
        $this->assertSame(['composer' => 'valtry', 'npm' => 'valtry'], $json['sources']);
        $this->assertSame('3.6.2', $json['findings'][0]['version']);
        $this->assertSame('3.6.2', $json['findings'][0]['installed']);
    }

    public function test_the_command_says_when_the_public_feeds_answered(): void
    {
        $this->fakeValtry(status: 500);

        $this->artisan('security-alerts:check')->expectsOutputToContain('Checked 67 Composer and 38 npm packages via public feeds.');
    }
}
