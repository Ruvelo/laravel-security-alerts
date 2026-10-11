<?php

declare(strict_types=1);

/*
 * Builds the demo published at https://ruvelo.github.io/laravel-security-alerts/.
 *
 * Boots a Laravel app with the package, points it at the lockfiles of
 * Halyard (a made-up billing SaaS) and answers Packagist, OSV and CISA KEV
 * from the responses recorded in tests/fixtures, so the build never touches
 * the network. Then it runs the real scan, the real artisan command and the
 * real notification, and renders the pages through the HTTP kernel, exactly
 * as an app would.
 *
 *   php demo/build.php <site-dir> [<shots-dir>]
 *
 * <shots-dir>, when given, receives the pages the screenshots are taken of:
 * without the demo banner, one section each.
 */

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Http\Request;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\View;
use Orchestra\Testbench\Foundation\Application;
use Ruvelo\SecurityAlerts\Notifications\VulnerabilitiesFound;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Ruvelo\SecurityAlerts\SecurityAlertsServiceProvider;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;

require __DIR__.'/../vendor/autoload.php';

const HOST = 'https://ruvelo.github.io';
const PATH = 'laravel-security-alerts';
const REPO = 'https://github.com/Ruvelo/laravel-security-alerts';
const FIXTURES = __DIR__.'/../tests/fixtures';

$site = rtrim($argv[1] ?? __DIR__.'/../build/site', '/');
$shots = isset($argv[2]) ? rtrim($argv[2], '/') : null;

foreach ([
    'APP_ENV' => 'production',
    'APP_NAME' => 'Halyard',
    'APP_KEY' => 'base64:'.base64_encode(random_bytes(32)),
    'APP_URL' => 'https://app.halyard.test',
    'DB_CONNECTION' => 'sqlite',
    'DB_DATABASE' => ':memory:',
    'CACHE_STORE' => 'array',
    'SESSION_DRIVER' => 'array',
    'MAIL_MAILER' => 'array',
] as $key => $value) {
    putenv("{$key}={$value}");
    $_ENV[$key] = $_SERVER[$key] = $value;
}

$app = Application::create(basePath: null, options: ['extra' => ['providers' => [SecurityAlertsServiceProvider::class]]]);
View::addNamespace('demo', __DIR__.'/views');

config()->set('database.default', 'sqlite');
config()->set('database.connections.sqlite.database', ':memory:');
config()->set('security-alerts.composer.lockfile', FIXTURES.'/composer.lock');
config()->set('security-alerts.npm.lockfile', FIXTURES.'/package-lock.json');
config()->set('security-alerts.notify.mail', ['maya@halyard.test', 'tom@halyard.test']);
Artisan::call('migrate', ['--force' => true]);

// --- The feeds, from recorded responses ----------------------------------------

$fixture = fn (string $name): array => json_decode((string) file_get_contents(FIXTURES.'/'.$name), true, 512, JSON_THROW_ON_ERROR);

Http::preventStrayRequests();
Http::fake([
    'packagist.org/api/security-advisories/*' => Http::response($fixture('packagist.json')),
    'api.osv.dev/v1/querybatch' => Http::response($fixture('osv-querybatch.json')),
    'api.osv.dev/v1/vulns/*' => fn (HttpRequest $request) => Http::response($fixture('osv/'.basename($request->url()).'.json')),
    'www.cisa.gov/*' => Http::response($fixture('kev.json')),
]);

// --- Run it, as the scheduler would on the morning of 12 October 2026 ----------

CarbonImmutable::setTestNow('2026-10-12 07:00:00');

$result = SecurityAlerts::check(notify: false);
$report = $result->report;

// The terminal, rendered by the real command with colours.
$output = new BufferedOutput(OutputInterface::VERBOSITY_NORMAL, decorated: true);
Artisan::call('security-alerts:check', [], $output);
$terminal = ansiToHtml($output->fetch());

// The email, rendered by the real notification.
$mail = new VulnerabilitiesFound(SecurityAlerts::open());
$mailHtml = (string) $mail->toMail(new AnonymousNotifiable)->render();
$mailSubject = $mail->subject();

Route::middleware('web')->get('/'.PATH, fn (Request $request) => view('demo::page', [
    'report' => $report,
    'terminal' => $terminal,
    'mailSubject' => $mailSubject,
    'only' => $request->query('only'),
    'shot' => $request->boolean('shot'),
    'repo' => REPO,
]));

Route::get('/'.PATH.'/mail', fn () => response($mailHtml));

// --- Render -------------------------------------------------------------------

$http = $app->make(HttpKernel::class);

$fetch = function (string $path = '', string $query = '') use ($http): string {
    $request = Request::create(HOST.'/'.PATH.'/'.$path.$query);
    $response = $http->handle($request);
    $http->terminate($request, $response);

    if ($response->getStatusCode() !== 200) {
        throw new RuntimeException('The demo page failed to render: '.$response->getStatusCode()."\n".$response->getContent());
    }

    return str_replace(HOST.'/', '/', (string) $response->getContent());
};

$banner = '<div class="demo-banner">'
    .'You’re looking at the demo of <a href="'.REPO.'">ruvelo/laravel-security-alerts</a>, built by the package itself from recorded feeds. '
    .'<a href="'.REPO.'#readme">Read the docs</a></div>';

$write = function (string $root, string $path, string $html, bool $withBanner = true) use ($banner): void {
    if ($withBanner) {
        $html = preg_replace('/<body([^>]*)>/', '<body$1>'.$banner, $html, 1);
    }
    $file = $root.'/'.($path === '' ? '' : $path.'/').'index.html';
    is_dir(dirname($file)) || mkdir(dirname($file), 0777, true);
    file_put_contents($file, $html);
};

$write($site, '', $fetch());
$write($site, 'mail', $fetch('mail'), false);

if ($shots !== null) {
    $write($shots, 'page', $fetch('', '?shot=1'), false);
    $write($shots, 'report', $fetch('', '?only=report&shot=1'), false);
    $write($shots, 'terminal', $fetch('', '?only=terminal&shot=1'), false);
    $write($shots, 'mail', $fetch('mail'), false);
}

fwrite(STDOUT, sprintf("Built the demo (%d findings, %d exploited) into %s\n", count($report->findings), count($report->exploited()), $site));

/**
 * The few ANSI codes Symfony's console writes, as spans.
 */
function ansiToHtml(string $ansi): string
{
    $html = '';
    $open = 0;

    foreach (preg_split('/(\e\[[\d;]*m)/', $ansi, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [] as $part) {
        if (preg_match('/^\e\[([\d;]*)m$/', $part, $m) !== 1) {
            $html .= htmlspecialchars($part, ENT_QUOTES);

            continue;
        }

        $classes = [];
        foreach (explode(';', $m[1]) as $code) {
            $class = match ($code) {
                '1' => 'b', '31' => 'red', '32' => 'green', '33' => 'yellow', '34' => 'blue', '90' => 'gray', '37' => 'white',
                '41' => 'bg-red', '42' => 'bg-green', '43' => 'bg-yellow', '44' => 'bg-blue',
                default => null,
            };
            if ($class !== null) {
                $classes[] = $class;
            }
        }

        if ($classes === []) {
            $html .= str_repeat('</span>', $open);
            $open = 0;
        } else {
            $html .= '<span class="'.implode(' ', $classes).'">';
            $open++;
        }
    }

    return rtrim($html.str_repeat('</span>', $open))."\n";
}
