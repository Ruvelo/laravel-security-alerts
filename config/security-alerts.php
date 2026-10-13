<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Who hears about it
    |--------------------------------------------------------------------------
    |
    | Alerts go out when a check finds a new vulnerability, or learns that one
    | it already knew about is now exploited in the wild. Each is sent once.
    |
    | `mail`: addresses, comma-separated in SECURITY_ALERTS_MAIL.
    | `slack`: an incoming webhook URL. Needs laravel/slack-notification-channel.
    | `via`: channels used for the notifiables you register yourself with
    | SecurityAlerts::notifyUsing(fn () => User::where('is_admin', true)->get()).
    | `min_severity`: skip new findings below this (critical, high, medium,
    | low). Exploited ones are always sent. Null sends everything.
    |
    */

    'notify' => [
        'mail' => array_values(array_filter(array_map('trim', explode(',', (string) env('SECURITY_ALERTS_MAIL', ''))))),
        'slack' => env('SECURITY_ALERTS_SLACK_WEBHOOK'),
        'via' => ['mail'],
        'min_severity' => env('SECURITY_ALERTS_MIN_SEVERITY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | When
    |--------------------------------------------------------------------------
    |
    | The check runs daily through Laravel's scheduler, which must already be
    | running (`php artisan schedule:run` every minute). The weekly digest,
    | off by default, lists everything still open, even when nothing changed.
    |
    */

    'schedule' => [
        'enabled' => (bool) env('SECURITY_ALERTS_SCHEDULE', true),
        'time' => env('SECURITY_ALERTS_TIME', '07:00'),
        'timezone' => null,
    ],

    'digest' => [
        'enabled' => (bool) env('SECURITY_ALERTS_DIGEST', false),
        'day' => 'monday',
        'time' => '08:00',
    ],

    /*
    |--------------------------------------------------------------------------
    | What gets checked
    |--------------------------------------------------------------------------
    |
    | Exact versions come from the lockfiles. Composer's dev packages aren't
    | deployed to production, so they're left out. npm's are kept: Laravel
    | apps list front-end libraries (axios, Alpine...) as devDependencies
    | because Vite bundles them into what visitors download.
    |
    */

    'composer' => [
        'lockfile' => null, // base_path('composer.lock')
        'include_dev' => false,
    ],

    'npm' => [
        'enabled' => true,
        'lockfile' => null, // base_path('package-lock.json')
        'include_dev' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Sources
    |--------------------------------------------------------------------------
    |
    | `source`: "valtry" (the default) asks Valtry's signed Advisory API, which
    | serves the same Packagist, OSV and CISA KEV data. It is sent package names
    | only, never versions, and its answers are signature-checked. Whenever it
    | can't answer, the public feeds are used instead, automatically. Set
    | SECURITY_ALERTS_SOURCE=public to never contact Valtry. Details in the
    | README ("Data sources").
    |
    | The public feeds are free and keyless. Packagist receives package names;
    | OSV receives the names and versions of your npm packages, as `npm audit`
    | does. The CISA KEV catalogue is downloaded whole (`kev.enabled` only
    | switches off that download: Valtry's answers carry the exploited verdict).
    | Point `url` at a mirror or Private Packagist if you use one.
    |
    */

    'source' => env('SECURITY_ALERTS_SOURCE', 'valtry'),

    'valtry_url' => 'https://valtry.co.uk/api/advisories/v1/query',

    'sources' => [
        'packagist' => ['url' => 'https://packagist.org/api/security-advisories/'],
        'osv' => ['url' => 'https://api.osv.dev/v1'],
        'kev' => [
            'enabled' => true,
            'url' => 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        ],
    ],

    'http' => [
        'timeout' => 15,
        'tries' => 2,
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache
    |--------------------------------------------------------------------------
    |
    | Feed answers are cached, in seconds, so running the command again is
    | instant. `--fresh` skips the cache. Null `store` means your default.
    |
    */

    'cache' => [
        'store' => env('SECURITY_ALERTS_CACHE_STORE'),
        'advisories_ttl' => 3600,
        'kev_ttl' => 21600,
        'osv_details_ttl' => 604800,
    ],

    /*
    |--------------------------------------------------------------------------
    | Storage
    |--------------------------------------------------------------------------
    |
    | What's been seen and sent lives in one small table, so a cache:clear
    | on deploy never re-sends old alerts.
    |
    */

    'table' => 'security_alerts',

    'run_migrations' => true,

    /*
    |--------------------------------------------------------------------------
    | MCP (AI agents)
    |--------------------------------------------------------------------------
    |
    | With laravel/mcp installed and this enabled, agents get a read-only
    | `list_security_alerts` tool. `local` is the handle for `php artisan
    | mcp:start {local}`; `path` an HTTP endpoint guarded by `middleware`.
    | Null turns either off.
    |
    */

    'mcp' => [
        'enabled' => (bool) env('SECURITY_ALERTS_MCP', false),
        'local' => 'security-alerts',
        'path' => null,
        'middleware' => ['auth:sanctum'],
    ],

];
