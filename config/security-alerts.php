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
    | Free and keyless. Packagist and OSV receive package names and versions,
    | the same data `composer audit` and `npm audit` send; nothing else about
    | your app. The CISA KEV catalogue is downloaded whole. Point `url` at a
    | mirror or Private Packagist if you use one.
    |
    */

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

];
