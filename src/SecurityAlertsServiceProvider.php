<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;
use Ruvelo\SecurityAlerts\Console\CheckCommand;
use Ruvelo\SecurityAlerts\Console\DigestCommand;

class SecurityAlertsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-alerts.php', 'security-alerts');

        $this->app->singleton(Scanner::class);
        $this->app->singleton(Recorder::class);
        $this->app->singleton(Notifier::class);
    }

    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'security-alerts');

        if (config('security-alerts.run_migrations', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        if ($this->app->runningInConsole()) {
            $this->commands([CheckCommand::class, DigestCommand::class]);

            $this->publishes([
                __DIR__.'/../config/security-alerts.php' => config_path('security-alerts.php'),
            ], 'security-alerts-config');

            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views/vendor/security-alerts'),
            ], 'security-alerts-views');

            $this->publishesMigrations([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'security-alerts-migrations');
        }

        $this->callAfterResolving(Schedule::class, fn (Schedule $schedule) => $this->schedule($schedule));
    }

    /**
     * The daily check, and the weekly digest when it's on. Both need the
     * scheduler to be running already.
     */
    private function schedule(Schedule $schedule): void
    {
        $timezone = config('security-alerts.schedule.timezone');
        $timezone = is_string($timezone) && $timezone !== '' ? $timezone : null;

        if (config('security-alerts.schedule.enabled', true)) {
            $event = $schedule->command(CheckCommand::class, ['--notify'])
                ->dailyAt(self::time(config('security-alerts.schedule.time'), '07:00'))
                ->withoutOverlapping()
                ->onOneServer()
                ->description('Check installed packages for known vulnerabilities');

            if ($timezone !== null) {
                $event->timezone($timezone);
            }
        }

        if (config('security-alerts.digest.enabled', false)) {
            $day = config('security-alerts.digest.day', 'monday');
            $days = ['sunday' => 0, 'monday' => 1, 'tuesday' => 2, 'wednesday' => 3, 'thursday' => 4, 'friday' => 5, 'saturday' => 6];

            $event = $schedule->command(DigestCommand::class)
                ->weeklyOn($days[strtolower(is_string($day) ? $day : 'monday')] ?? (is_numeric($day) ? (int) $day : 1), self::time(config('security-alerts.digest.time'), '08:00'))
                ->onOneServer()
                ->description('Send the weekly digest of open security alerts');

            if ($timezone !== null) {
                $event->timezone($timezone);
            }
        }
    }

    private static function time(mixed $value, string $default): string
    {
        return is_string($value) && preg_match('/^([01]?\d|2[0-3]):[0-5]\d$/', $value) === 1 ? $value : $default;
    }
}
