<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Slack\SlackMessage;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Notification;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;
use Ruvelo\SecurityAlerts\Notifications\VulnerabilitiesFound;
use Ruvelo\SecurityAlerts\Notifications\WeeklyDigest;

/**
 * Sends what hasn't been sent, to whoever the config and the app name.
 *
 * @internal Use SecurityAlerts::check() and SecurityAlerts::sendDigest()
 */
class Notifier
{
    /** @var (Closure(): iterable<object>)|null */
    private static ?Closure $notifiables = null;

    /**
     * @param  (Closure(): iterable<object>)|null  $callback
     */
    public static function using(?Closure $callback): void
    {
        self::$notifiables = $callback;
    }

    /**
     * Sends open alerts nobody has heard about yet, then marks them sent.
     * If nothing can be sent (no one configured, or sending fails), they
     * stay pending and go out with the next check.
     */
    public function sendPending(): int
    {
        $alerts = SecurityAlert::query()->open()
            ->where(fn ($query) => $query->whereNull('notified_at')
                ->orWhere(fn ($query) => $query->whereNotNull('exploited_at')->whereNull('exploited_notified_at')))
            ->worstFirst()
            ->get();

        $minimum = Severity::tryFrom(strtolower((string) (is_string($min = config('security-alerts.notify.min_severity')) ? $min : '')));
        if ($minimum !== null) {
            $alerts = $alerts->filter(fn (SecurityAlert $alert): bool => $alert->isExploited() || $alert->severity->atLeast($minimum))->values();
        }

        $notifiables = $this->notifiables();

        if ($alerts->isEmpty() || $notifiables === []) {
            return 0;
        }

        Notification::send($notifiables, new VulnerabilitiesFound($alerts));

        $now = CarbonImmutable::now();
        $alerts->each(function (SecurityAlert $alert) use ($now): void {
            $alert->forceFill([
                'notified_at' => $alert->notified_at ?? $now,
                'exploited_notified_at' => $alert->isExploited() ? ($alert->exploited_notified_at ?? $now) : null,
            ])->save();
        });

        return $alerts->count();
    }

    /**
     * @return Collection<int, SecurityAlert> What was sent
     */
    public function sendDigest(): Collection
    {
        $alerts = SecurityAlert::query()->open()->worstFirst()->get();
        $notifiables = $this->notifiables();

        if ($notifiables !== []) {
            Notification::send($notifiables, new WeeklyDigest($alerts));
        }

        return $alerts;
    }

    /**
     * @return list<object>
     */
    public function notifiables(): array
    {
        $notifiables = [];
        $routes = new AnonymousNotifiable;

        $mail = config('security-alerts.notify.mail');
        $mail = array_values(array_filter(is_string($mail) ? explode(',', $mail) : (is_array($mail) ? $mail : []), fn ($a): bool => is_string($a) && trim($a) !== ''));
        if ($mail !== []) {
            $routes->route('mail', array_map('trim', $mail));
        }

        $slack = config('security-alerts.notify.slack');
        if (is_string($slack) && $slack !== '') {
            if (class_exists(SlackMessage::class)) {
                $routes->route('slack', $slack);
            } else {
                logger()->warning('Security alerts: a Slack webhook is set (security-alerts.notify.slack), but laravel/slack-notification-channel is not installed. Run: composer require laravel/slack-notification-channel');
            }
        }

        if ($routes->routes !== []) {
            $notifiables[] = $routes;
        }

        if (self::$notifiables !== null) {
            foreach ((self::$notifiables)() as $notifiable) {
                $notifiables[] = $notifiable;
            }
        }

        return $notifiables;
    }
}
