<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Notifications;

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Slack\BlockKit\Blocks\ContextBlock;
use Illuminate\Notifications\Slack\BlockKit\Blocks\SectionBlock;
use Illuminate\Notifications\Slack\SlackMessage;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Ruvelo\SecurityAlerts\Models\SecurityAlert;

/**
 * What the alert and the digest share: a list of alerts, exploited first,
 * by mail and Slack.
 */
abstract class AlertsNotification extends Notification
{
    /**
     * @param  Collection<int, SecurityAlert>  $alerts  Worst first
     */
    public function __construct(public readonly Collection $alerts) {}

    abstract public function subject(): string;

    abstract protected function heading(): string;

    abstract protected function intro(): string;

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        if ($notifiable instanceof AnonymousNotifiable) {
            return array_keys($notifiable->routes);
        }

        $via = config('security-alerts.notify.via', ['mail']);

        return is_array($via) ? array_values(array_filter($via, 'is_string')) : ['mail'];
    }

    /**
     * @return Collection<int, SecurityAlert>
     */
    public function exploited(): Collection
    {
        return $this->alerts->filter(fn (SecurityAlert $alert): bool => $alert->isExploited())->values();
    }

    /**
     * @return Collection<int, SecurityAlert>
     */
    public function others(): Collection
    {
        return $this->alerts->reject(fn (SecurityAlert $alert): bool => $alert->isExploited())->values();
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject($this->subject())
            ->markdown('security-alerts::mail.alerts', [
                'heading' => $this->heading(),
                'intro' => $this->intro(),
                'exploited' => $this->exploited(),
                'others' => $this->others(),
                'footer' => $this->footer(),
                'md' => self::markdown(...),
            ]);
    }

    public function toSlack(object $notifiable): SlackMessage
    {
        $message = (new SlackMessage)
            ->text($this->subject())
            ->headerBlock(Str::limit($this->heading(), 140, '…'))
            ->sectionBlock(fn (SectionBlock $block) => $block->text(self::slack($this->intro())));

        // Slack allows 50 blocks: keep room for the header, intro and footer.
        foreach ($this->alerts->take(40) as $alert) {
            $message->sectionBlock(fn (SectionBlock $block) => $block->text($this->slackLine($alert))->markdown());
        }

        if ($this->alerts->count() > 40) {
            $message->contextBlock(fn (ContextBlock $block) => $block->text('And '.($this->alerts->count() - 40).' more. Run php artisan security-alerts:check for the full list.'));
        }

        return $message->contextBlock(fn (ContextBlock $block) => $block->text($this->footer()));
    }

    protected function footer(): string
    {
        return 'Run php artisan security-alerts:check to see every open alert.';
    }

    protected function slackLine(SecurityAlert $alert): string
    {
        $title = self::slack($alert->title);
        $title = $alert->link !== null ? '<'.self::slack($alert->link).'|'.$title.'>' : $title;

        $line = ($alert->isExploited() ? ':rotating_light: *Exploited in the wild* · ' : '')
            .'*'.self::slack($alert->package).'* '.self::slack($alert->version).' · '.$alert->severity->label()."\n".$title;

        $details = array_filter([
            $alert->cve !== null ? self::slack($alert->cve) : null,
            $alert->fixed_in !== null ? 'Fixed in '.self::slack($alert->fixed_in) : 'No fixed version listed',
            $alert->isExploited() ? 'In CISA KEV since '.$alert->exploited_at?->toDateString().($alert->kev_due_date !== null ? ', patch by '.$alert->kev_due_date->toDateString() : '') : null,
        ]);

        return $line."\n".implode(' · ', $details);
    }

    protected function appName(): string
    {
        $name = config('app.name');

        return is_string($name) && $name !== '' ? $name : 'your app';
    }

    protected static function plural(int $count, string $one, string $many): string
    {
        return $count === 1 ? $one : $count.' '.$many;
    }

    /**
     * Advisory titles are data, not Markdown: keep them from formatting the
     * mail or breaking its tables.
     */
    public static function markdown(?string $text): string
    {
        // < and > are left to Blade, which turns them into entities.
        return (string) preg_replace('/([\\\\`*_{}\[\]()#+!|~])/', '\\\\$1', (string) $text);
    }

    public static function slack(?string $text): string
    {
        return str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], (string) $text);
    }
}
