<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Ruvelo\SecurityAlerts\Notifier;
use Ruvelo\SecurityAlerts\SecurityAlerts;

class DigestCommand extends Command
{
    protected $signature = 'security-alerts:digest';

    protected $description = 'Send the digest of open security alerts, as of the last check';

    public function handle(): int
    {
        if (app(Notifier::class)->notifiables() === []) {
            $this->components->warn('Nobody to send the digest to. Set SECURITY_ALERTS_MAIL or SECURITY_ALERTS_SLACK_WEBHOOK, or call SecurityAlerts::notifyUsing().');

            return self::FAILURE;
        }

        $alerts = SecurityAlerts::sendDigest();

        $this->components->info('Sent the digest: '.($alerts->isEmpty() ? 'no open alerts.' : Str::plural('open alert', $alerts->count(), true).'.'));

        return self::SUCCESS;
    }
}
