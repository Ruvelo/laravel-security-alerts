<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SecurityAdvisoriesException;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Threshold;
use Ruvelo\SecurityAlerts\Exceptions\SecurityAlertsException;
use Ruvelo\SecurityAlerts\SecurityAlerts;
use Symfony\Component\Console\Helper\TableSeparator;

class CheckCommand extends Command
{
    /** Exit code when a source or lockfile couldn't be read, so the answer is incomplete. */
    public const INCOMPLETE = 2;

    protected $signature = 'security-alerts:check
        {--fail-on= : Exit with 1 when a finding is at least: exploited, critical, high, medium or any}
        {--json : Print the report as JSON}
        {--notify : Remember findings and send alerts for new ones (what the scheduler runs)}
        {--fresh : Ignore cached advisories}';

    protected $description = 'Check installed Composer and npm packages for known vulnerabilities, exploited ones first';

    public function handle(): int
    {
        try {
            $threshold = is_string($this->option('fail-on')) && $this->option('fail-on') !== '' ? Threshold::parse($this->option('fail-on')) : null;

            if ($this->option('notify')) {
                $result = SecurityAlerts::check((bool) $this->option('fresh'));
                $report = $result->report;
            } else {
                $report = SecurityAlerts::scan((bool) $this->option('fresh'));
            }
        } catch (SecurityAlertsException|SecurityAdvisoriesException $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }

        if ($this->option('json')) {
            $this->line((string) json_encode(SecurityAlerts::toArray($report), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        } else {
            $this->render($report);

            if (isset($result) && $result->notified > 0) {
                $this->components->info('Sent an alert about '.Str::plural('finding', $result->notified, true).'.');
            }
        }

        if ($threshold !== null && $report->failing($threshold) !== []) {
            return self::FAILURE;
        }

        return $report->isComplete() ? self::SUCCESS : self::INCOMPLETE;
    }

    private function render(Report $report): void
    {
        $this->newLine();

        if ($report->isClean()) {
            if ($report->packageCount() > 0) {
                $this->components->info('No known vulnerabilities in '.$this->scope($report).', checked '.SecurityAlerts::sourceLabel($report, true).'.');
            }
        } else {
            $rows = [];
            foreach ($report->findings as $i => $finding) {
                if ($i > 0) {
                    $rows[] = new TableSeparator;
                }
                $rows[] = $this->row($finding);
            }

            $this->table(['', 'Package', 'Installed', 'Fixed in', 'Advisory'], $rows, 'box');
            $this->newLine();
            foreach ($this->summary($report) as $line) {
                $this->line('  '.$line);
            }
            $this->newLine();
        }

        foreach ($report->problems as $problem) {
            $this->components->warn($problem);
        }
    }

    /**
     * @return array<int, string>
     */
    private function row(Finding $finding): array
    {
        $advisory = Str::limit($finding->title, 64, '…');
        $details = array_filter([$finding->cve, $finding->link !== null ? preg_replace('#^https?://(www\.)?#', '', $finding->link) : null]);
        if ($details !== []) {
            $advisory .= "\n<fg=gray>".implode(' · ', $details).'</>';
        }
        if ($finding->exploited !== null) {
            $advisory .= "\n<fg=red>In CISA KEV since ".$finding->exploited->dateAdded->format('Y-m-d')
                .($finding->exploited->dueDate !== null ? ', patch by '.$finding->exploited->dueDate->format('Y-m-d') : '').'</>';
        }

        return [
            $finding->isExploited() ? '<fg=red;options=bold>Exploited</>' : $this->severity($finding->severity),
            $finding->package.($finding->ecosystem === Ecosystem::Npm ? ' <fg=gray>npm</>' : '').($finding->isDev ? ' <fg=gray>dev</>' : ''),
            $finding->installed,
            $finding->fixedIn !== null ? '<fg=green>'.$finding->fixedIn.'</>' : '<fg=gray>–</>',
            $advisory,
        ];
    }

    private function severity(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => '<fg=red>Critical</>',
            Severity::High => '<fg=yellow>High</>',
            Severity::Medium => 'Medium',
            Severity::Low, Severity::NotRated => '<fg=gray>'.$severity->label().'</>',
        };
    }

    /**
     * @return list<string>
     */
    private function summary(Report $report): array
    {
        $parts = [];
        foreach ($report->counts() as $kind => $count) {
            $parts[] = $kind === 'exploited'
                ? "<fg=red;options=bold>{$count} exploited in the wild</>"
                : $count.' '.($kind === 'not_rated' ? 'unrated' : $kind);
        }

        $total = count($report->findings);
        $packages = count($report->affectedPackages());
        $line = Str::plural('vulnerability', $total, true).' in '.Str::plural('package', $packages, true).': '.implode(', ', $parts).'.';

        $lines = [$line];

        $worst = $report->findings[0];
        if ($worst->isExploited()) {
            $lines[] = '<options=bold>Update '.$worst->package.($worst->fixedIn !== null && ! str_starts_with($worst->fixedIn, '>') ? ' to '.$worst->fixedIn.' or later' : '').' today.</>';
        }

        $lines[] = '<fg=gray>Checked '.$this->scope($report).' '.SecurityAlerts::sourceLabel($report, true).'.</>';

        return $lines;
    }

    private function scope(Report $report): string
    {
        $parts = [];
        foreach (Ecosystem::cases() as $ecosystem) {
            if (($count = $report->packageCount($ecosystem)) > 0) {
                $parts[] = $count.' '.$ecosystem->label();
            }
        }

        return implode(' and ', $parts).' '.Str::plural('package', $report->packageCount());
    }
}
