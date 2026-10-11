<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Finding;
use Ruvelo\SecurityAlerts\KevEntry;
use Ruvelo\SecurityAlerts\Report;
use Ruvelo\SecurityAlerts\Severity;
use Ruvelo\SecurityAlerts\Threshold;

class ReportTest extends TestCase
{
    public function test_findings_are_sorted_exploited_first_then_by_severity(): void
    {
        $report = new Report([
            $this->finding('b/low', Severity::Low),
            $this->finding('a/high', Severity::High),
            $this->finding('z/exploited-low', Severity::Low, '2026-01-01'),
            $this->finding('c/critical', Severity::Critical),
            $this->finding('y/exploited-recent', Severity::Medium, '2026-09-01'),
            $this->finding('b/high', Severity::High),
            $this->finding('d/unknown', Severity::Unknown),
        ]);

        $this->assertSame(
            ['y/exploited-recent', 'z/exploited-low', 'c/critical', 'a/high', 'b/high', 'd/unknown', 'b/low'],
            array_map(fn (Finding $f) => $f->package, $report->findings),
        );
    }

    public function test_counts_thresholds_and_shape(): void
    {
        $report = new Report(
            [$this->finding('a/a', Severity::High), $this->finding('a/a', Severity::Medium, id: 'PKSA-2'), $this->finding('b/b', Severity::Critical, '2026-03-20')],
            packages: ['composer' => 60, 'npm' => 30],
            checked: [Ecosystem::Composer, Ecosystem::Npm],
            checkedAt: CarbonImmutable::parse('2026-10-12 07:00:00', 'UTC'),
        );

        $this->assertSame(['exploited' => 1, 'high' => 1, 'medium' => 1], $report->counts());
        $this->assertSame(['b/b', 'a/a'], $report->affectedPackages());
        $this->assertSame(90, $report->packageCount());
        $this->assertSame(30, $report->packageCount(Ecosystem::Npm));
        $this->assertCount(1, $report->exploited());
        $this->assertCount(2, $report->failing(Threshold::High));
        $this->assertCount(3, $report->failing(Threshold::Any));
        $this->assertFalse($report->isClean());
        $this->assertTrue($report->isComplete());

        $array = json_decode((string) json_encode($report), true);
        $this->assertSame(['checked_at', 'clean', 'complete', 'packages', 'counts', 'problems', 'findings'], array_keys($array));
        $this->assertSame('2026-10-12T07:00:00+00:00', $array['checked_at']);
        $this->assertSame([
            'key' => 'composer:b/b:PKSA-1', 'ecosystem' => 'composer', 'package' => 'b/b', 'version' => '1.0.0', 'dev' => false,
            'advisory_id' => 'PKSA-1', 'title' => 'A flaw in b/b', 'severity' => 'critical', 'link' => null, 'cve' => 'CVE-2026-0001',
            'fixed_in' => '1.0.1', 'affected_versions' => '<1.0.1', 'reported_at' => null, 'exploited' => true,
            'kev' => ['cve' => 'CVE-2026-0001', 'name' => 'Flaw', 'date_added' => '2026-03-20', 'due_date' => null, 'ransomware' => false],
        ], $array['findings'][0]);
    }

    public function test_a_clean_report(): void
    {
        $report = new Report([], problems: ['OSV couldn\'t be reached.']);

        $this->assertTrue($report->isClean());
        $this->assertFalse($report->isComplete());
        $this->assertSame([], $report->counts());
    }

    private function finding(string $package, Severity $severity, ?string $exploited = null, string $id = 'PKSA-1'): Finding
    {
        return new Finding(
            Ecosystem::Composer, $package, '1.0.0', $id, 'A flaw in '.$package, $severity,
            cve: 'CVE-2026-0001', fixedIn: '1.0.1', affectedVersions: '<1.0.1',
            exploited: $exploited !== null ? new KevEntry('CVE-2026-0001', 'Flaw', CarbonImmutable::parse($exploited, 'UTC')) : null,
        );
    }
}
