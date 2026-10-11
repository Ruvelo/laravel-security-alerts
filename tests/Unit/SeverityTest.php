<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Exceptions\InvalidThreshold;
use Ruvelo\SecurityAlerts\Exceptions\SecurityAlertsException;
use Ruvelo\SecurityAlerts\Finding;
use Ruvelo\SecurityAlerts\KevEntry;
use Ruvelo\SecurityAlerts\Severity;
use Ruvelo\SecurityAlerts\Threshold;

class SeverityTest extends TestCase
{
    public function test_it_reads_every_source_spelling(): void
    {
        $this->assertSame(Severity::Critical, Severity::parse('critical'));
        $this->assertSame(Severity::High, Severity::parse('HIGH'));
        $this->assertSame(Severity::Medium, Severity::parse('MODERATE'));
        $this->assertSame(Severity::Medium, Severity::parse(' medium '));
        $this->assertSame(Severity::Low, Severity::parse('low'));
        $this->assertSame(Severity::Unknown, Severity::parse(null));
        $this->assertSame(Severity::Unknown, Severity::parse('severe'));
    }

    public function test_unknown_ranks_above_low(): void
    {
        $this->assertTrue(Severity::Critical->atLeast(Severity::High));
        $this->assertTrue(Severity::Unknown->atLeast(Severity::Low));
        $this->assertFalse(Severity::Unknown->atLeast(Severity::Medium));
        $this->assertFalse(Severity::Low->atLeast(Severity::Unknown));
        $this->assertSame('Medium', Severity::Medium->label());
    }

    public function test_thresholds(): void
    {
        $medium = $this->finding(Severity::Medium);
        $high = $this->finding(Severity::High);
        $exploitedLow = $this->finding(Severity::Low, exploited: true);

        $this->assertFalse(Threshold::Exploited->isMetBy($high));
        $this->assertTrue(Threshold::Exploited->isMetBy($exploitedLow));
        $this->assertTrue(Threshold::High->isMetBy($high));
        $this->assertFalse(Threshold::High->isMetBy($medium));
        $this->assertTrue(Threshold::High->isMetBy($exploitedLow), 'Exploited always counts');
        $this->assertFalse(Threshold::Critical->isMetBy($high));
        $this->assertTrue(Threshold::Medium->isMetBy($medium));
        $this->assertTrue(Threshold::Any->isMetBy($this->finding(Severity::Low)));
        $this->assertSame(Threshold::High, Threshold::parse(' HIGH '));
    }

    public function test_an_unknown_threshold_is_a_typed_exception(): void
    {
        try {
            Threshold::parse('severe');
            $this->fail('No exception');
        } catch (InvalidThreshold $e) {
            $this->assertInstanceOf(SecurityAlertsException::class, $e);
            $this->assertStringContainsString('exploited, critical, high, medium or any', $e->getMessage());
        }
    }

    public function test_ecosystem_labels(): void
    {
        $this->assertSame('Composer', Ecosystem::Composer->label());
        $this->assertSame('npm', Ecosystem::Npm->label());
    }

    private function finding(Severity $severity, bool $exploited = false): Finding
    {
        return new Finding(Ecosystem::Composer, 'acme/thing', '1.0.0', 'PKSA-1', 'A flaw', $severity,
            exploited: $exploited ? new KevEntry('CVE-2026-1', 'Flaw', CarbonImmutable::now()) : null);
    }
}
