<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\KevEntry;
use Ruvelo\SecurityAlerts\Package;
use Ruvelo\SecurityAlerts\Severity;
use Ruvelo\SecurityAlerts\Sources\Osv;
use Ruvelo\SecurityAlerts\Sources\Packagist;

class AdvisoriesTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../fixtures';

    public function test_a_packagist_advisory(): void
    {
        $advisory = Packagist::advisory('livewire/livewire', [
            'advisoryId' => 'PKSA-g5js-3ypd-k2kr',
            'packageName' => 'livewire/livewire',
            'title' => 'Livewire is vulnerable to remote command execution',
            'link' => 'https://github.com/advisories/GHSA-29cq-5w36-x7w3',
            'cve' => 'cve-2025-54068',
            'affectedVersions' => '>=3.0.0-beta.1,<3.6.4',
            'severity' => 'critical',
            'reportedAt' => '2025-07-17 20:26:45',
        ]);

        $this->assertNotNull($advisory);
        $this->assertSame('PKSA-g5js-3ypd-k2kr', $advisory->id);
        $this->assertSame(Ecosystem::Composer, $advisory->ecosystem);
        $this->assertSame('CVE-2025-54068', $advisory->cve);
        $this->assertSame(Severity::Critical, $advisory->severity);
        $this->assertSame('>=3.0.0-beta.1,<3.6.4', $advisory->affectedVersions);
        $this->assertSame('2025-07-17 20:26:45', $advisory->reportedAt);
    }

    public function test_packagist_gaps_and_repeated_cves(): void
    {
        $advisory = Packagist::advisory('symfony/http-foundation', [
            'advisoryId' => 'PKSA-1', 'affectedVersions' => '<7.4.13', 'title' => 'CVE-2026-48736: IpUtils omits IPv6 forms',
            'cve' => 'CVE-2026-48736', 'severity' => null, 'link' => '',
        ]);

        $this->assertSame('IpUtils omits IPv6 forms', $advisory?->title);
        $this->assertSame(Severity::Unknown, $advisory?->severity);
        $this->assertNull($advisory?->link);

        $this->assertSame('PKSA-2', Packagist::advisory('a/b', ['advisoryId' => 'PKSA-2', 'affectedVersions' => '<1', 'cve' => 'GHSA-xxxx'])?->title);
        $this->assertNull(Packagist::advisory('a/b', ['advisoryId' => 'PKSA-2', 'affectedVersions' => '<1', 'cve' => 'GHSA-xxxx'])?->cve);
        $this->assertNull(Packagist::advisory('a/b', ['advisoryId' => 'PKSA-3']), 'No constraint, no advisory');
        $this->assertNull(Packagist::advisory('a/b', 'nonsense'));
    }

    public function test_an_osv_record(): void
    {
        $vuln = json_decode((string) file_get_contents(self::FIXTURES.'/osv/GHSA-v6wh-96g9-6wx3.json'), true);
        $advisory = Osv::advisory($vuln, new Package(Ecosystem::Npm, 'vite', '7.3.2', true));

        $this->assertSame('GHSA-v6wh-96g9-6wx3', $advisory->id);
        $this->assertSame(Ecosystem::Npm, $advisory->ecosystem);
        $this->assertSame('vite', $advisory->package);
        $this->assertSame('CVE-2026-53632', $advisory->cve);
        $this->assertSame(Severity::Medium, $advisory->severity, 'MODERATE is medium');
        $this->assertSame('https://github.com/advisories/GHSA-v6wh-96g9-6wx3', $advisory->link);
        $this->assertSame('7.3.5', $advisory->fixedIn);
        $this->assertNull($advisory->affectedVersions);
    }

    public function test_an_osv_record_without_ghsa_or_summary(): void
    {
        $advisory = Osv::advisory(['id' => 'MAL-2026-1', 'aliases' => []], new Package(Ecosystem::Npm, 'evil', '1.0.0'));

        $this->assertSame('MAL-2026-1', $advisory->title);
        $this->assertSame('https://osv.dev/vulnerability/MAL-2026-1', $advisory->link);
        $this->assertNull($advisory->cve);
        $this->assertSame(Severity::Unknown, $advisory->severity);
        $this->assertNull($advisory->fixedIn);
    }

    public function test_kev_entries(): void
    {
        $entry = KevEntry::fromCatalogue([
            'cveID' => 'CVE-2021-3129', 'vulnerabilityName' => ' Laravel Ignition File Upload Vulnerability ',
            'dateAdded' => '2023-09-18', 'dueDate' => '2023-10-09', 'knownRansomwareCampaignUse' => 'Known',
        ]);

        $this->assertNotNull($entry);
        $this->assertSame('Laravel Ignition File Upload Vulnerability', $entry->name);
        $this->assertSame('2023-09-18', $entry->dateAdded->toDateString());
        $this->assertSame('2023-10-09', $entry->dueDate?->toDateString());
        $this->assertTrue($entry->ransomware);
        $this->assertEquals($entry, KevEntry::fromArray($entry->toArray()));

        $this->assertNull(KevEntry::fromCatalogue(['cveID' => 'CVE-1']));
        $this->assertNull(KevEntry::fromCatalogue(['cveID' => 'CVE-1', 'dateAdded' => 'yesterday']));
        $this->assertNull(KevEntry::fromCatalogue(['cveID' => 'CVE-1', 'dateAdded' => '2026-01-01', 'dueDate' => 'soon'])?->dueDate);
    }
}
