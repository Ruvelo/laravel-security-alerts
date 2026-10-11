<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Ecosystem;
use Ruvelo\SecurityAlerts\Exceptions\LockfileUnreadable;
use Ruvelo\SecurityAlerts\Exceptions\SecurityAlertsException;
use Ruvelo\SecurityAlerts\Lockfiles\ComposerLock;
use Ruvelo\SecurityAlerts\Lockfiles\NpmLock;
use Ruvelo\SecurityAlerts\Package;

class LockfilesTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../fixtures';

    public function test_composer_production_packages_by_default(): void
    {
        $packages = ComposerLock::read(self::FIXTURES.'/composer.lock');

        $this->assertNotNull($packages);
        $this->assertCount(67, $packages);
        $livewire = $this->find($packages, 'livewire/livewire');
        $this->assertSame('3.6.2', $livewire->version, 'The v prefix is dropped');
        $this->assertSame(Ecosystem::Composer, $livewire->ecosystem);
        $this->assertFalse($livewire->dev);
        $this->assertNull($this->find($packages, 'phpunit/phpunit', false));
    }

    public function test_composer_dev_packages_when_asked(): void
    {
        $packages = ComposerLock::read(self::FIXTURES.'/composer.lock', includeDev: true);

        $this->assertCount(73, (array) $packages);
        $this->assertTrue($this->find((array) $packages, 'phpunit/phpunit')->dev);
    }

    public function test_a_missing_lockfile_is_null(): void
    {
        $this->assertNull(ComposerLock::read('/nowhere/composer.lock'));
        $this->assertNull(NpmLock::read('/nowhere/package-lock.json'));
    }

    public function test_a_broken_lockfile_is_a_typed_exception(): void
    {
        $path = $this->write('{"packages": [');

        try {
            ComposerLock::read($path);
            $this->fail('No exception');
        } catch (LockfileUnreadable $e) {
            $this->assertInstanceOf(SecurityAlertsException::class, $e);
            $this->assertStringContainsString('isn\'t valid JSON', $e->getMessage());
        }

        $this->expectException(LockfileUnreadable::class);
        $this->expectExceptionMessage('no "packages" list');
        ComposerLock::read($this->write('{"content-hash": "x"}'));
    }

    public function test_composer_skips_malformed_entries(): void
    {
        $packages = ComposerLock::read($this->write(json_encode(['packages' => [
            ['name' => 'Acme/Thing', 'version' => '1.0.0'],
            ['name' => 'acme/no-version'],
            'nonsense',
        ]])));

        $this->assertEquals([new Package(Ecosystem::Composer, 'acme/thing', '1.0.0')], $packages);
    }

    public function test_npm_v3_with_dev_flags(): void
    {
        $packages = (array) NpmLock::read(self::FIXTURES.'/package-lock.json');

        $this->assertCount(38, $packages);
        $this->assertTrue($this->find($packages, 'vite')->dev);
        $this->assertFalse($this->find($packages, 'chart.js')->dev);
        $this->assertSame('4.2.0', $this->find($packages, '@tailwindcss/vite')->version);

        $production = (array) NpmLock::read(self::FIXTURES.'/package-lock.json', includeDev: false);
        $this->assertSame(['chart.js', '@kurkle/color', 'dayjs'], array_map(fn (Package $p) => $p->name, $production));
    }

    public function test_npm_nested_copies_links_and_workspaces(): void
    {
        $packages = NpmLock::read($this->write(json_encode(['lockfileVersion' => 3, 'packages' => [
            '' => ['name' => 'app', 'version' => '1.0.0'],
            'node_modules/a' => ['version' => '1.0.0', 'dev' => true],
            'node_modules/b/node_modules/a' => ['version' => '1.0.0'],
            'node_modules/b/node_modules/@scope/c' => ['version' => '2.0.0'],
            'node_modules/aliased' => ['name' => 'real-name', 'version' => '3.0.0'],
            'node_modules/linked' => ['resolved' => 'packages/linked', 'link' => true],
            'packages/linked' => ['name' => 'linked', 'version' => '0.1.0'],
            'node_modules/no-version' => [],
        ]])));

        $this->assertEquals([
            new Package(Ecosystem::Npm, 'a', '1.0.0', dev: false),
            new Package(Ecosystem::Npm, '@scope/c', '2.0.0'),
            new Package(Ecosystem::Npm, 'real-name', '3.0.0'),
        ], $packages, 'One copy per version, production if any copy is; workspaces and links left out');
    }

    public function test_npm_v1_nested_dependencies(): void
    {
        $packages = NpmLock::read($this->write(json_encode(['lockfileVersion' => 1, 'dependencies' => [
            'axios' => ['version' => '0.21.0', 'dev' => true, 'dependencies' => [
                'follow-redirects' => ['version' => '1.13.0', 'dev' => true],
            ]],
            'local' => ['version' => 'file:../local'],
        ]])));

        $this->assertEquals([
            new Package(Ecosystem::Npm, 'axios', '0.21.0', true),
            new Package(Ecosystem::Npm, 'follow-redirects', '1.13.0', true),
        ], $packages);
    }

    public function test_npm_without_packages_is_unreadable(): void
    {
        $this->expectException(LockfileUnreadable::class);

        NpmLock::read($this->write('{"name": "app"}'));
    }

    private function write(string|false $contents): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'lock');
        file_put_contents($path, (string) $contents);

        return $path;
    }

    /**
     * @param  list<Package>  $packages
     */
    private function find(array $packages, string $name, bool $required = true): ?Package
    {
        foreach ($packages as $package) {
            if ($package->name === $name) {
                return $package;
            }
        }

        $this->assertFalse($required, "{$name} not found");

        return null;
    }
}
