<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Versions;

class VersionsTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function constraints(): iterable
    {
        yield 'inside a range' => ['3.6.2', '>=3.0.0-beta.1,<3.6.4', true];
        yield 'the fixed release' => ['3.6.4', '>=3.0.0-beta.1,<3.6.4', false];
        yield 'with a v prefix' => ['v3.6.2', '>=3.0.0-beta.1,<3.6.4', true];
        yield 'second alternative' => ['7.15.1', '>=8.0.0,<8.0.1|<7.15.2', true];
        yield 'between alternatives' => ['7.16.0', '>=8.0.0,<8.0.1|<7.15.2', false];
        yield 'last affected, inclusive' => ['2.10.1', '>=2.0.0,<=2.10.1', true];
        yield 'an exact version' => ['2.4.9', '=2.4.9|<=2.4.5-p14', true];
        yield 'a dev branch is never matched' => ['dev-main', '<3.0', false];
        yield 'a dev alias is never matched' => ['1.0.x-dev', '<3.0', false];
        yield 'nonsense never matches' => ['not a version', '<3.0', false];
        yield 'a broken constraint never matches' => ['1.0.0', '<<>>', false];
    }

    #[DataProvider('constraints')]
    public function test_affects(string $version, string $constraint, bool $expected): void
    {
        $this->assertSame($expected, Versions::affects($version, $constraint));
    }

    /**
     * @return iterable<string, array{string, string, string|null}>
     */
    public static function fixes(): iterable
    {
        yield 'upper bound of the range' => ['3.6.2', '>=3.0.0-beta.1,<3.6.4', '3.6.4'];
        yield 'the range the version is in' => ['8.0.0', '>=8.0.0,<8.0.1|<7.15.2', '8.0.1'];
        yield 'the other range' => ['7.9.3', '>=8.0.0,<8.0.1|<7.15.2', '7.15.2'];
        yield 'ranges split by minor version' => ['8.0.5', '>=8.0.0,<8.1.0|>=8.1.0,<8.2.0|>=8.2.0,<8.3.0', '8.3.0'];
        yield 'only the last affected release' => ['2.7.0', '>=2.0.0,<=2.10.1', '>2.10.1'];
        yield 'a v prefix in the bound' => ['1.0.0', '<v1.2.0', '1.2.0'];
        yield 'no upper bound' => ['3.0.0', '>=1.0', null];
        yield 'an exact version' => ['2.4.9', '=2.4.9', null];
        yield 'not affected' => ['4.0.0', '<3.0', null];
    }

    #[DataProvider('fixes')]
    public function test_fixed_in(string $version, string $constraint, ?string $expected): void
    {
        $this->assertSame($expected, Versions::fixedIn($version, $constraint));
    }

    public function test_fixed_in_from_osv_ranges(): void
    {
        $affected = [
            ['package' => ['name' => 'launch-editor', 'ecosystem' => 'npm'], 'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '2.14.1']]]]],
            ['package' => ['name' => 'vite', 'ecosystem' => 'npm'], 'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '8.0.0'], ['fixed' => '8.0.16']]]]],
            ['package' => ['name' => 'vite', 'ecosystem' => 'npm'], 'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '7.0.0'], ['fixed' => '7.3.5']]]]],
            ['package' => ['name' => 'vite', 'ecosystem' => 'npm'], 'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '6.4.3']]]]],
        ];

        $this->assertSame('7.3.5', Versions::fixedInOsv($affected, 'vite', '7.3.2'));
        $this->assertSame('8.0.16', Versions::fixedInOsv($affected, 'vite', '8.0.1'));
        $this->assertSame('6.4.3', Versions::fixedInOsv($affected, 'vite', '5.0.0'));
        $this->assertSame('2.14.1', Versions::fixedInOsv($affected, 'launch-editor', '2.0.0'));
        $this->assertNull(Versions::fixedInOsv($affected, 'vite', '7.3.5'));
        $this->assertNull(Versions::fixedInOsv($affected, 'other', '1.0.0'));
        $this->assertNull(Versions::fixedInOsv([['package' => ['name' => 'a'], 'ranges' => [['type' => 'GIT', 'events' => [['introduced' => '0'], ['fixed' => 'abc123']]]]]], 'a', '1.0.0'));
    }

    public function test_several_ranges_in_one_list_of_events(): void
    {
        $affected = [['package' => ['name' => 'form-data'], 'ranges' => [['type' => 'SEMVER', 'events' => [
            ['introduced' => '0'], ['fixed' => '2.5.4'], ['introduced' => '3.0.0'], ['fixed' => '3.0.4'], ['introduced' => '4.0.0'], ['fixed' => '4.0.4'],
        ]]]]];

        $this->assertSame('4.0.4', Versions::fixedInOsv($affected, 'form-data', '4.0.3'));
        $this->assertSame('3.0.4', Versions::fixedInOsv($affected, 'form-data', '3.0.1'));
        $this->assertSame('2.5.4', Versions::fixedInOsv($affected, 'form-data', '2.3.0'));
    }
}
