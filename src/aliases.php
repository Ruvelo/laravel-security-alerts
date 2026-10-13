<?php

declare(strict_types=1);

/*
 * 1.0 kept its own copies of these classes. They moved to ruvelo/security-advisories
 * in 1.1; the old names keep resolving, loaded only when something asks for them.
 * Severity::Unknown is now Severity::NotRated.
 */
spl_autoload_register(static function (string $class): void {
    static $moved = [
        'Ruvelo\SecurityAlerts\Ecosystem' => 'Ruvelo\SecurityAdvisories\Ecosystem',
        'Ruvelo\SecurityAlerts\Finding' => 'Ruvelo\SecurityAdvisories\Finding',
        'Ruvelo\SecurityAlerts\KevEntry' => 'Ruvelo\SecurityAdvisories\KevEntry',
        'Ruvelo\SecurityAlerts\Report' => 'Ruvelo\SecurityAdvisories\Report',
        'Ruvelo\SecurityAlerts\Severity' => 'Ruvelo\SecurityAdvisories\Severity',
        'Ruvelo\SecurityAlerts\Threshold' => 'Ruvelo\SecurityAdvisories\Threshold',
        'Ruvelo\SecurityAlerts\Exceptions\InvalidThreshold' => 'Ruvelo\SecurityAdvisories\Exceptions\InvalidThreshold',
        'Ruvelo\SecurityAlerts\Exceptions\SourceUnavailable' => 'Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable',
        'Ruvelo\SecurityAlerts\Exceptions\LockfileUnreadable' => 'Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable',
    ];

    if (isset($moved[$class])) {
        class_alias($moved[$class], $class);
    }
});
