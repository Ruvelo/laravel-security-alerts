<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts;

use Ruvelo\SecurityAlerts\Exceptions\InvalidThreshold;

/**
 * When `security-alerts:check --fail-on=...` should exit non-zero.
 */
enum Threshold: string
{
    case Exploited = 'exploited';
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Any = 'any';

    public static function parse(string $value): self
    {
        return self::tryFrom(strtolower(trim($value))) ?? throw InvalidThreshold::for($value);
    }

    public function isMetBy(Finding $finding): bool
    {
        return match ($this) {
            self::Exploited => $finding->isExploited(),
            self::Critical => $finding->isExploited() || $finding->severity->atLeast(Severity::Critical),
            self::High => $finding->isExploited() || $finding->severity->atLeast(Severity::High),
            self::Medium => $finding->isExploited() || $finding->severity->atLeast(Severity::Medium),
            self::Any => true,
        };
    }
}
