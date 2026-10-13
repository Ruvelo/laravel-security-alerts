<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Models;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use Ruvelo\SecurityAdvisories\Severity;

/**
 * 1.0 stored an unrated advisory as "unknown", and the table keeps doing so
 * (a downgrade still reads it). The core calls it NotRated.
 *
 * @implements CastsAttributes<Severity, Severity>
 */
class StoredSeverity implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): Severity
    {
        return is_string($value) && $value === 'unknown' ? Severity::NotRated : Severity::tryFrom((string) $value) ?? Severity::NotRated;
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): string
    {
        $severity = $value instanceof Severity ? $value : Severity::parse(is_string($value) ? $value : null);

        return $severity === Severity::NotRated ? 'unknown' : $severity->value;
    }
}
