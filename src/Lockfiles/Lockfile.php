<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Lockfiles;

use JsonException;
use Ruvelo\SecurityAlerts\Exceptions\LockfileUnreadable;

/**
 * @internal
 */
final class Lockfile
{
    /**
     * @return array<mixed>|null Null when the file doesn't exist
     *
     * @throws LockfileUnreadable
     */
    public static function json(string $path): ?array
    {
        if (! is_file($path)) {
            return null;
        }

        $contents = @file_get_contents($path);

        if ($contents === false) {
            throw LockfileUnreadable::at($path, 'it isn\'t readable');
        }

        try {
            $data = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw LockfileUnreadable::at($path, 'it isn\'t valid JSON ('.$e->getMessage().')');
        }

        if (! is_array($data)) {
            throw LockfileUnreadable::at($path, 'it doesn\'t hold a JSON object');
        }

        return $data;
    }
}
