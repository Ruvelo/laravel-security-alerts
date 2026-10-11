<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Exceptions;

use RuntimeException;

/**
 * Every exception the package throws extends this one.
 */
abstract class SecurityAlertsException extends RuntimeException {}
