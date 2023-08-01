<?php

declare(strict_types=1);

/*
 * This file is part of the drewlabs namespace.
 *
 * (c) Sidoine Azandrew <azandrewdevelopper@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Drewlabs\Auth\JwtGuard\Exceptions;

use Exception;

class AuthenticationException extends \Exception
{
    /**
     * Creates authentication exception instance.
     */
    public function __construct(string $message = null)
    {
        parent::__construct($message ?? 'UnAuthenticated.', 401);
    }
}
