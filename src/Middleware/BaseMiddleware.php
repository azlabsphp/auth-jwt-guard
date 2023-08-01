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

namespace Drewlabs\Auth\JwtGuard\Middleware;

use Psr\Http\Message\ServerRequestInterface;

abstract class BaseMiddleware
{
    /**
     * @param \Illuminate\Http\Request|ServerRequestInterface $request
     * @param mixed                                           $default
     *
     * @return string
     */
    protected function getRequestHeader($request, string $name, $default = null)
    {
        return $request->headers->get($name, $default);
    }

    /**
     * @param \Illuminate\Http\Request $request
     * @param mixed                    $default
     *
     * @return string
     */
    protected function getRequestCookie($request, string $name, $default = null)
    {
        return $request->cookies->get($name, $default);
    }
}
