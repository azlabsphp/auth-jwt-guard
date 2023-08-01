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

use Drewlabs\Auth\JwtGuard\Exceptions\AuthenticationException;
use Drewlabs\Auth\JwtGuard\Exceptions\MissingScopesException;

class CheckForAnyScope
{
    /**
     * Handle the incoming request.
     *
     * @param mixed    $request
     * @param \Closure $next
     * @param mixed    ...$scopes
     *
     * @throws AuthenticationException|MissingScopesException
     *
     * @return mixed
     */
    public function handle($request, $next, ...$scopes)
    {
        if (!$request->user() || !$request->user()->token()) {
            throw new AuthenticationException();
        }

        foreach ($scopes as $scope) {
            if ($request->user()->tokenCan($scope)) {
                return $next($request);
            }
        }

        throw new MissingScopesException($scopes);
    }
}
