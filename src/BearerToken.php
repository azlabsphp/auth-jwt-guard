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

namespace Drewlabs\Auth\JwtGuard;

use Drewlabs\Auth\Jwt\Exceptions\MissingTokenException;
use Drewlabs\Core\Helpers\Str;

class BearerToken
{
    /**
     * @var string
     */
    private $value;

    /**
     * Creates bearer token class instance.
     *
     * @return void
     */
    public function __construct(string $value)
    {
        $this->value = $value;
    }

    /**
     * Returns the string representation of the bearer token.
     */
    public function __toString(): string
    {
        return $this->value;
    }

    /**
     * Read bearer token from Psr7 or symfony or laravel request.
     *
     * @param \Illuminate\Http\Request|\Symfony\Component\HttpFoundation\Request $request
     *
     * @return static
     */
    public static function fromRequest($request)
    {
        $bearerToken = static::getBearerTokenRequest($request);
        if (!\is_string($bearerToken)) {
            throw new MissingTokenException('Bearer token not found in request');
        }

        return new static($bearerToken);
    }

    /**
     * @param \Illuminate\Http\Request|\Symfony\Component\HttpFoundation\Request $request
     *
     * @return string|null
     */
    private static function getBearerTokenRequest($request, $header = 'authorization', $method = 'bearer', $query = 'token')
    {
        $value = $request->headers->get($header ?? 'Authorization', '');
        if (Str::startsWith(strtolower($value), $method)) {
            return trim(str_ireplace($method ?? 'bearer', '', $value));
        }

        return static::getFromRequestBody($request, $query);
    }

    /**
     * @param \Illuminate\Http\Request|\Symfony\Component\HttpFoundation\Request $request
     *
     * @return string|null
     */
    private static function getFromRequestBody($request, $query = 'token')
    {
        return $request->get($query) ?? null;
    }
}
