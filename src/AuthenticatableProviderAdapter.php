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

use Drewlabs\Auth\Jwt\Contracts\UserProvider;
use Drewlabs\Contracts\Auth\AuthenticatableProvider;
use Drewlabs\Contracts\OAuth\HasApiTokens;

class AuthenticatableProviderAdapter implements UserProvider
{
    /**
     * @var AuthenticatableProvider
     */
    private $provider;

    /**
     * Create an instance of authenticatable provider adapter.
     */
    public function __construct(AuthenticatableProvider $provider)
    {
        $this->provider = $provider;
    }

    public function findById(string $id): ?HasApiTokens
    {
        /**
         * @var HasApiTokens
         */
        $user = $this->provider->findById($id);

        return $user;
    }
}
