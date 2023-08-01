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
use Drewlabs\Contracts\OAuth\HasApiTokens;
use Illuminate\Contracts\Auth\UserProvider as AuthUserProvider;

class UserProviderAdapter implements UserProvider
{
    /**
     * @var AuthUserProvider
     */
    private $provider;

    /**
     * Create an instance of authenticatable provider adapter.
     */
    public function __construct(AuthUserProvider $provider)
    {
        $this->provider = $provider;
    }

    public function findById(string $id): ?HasApiTokens
    {
        /**
         * @var HasApiTokens
         */
        $user = $this->provider->retrieveById($id);

        return $user;
    }
}
