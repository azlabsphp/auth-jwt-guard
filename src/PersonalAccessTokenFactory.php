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

use Drewlabs\Auth\Jwt\Contracts\AccessTokenRepository;
use Drewlabs\Auth\Jwt\Contracts\TokenManagerInterface;
use Drewlabs\Auth\Jwt\NewAccessToken;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Contracts\OAuth\PersonalAccessTokenFactory as AccessTokenFactory;
use Drewlabs\Core\Helpers\Functional;

class PersonalAccessTokenFactory implements AccessTokenFactory
{
    /**
     * @var TokenManagerInterface
     */
    private $manager;

    /**
     * @var AccessTokenRepository|null
     */
    private $repository;

    /**
     * Creates factory class instance.
     *
     * @return void
     */
    public function __construct(TokenManagerInterface $manager, AccessTokenRepository $repository = null)
    {
        $this->manager = $manager;
        $this->repository = $repository;
    }

    public function make($user, $name, array $scopes = [])
    {
        // Call a functional Tap method that write the token details to the storage
        Functional::tap(
            $token = $this->manager->createToken([ClaimTypes::SUBJECT => $user, ClaimTypes::SCOPES => $scopes]),
            function (NewAccessToken $token) {
                if ($this->repository) {
                    $this->repository->persist($token->accessToken);
                }
            }
        );

        return $token;
    }
}
