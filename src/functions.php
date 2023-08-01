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

namespace Drewlabs\Auth\JwtGuard\Functions;

use Drewlabs\Auth\Jwt\AccessToken;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenEntity;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenRepository;
use Drewlabs\Auth\Jwt\Contracts\LastUsedStateAware;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\JwtGuard\JwtAuthGlobals;

/**
 * Resolve an instance of {@see AccessTokenRepository} class.
 *
 * @param Illuminate\Database\ConnectionInterface|mixed $connection
 *
 * @return AccessTokenRepository
 */
function useAccessTokenRepository($connection)
{
    $object = new class() implements AccessTokenRepository {
        /**
         * @var mixed
         */
        private $connection;

        /**
         * @param mixed $connection
         *
         * @return self
         */
        public function setConnection($connection)
        {
            $this->connection = $connection;

            return $this;
        }

        /**
         * Save the personal access token details to disk.
         *
         * @return mixed
         */
        public function persist(AccessTokenEntity $entity)
        {
            $last_used_at = $entity instanceof LastUsedStateAware ? $entity->lastUsedAt() : null;
            $this->connection->table('oauth_tokens')->insert([
                'scopes' => json_encode($entity->abilities() ?? []),
                'sub' => $entity->subject(),
                'jti' => $entity->id(),
                'expires_at' => \is_string($expires_at = $entity->expiresAt()) ?
                    $expires_at :
                    $expires_at->format(JwtAuthGlobals::getDBDateFormat() ?? 'Y-m-d H:i:s'),
                'revoked' => $entity->revoked() ?? false,
                'issued_at' => \is_string($issued_at = $entity->issuedAt()) ?
                    $issued_at :
                    $issued_at->format(JwtAuthGlobals::getDBDateFormat() ?? 'Y-m-d H:i:s'),
                'issuer' => $entity->issuer(),
                'last_used_at' => null === $last_used_at ?
                    $last_used_at : (\is_string($last_used_at) ?
                        $last_used_at :
                        $last_used_at->format(JwtAuthGlobals::getDBDateFormat() ?? 'Y-m-d H:i:s')),
            ]);
        }

        /**
         * Removes all revoked tokens from the storage.
         *
         * @return bool|void
         */
        public function prune()
        {
            return $this->connection->table('oauth_tokens')->where('revoked', true)->delete();
        }

        /**
         * Query a personnal access token by it jit.
         *
         * @param string $id
         *
         * @return AccessTokenEntity|null
         */
        public function get($id)
        {
            // Return the token matching provided jit
            $value = $this->connection->table('oauth_tokens')->where('jti', $id)->first([
                'scopes',
                'sub',
                'jti',
                'expires_at',
                'revoked',
                'issued_at',
                'issuer',
            ]);
            if (null === $value) {
                return null;
            }
            $value = (object) $value;
            $accessToken = new AccessToken([
                ClaimTypes::SCOPES => json_decode($value->scopes, true),
                ClaimTypes::SUBJECT => $value->sub,
                ClaimTypes::JIT => $value->jti,
                ClaimTypes::EXPIRATION => new \DateTimeImmutable($value->expires_at),
                ClaimTypes::ISSUE_AT => new \DateTimeImmutable($value->issued_at),
                ClaimTypes::ISSUER => $value->issuer,
            ]);

            if ((bool) $value->revoked) {
                $accessToken->markAsRevoked();
            }
            if ($accessToken instanceof LastUsedStateAware && property_exists($value, 'last_used_at')) {
                $accessToken->lastUsedAt($value->last_used_at);
            }

            return $accessToken;
        }
    };

    return $object->setConnection($connection);
}
