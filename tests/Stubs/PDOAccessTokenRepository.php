<?php

namespace Drewlabs\Auth\JwtGuard\Tests;

use Drewlabs\Auth\Jwt\AccessToken;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenEntity;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenRepository;
use Drewlabs\Auth\Jwt\Contracts\LastUsedStateAware;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\JwtGuard\JwtAuthGlobals;

class PDOAccessTokenRepository implements AccessTokenRepository
{
    /**
     * @var PDOAdapter
     */
    private $pdo;

    /**
     * Creates pdo access token repository class instance
     * 
     * @param PDOAdapter $pdo 
     * @return void 
     */
    public function __construct()
    {
        $this->pdo = new PDOAdapter('sqlite:memory');
        $sql = '
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scopes TEXT NOT NULL,
                sub TEXT NULL,
                issuer TEXT NOT NULL,
                jti TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                issued_at DATETIME NOT NULL,
                revoked INTEGER DEFAULT 0,
                last_used_at DATETIME NULL,
                created_at DATETIME NULL,
                updated_at DATETIME NULL
            )
        ';
        
        // Create database at initialization
        $this->pdo->rawSql($sql);
    }

    /**
     * Save the personal access token details to disk.
     *
     * @return mixed
     */
    public function persist(AccessTokenEntity $entity)
    {
        $last_used_at = $entity instanceof LastUsedStateAware ? $entity->lastUsedAt() : null;
        $this->pdo->table('oauth_tokens')->create([
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
        return $this->pdo->table('oauth_tokens')->delete(['revoked' => 1]);
    }

    /**
     * Query a personnal access token by it jit.
     *
     * @param string $id
     *
     * @return AccessTokenEntity|null
     */
    public function findById($id)
    {
        // Return the token matching provided jit
        $value = $this->pdo->table('oauth_tokens')->selectOne(
            ['jti' => $id],
            ['scopes', 'sub', 'jti', 'expires_at', 'revoked', 'issued_at', 'issuer']
        );
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
}
