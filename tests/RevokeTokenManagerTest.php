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

use Drewlabs\Auth\Jwt\AccessToken;
use Drewlabs\Auth\Jwt\Contracts\RevokeTokenManager;
use Drewlabs\Auth\Jwt\Payload\Claims;
use Drewlabs\Auth\Jwt\RevokedTokens;
use Drewlabs\Auth\Jwt\RevokedTokenStorage;
use Drewlabs\Auth\Jwt\RevokedTokenStorageAdapters;
use Drewlabs\Auth\JwtGuard\Tests\Stubs\PDOAccessTokenRepository;
use PHPUnit\Framework\TestCase;

class RevokeTokenManagerTest extends TestCase
{
    protected function setUp(): void
    {
        $this->addDatabaseAdapter();
    }

    public function test_constructor()
    {
        $this->assertInstanceOf(RevokeTokenManager::class, new RevokedTokens());
    }

    public function test_add_method()
    {
        $blacklist = new RevokedTokens();
        $claims = new Claims('http://127.0.0.1');
        $payload = $claims->toPayload();
        $token = new AccessToken($payload);
        $blacklist->add($token);
        $this->assertTrue($blacklist->has($token));
    }

    public function test_clear_method()
    {
        $blacklist = new RevokedTokens();
        $claims = new Claims('http://127.0.0.1');
        $payload = $claims->toPayload();
        $token = new AccessToken($payload);
        $blacklist->add($token);
        $blacklist->clear();
        $this->assertFalse($blacklist->has($token));
    }

    private function addDatabaseAdapter()
    {
        RevokedTokenStorageAdapters::getInstance()->addAdapter('database', new RevokedTokenStorage(new PDOAccessTokenRepository()));
        // Setting database adapter as default adapter
        RevokedTokenStorageAdapters::getInstance()->default('database');
    }
}
