<?php

declare(strict_types=1);

use Drewlabs\Auth\Jwt\Factory;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\Jwt\Providers\JWT;
use Drewlabs\Auth\JwtGuard\Guard;
use Drewlabs\Core\Helpers\Str;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;

class GuardTest extends TestCase
{
    /**
     * @var TokenManagerInterface
     */
    private $tokenManager;

    public function test_constructor()
    {
        $this->assertInstanceOf(Guard::class, $this->createGuardInstance());
        $this->assertIsCallable($this->createGuardInstance());
    }

    public function test_invoke_returns_null()
    {
        $guard = $this->createGuardInstance();
        /**
         * @var NewAccessToken
         */
        $accessToken = $this->tokenManager->createToken([
            ClaimTypes::SUBJECT => 10,
            ClaimTypes::SCOPES => ['*'],
        ]);
        $request = new Request();
        $request->headers->set('authorization', "Bearer $accessToken->plainTextToken");
        $user = $guard->__invoke($request);
        $this->assertNull($user);
    }

    public function test_invoke_returns_user()
    {
        $guard = $this->createGuardInstance();
        /**
         * @var NewAccessToken
         */
        $accessToken = $this->tokenManager->createToken([
            ClaimTypes::SUBJECT => 1,
            ClaimTypes::SCOPES => ['*'],
        ]);
        $request = new Request();
        $request->headers->set('authorization', "Bearer $accessToken->plainTextToken");
        $user = $guard->__invoke($request);
        $this->assertInstanceOf(HasApiTokens::class, $user);
    }

    public function test_returns_null_for_invalid_token_payload()
    {
        $jwt = new JWT('HS256', 'secret');
        $plainTextToken = $jwt->encode([
            'name' => 'Azandrew',
            'address' => 'HN 238, LOME',
        ]);
        $guard = new Guard();
        $request = new Request();
        $request->headers->set('authorization', "Bearer $plainTextToken");
        $user = $guard->__invoke($request);
        $this->assertNull($user);
    }


    private function createTokenManager()
    {
        if (null !== $this->tokenManager) {
            return $this->tokenManager;
        }
        $config = [

            'storage' => [
                'revokeTokens' => 'array',
            ],

            'accessToken' => [
                'refreshTTL' => 10000,
                'tokenTTL' => 360,
            ],

            'issuer' => 'DREWLABS SERVICES',

            'use_ssl' => true,

            'encryption' => [
                'default' => [
                    'key' => Str::base62encode(Str::md5())
                ],
            ],
        ];

        return $this->tokenManager = (new Factory)->create($config);
    }

    private function createGuardInstance()
    {
        return new Guard();
    }
}
