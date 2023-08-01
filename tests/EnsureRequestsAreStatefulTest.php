<?php

declare(strict_types=1);

use Drewlabs\Auth\Jwt\Factory;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\JwtGuard\Middleware\EnsureRequestsAreStateful;
use Drewlabs\Auth\JwtGuard\Middleware\VerifyCsrfToken;
use Drewlabs\Core\Helpers\Str;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Pipeline\Pipeline;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use PHPUnit\Framework\TestCase;

class EnsureRequestsAreStatefulTest extends TestCase
{
    /**
     * @var TokenManagerInterface
     */
    private $tokenManager;

    public function test_constructor()
    {
        $this->assertInstanceOf(EnsureRequestsAreStateful::class, $this->createMiddleware());
    }

    public function test_ensure_stateless_request_invoke()
    {
        $middleware = $this->createMiddleware();
        $accessToken = $this->tokenManager->createToken([
            ClaimTypes::SUBJECT => 1,
        ]);
        $request = new Request();
        $request->setMethod('POST');
        $request->headers->set('authorization', "Bearer $accessToken->plainTextToken");
        $response = $middleware->__invoke($request, function () {
            return new Response();
        });
        $this->assertInstanceOf(Response::class, $response);
    }

    public function test_ensure_stateful_request_invoke()
    {
        $middleware = $this->createMiddleware();
        $accessToken = $this->tokenManager->createToken([
            ClaimTypes::SUBJECT => 1,
        ]);
        $request = new Request();
        $request->setMethod('POST');
        $request->headers->set('authorization', "Bearer $accessToken->plainTextToken");
        $request->headers->set('referer', 'https://safepay.ayael-entreprise.com');
        $this->assertInstanceOf(Response::class, $middleware->__invoke($request, static function () {
            return new Response();
        }));
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

    private function createCSRFMiddleware(bool $testing = true)
    {
        $encrypter = $this->createMock(Encrypter::class);
        return new VerifyCsrfToken(
            $encrypter,
            $this->createTokenManager(),
            [
                'path' => '/',
                'domain' => 'http://127.0.0.1',
                'secure' => true,
                'http_only' => true,
                'lifetime' => 1440,
                'same_site' => 'Lax',
            ],
            static function () use ($testing) {
                return $testing;
            }
        );
    }

    private function createMiddleware()
    {
        $pipeline = $this->createMock(Pipeline::class);
        return new EnsureRequestsAreStateful($pipeline, [
            'encrypt_cookies' => \Illuminate\Cookie\Middleware\EncryptCookies::class,
            'verify_csrf_token' => $this->createCSRFMiddleware(),
            'stateful' => [
                'safepay.ayael-entreprise.com',
            ],
        ]);
    }
}
