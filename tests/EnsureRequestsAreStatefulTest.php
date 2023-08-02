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
use Drewlabs\Auth\Jwt\Contracts\TokenManagerInterface;
use Drewlabs\Auth\Jwt\Payload\ClaimTypes;
use Drewlabs\Auth\JwtGuard\Middleware\EnsureRequestsAreStateful;
use Drewlabs\Auth\JwtGuard\Middleware\VerifyCsrfToken;
use Drewlabs\Auth\JwtGuard\Tests\Stubs\Pipeline as StubsPipeline;
use Drewlabs\Core\Helpers\Str;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class EnsureRequestsAreStatefulTest extends TestCase
{
    public function test_constructor()
    {
        $this->assertInstanceOf(EnsureRequestsAreStateful::class, $this->createMiddleware());
    }

    public function test_ensure_stateless_request_invoke()
    {
        $csrfToken = Str::md5();
        $middleware = $this->createMiddleware($csrfToken);
        $request = new Request();
        $request->setMethod('POST');
        $request->headers->set('X-CSRF-TOKEN', $csrfToken);
        $request->headers->set('authorization', "Bearer $csrfToken");
        $this->assertInstanceOf(Response::class, $middleware->__invoke($request, static function () {
            return new Response();
        }));
    }

    public function test_ensure_stateful_request_invoke()
    {
        $csrfToken = Str::md5();
        $middleware = $this->createMiddleware($csrfToken);
        $request = new Request();
        $request->setMethod('POST');
        $request->headers->set('X-CSRF-TOKEN', $csrfToken);
        $request->headers->set('authorization', "Bearer $csrfToken");
        $request->headers->set('referer', 'https://safepay.ayael-entreprise.com');
        $this->assertInstanceOf(Response::class, $middleware->__invoke($request, static function () {
            return new Response();
        }));
    }

    private function createMiddleware(string $csrfToken = null)
    {
        /**
         * @var Encrypter&MockObject
         */
        $encrypter = $this->createMock(Encrypter::class);

        // Mock Encrypter decrypt method
        $encrypter->method('decrypt')
            ->willReturn($csrfToken);

        /**
         * @var TokenManagerInterface&MockObject
         */
        $tokenManager = $this->createMock(TokenManagerInterface::class);

        $tokenManager->method('decodeToken')
            ->willReturn(new AccessToken([
                ClaimTypes::XCSRF => $csrfToken,
            ]));

        return new EnsureRequestsAreStateful(new StubsPipeline(), [
            'encrypt_cookies' => static function ($request, $next) {
                return $next($request);
            },
            'verify_csrf_token' => static function ($request, $next) use ($encrypter, $tokenManager) {
                $middleware = new VerifyCsrfToken(
                    $encrypter,
                    $tokenManager,
                    [
                        'path' => '/',
                        'domain' => 'http://127.0.0.1',
                        'secure' => true,
                        'http_only' => true,
                        'lifetime' => 1440,
                        'same_site' => 'Lax',
                    ],
                    static function () {
                        return true;
                    }
                );

                return $middleware->handle($request, $next);
            },
            'stateful' => [
                'safepay.ayael-entreprise.com',
            ],
        ]);
    }
}
