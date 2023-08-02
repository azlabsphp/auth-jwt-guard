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

use Drewlabs\Auth\Jwt\Contracts\TokenProvider;
use Drewlabs\Auth\JwtGuard\Guard;
use Drewlabs\Core\Helpers\Str;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Guard as AuthGuard;
use Illuminate\Http\Request;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class GuardTest extends TestCase
{
    /**
     * @var TokenManagerInterface
     */
    private $tokenManager;

    public function test_constructor()
    {
        $tokenProvider = $this->createMock(TokenProvider::class);
        $guard = new Guard($tokenProvider);
        $this->assertInstanceOf(Guard::class, $guard);
        $this->assertIsCallable($guard);
    }

    public function test_guard_invoke_returns_null_if_token_was_not_provided_in_the_request()
    {
        /**
         * @var TokenProvider&MockObject
         */
        $tokenProvider = $this->createMock(TokenProvider::class);
        $guard = new Guard($tokenProvider);

        $request = new Request();
        $user = $guard->__invoke($request);
        $this->assertNull($user);
    }

    public function test_guard_invoke_returns_return_value_of_token_provider_if_request_has_bearer_token()
    {
        // Initialize
        /**
         * @var TokenProvider&MockObject
         */
        $tokenProvider = $this->createMock(TokenProvider::class);
        $user = new stdClass();
        $tokenProvider->method('findByBearerToken')
            ->willReturn($user);

        $guard = new Guard($tokenProvider);
        $plainTextToken = Str::md5();

        // Act
        $request = new Request();
        $request->headers->set('authorization', "Bearer $plainTextToken");
        $result = $guard->__invoke($request);

        // Assert
        $this->assertSame($user, $result);
    }

    public function test_guard_invoke_calls_token_provider_once_with_authorization_token()
    {
        // Initialize
        $plainTextToken = Str::md5();
        /**
         * @var TokenProvider&MockObject
         */
        $tokenProvider = $this->createMock(TokenProvider::class);

        // Assert
        $tokenProvider->expects($this->once())
            ->method('findByBearerToken')
            ->with($plainTextToken)
            ->willReturn(new \stdClass());

        $guard = new Guard($tokenProvider);

        // Act
        $request = new Request();
        $request->headers->set('authorization', "Bearer $plainTextToken");
        $guard->__invoke($request);
    }

    public function test_guard_invoke_call_factory_guard_and_guards_user_method_if_auth_factory_is_provided_as_parameter_to_constructor()
    {
        // Initialize
        /**
         * @var TokenProvider&MockObject
         */
        $tokenProvider = $this->createMock(TokenProvider::class);
        /**
         * @var AuthFactory&MockObject
         */
        $authFactory = $this->createMock(AuthFactory::class);

        /**
         * @var AuthGuard&MockObject
         */
        $authGuard = $this->createMock(AuthGuard::class);

        // Assert
        $authGuard->expects($this->once())
            ->method('user')
            ->willReturn(null);

        $authFactory->expects($this->once())
            ->method('guard')
            ->with('web')
            ->willReturn($authGuard);

        $guard = new Guard($tokenProvider, $authFactory);

        // Act
        $guard->__invoke(new Request());
    }

    public function test_guard_invoke_call_guard_multiple_times_with_provided_guards_passed_as_parameter()
    {

        // Initialize
        /**
         * @var TokenProvider&MockObject
         */
        $tokenProvider = $this->createMock(TokenProvider::class);
        /**
         * @var AuthFactory&MockObject
         */
        $authFactory = $this->createMock(AuthFactory::class);

        /**
         * @var AuthGuard&MockObject
         */
        $authGuard = $this->createMock(AuthGuard::class);

        // Assert
        $authGuard->method('user')
            ->willReturn(null);

        $authFactory->expects($this->exactly(2))
            ->method('guard')
            ->willReturn($authGuard);

        $guard = new Guard($tokenProvider, $authFactory, ['http', 'api']);

        // Act
        $guard->__invoke(new Request());
    }
}
