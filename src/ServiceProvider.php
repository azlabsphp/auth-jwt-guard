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

use Drewlabs\Auth\Jwt\BearerTokenProvider;
use Drewlabs\Auth\Jwt\Contracts\AccessTokenRepository;
use Drewlabs\Auth\Jwt\Contracts\TokenManagerInterface;
use Drewlabs\Auth\Jwt\Factory;
use Drewlabs\Auth\Jwt\RevokedTokenStorage;
use Drewlabs\Auth\Jwt\RevokedTokenStorageAdapters;
use Drewlabs\Auth\JwtGuard\Console\Commands\KeysCommand;

use function Drewlabs\Auth\JwtGuard\Functions\useAccessTokenRepository;

use Drewlabs\Auth\JwtGuard\Middleware\EnsureRequestsAreStateful;
use Drewlabs\Auth\JwtGuard\Middleware\VerifyCsrfToken;
use Drewlabs\Contracts\Auth\AuthenticatableProvider;
use Drewlabs\Contracts\OAuth\PersonalAccessTokenFactory as AccessTokenFactory;
use Drewlabs\Core\Helpers\Arr;
use Drewlabs\Core\Helpers\Functional;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Http\Kernel;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider as ServiceProviderBase;

class ServiceProvider extends ServiceProviderBase
{
    /**
     * Run providers when application boot.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/database/migrations' => $this->app->basePath('database/migrations'),
        ], 'drewlabs-jwt-migrations');

        // Publish configuration files
        $this->publishes([
            __DIR__ . '/config' => $this->app->basePath('config'),
        ], 'drewlabs-jwt-configs');

        if ($this->app->runningInConsole()) {
            $this->commands([KeysCommand::class]);
        }
        $this->createGuard();
        $this->configureMiddleware();
        $this->provideRoutes();
    }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/config/jwt.php', 'jwt');

        $this->provideForAccessToken();

        $this->provideBearerToken();

        // Register token manager implementation
        $this->provideTokenManager();

        // Provide bindings for middlewares
        $this->provideMiddlewares();
    }


    private function createGuard()
    {
        Auth::resolved(function ($auth) {
            $auth->extend(JwtAuthGlobals::guard(), function ($app) use ($auth) {
                return Functional::tap(
                    $this->createGuardInstance($app, $auth),
                    static function ($guard) use ($app) {
                        $app->refresh('request', $guard, 'setRequest');
                    }
                );
            });
        });
    }

    /**
     * Register request guard.
     *
     * @param mixed $app
     * @param mixed $auth
     *
     * @return Illuminate\Auth\RequestGuard
     */
    private function createGuardInstance($app, $auth)
    {
        return new RequestGuard(new Guard($app[BearerTokenProvider::class], $auth, $app['config']->get('jwt.guard', ['web'])), $app->make('request'));
    }

    private function provideBearerToken()
    {
        $this->app->bind(BearerTokenProvider::class, static function ($app) {
            $config = $app['config'];
            $driver = $config->get('auth.guards.' . (JwtAuthGlobals::guard()) . '.driver');
            $provider = $config->get('auth.providers.' . $driver . '.provider');
            /**
             * @var UserProvider
             */
            $providerInstance = null;
            if ($provider) {
                $providerInstance = $app[$provider];
            } elseif ($app->bound(AuthenticatableProvider::class)) {
                $providerInstance = new AuthenticatableProviderAdapter($app[AuthenticatableProvider::class]);
            } elseif ($app->bound(UserProvider::class)) {
                $providerInstance = new UserProviderAdapter($app[UserProvider::class]);
            }

            return new BearerTokenProvider($app[TokenManagerInterface::class], $providerInstance, $app[AccessTokenRepository::class]);
        });
    }

    private function provideForAccessToken()
    {
        // Bindings for AccessTokenRepository
        $this->app->singleton(AccessTokenRepository::class, static function ($app) {
            return useAccessTokenRepository($app['db.connection']);
        });
        // Define Database Storage as default storage
        RevokedTokenStorageAdapters::getInstance()->addAdapter('database', new RevokedTokenStorage($this->app[AccessTokenRepository::class]));

        // Bindings for PersonalAccessTokenFactory
        $this->app->bind(AccessTokenFactory::class, PersonalAccessTokenFactory::class);
    }

    private function provideTokenManager()
    {
        $this->app->bind(TokenManagerInterface::class, static function ($app) {
            return (new Factory())->create($app['config']['jwt'] ?? []);
        });
    }

    private function provideMiddlewares()
    {
        $this->app->bind(VerifyCsrfToken::class, function ($app) {
            $config = $this->app['config']['jwt']['middleware'] ?? [];

            return new VerifyCsrfToken(
                $app[Encrypter::class],
                $app[TokenManagerInterface::class],
                Arr::except($config['cookies'] ?? [], ['encrypt']),
                static function () use ($app) {
                    return $app->runningInConsole() && $app->runningUnitTests();
                }
            );
        });

        $this->app->bind(EnsureRequestsAreStateful::class, function ($app) {
            $config = $this->app['config']['jwt']['middleware'] ?? [];
            $pipeline = $this->isLumen() ? new \Laravel\Lumen\Routing\Pipeline($app) : new \Illuminate\Routing\Pipeline($app);

            return new EnsureRequestsAreStateful($pipeline, [
                'encrypt_cookies' => $config['cookies']['encrypt'] ?? \Illuminate\Cookie\Middleware\EncryptCookies::class,
                'verify_csrf_token' => $config['verify_csrf_token'] ?? VerifyCsrfToken::class,
                'stateful' => $config['stateful'] ?? [],
            ]);
        });
    }

    /**
     * Configure the Sanctum middleware and priority.
     *
     * @return void
     */
    private function configureMiddleware()
    {
        if (!$this->isLumen()) {
            $kernel = $this->app->make(Kernel::class);
            $kernel->prependToMiddlewarePriority(EnsureRequestsAreStateful::class);
        }
    }

    /**
     * Provides application route fot csrf-token.
     *
     * @return Illuminate\Routing\Router|void
     */
    private function provideRoutes()
    {
        if ($this->isLumen()) {
            return Route::group(['prefix' => $this->app['config']->get('jwt.prefix', 'jwt')], static function () {
                Route::get(
                    '/csrf-cookie',
                    static function (Request $request) {
                        return $request->expectsJson() ? new JsonResponse(null, 204) : new Response('', 204);
                    }
                );
            });
        }
        Route::group(['prefix' => $this->app['config']->get('jwt.prefix', 'jwt')], static function () {
            Route::get(
                '/csrf-cookie',
                static function (Request $request) {
                    return $request->expectsJson() ? new JsonResponse(null, 204) : new Response('', 204);
                }
            );
        })->middleware('web');
    }

    /**
     * Checks if the framework on which library is run is laravel/lumen.
     *
     * @return bool
     */
    private function isLumen()
    {
        return ("Laravel\Lumen\Application" === \get_class($this->app)) && preg_match('/(5\.[5-8]\..*)|(6\..*)|(7\..*)|(8\..*)|(9\..*)|(10\..*)/', $this->app->version());
    }
}
