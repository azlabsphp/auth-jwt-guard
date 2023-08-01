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

return [

    'storage' => [
        'revokeTokens' => 'database',
    ],

    'accessToken' => [
        'refreshTTL' => 20160,
        'tokenTTL' => 1440,
    ],

    'issuer' => env(
        'APP_NAME',
        'http://127.0.0.1'
    ),

    'use_ssl' => true,

    /*
    |--------------------------------------------------------------------------
    | Sanctum Guards
    |--------------------------------------------------------------------------
    |
    | This array contains the authentication guards that will be checked when
    | Sanctum is trying to authenticate a request. If none of these guards
    | are able to authenticate the request, Sanctum will use the bearer
    | token that's present on an incoming request for authentication.
    |
    */
    'guard' => [],

    'encryption' => [
        'useSSL' => false,
        /*
        |----------------------------------------------------
        | Private key used in asymmetric encryption algorithm
        |----------------------------------------------------
        */
        'ssl' => [
            'key' => null,
            /*
            |------------------------------------
            | Public key configuration definition
            |------------------------------------
            */
            'public' => null,
            /*
            |------------------------------------------------
            | OpenSSL pem file passphrase configuration value
            |------------------------------------------------
            */
            'passphrase' => '',
        ],
        /*
        |------------------------------------------------------
        | Configuration value used for encrypting access tokens
        |------------------------------------------------------
        */
        'hmac' => [
            'key' => null,
        ],
    ],

    /*
    |-------------------------------------------------
    |Application middleware configurations definitions
    |-------------------------------------------------
    */
    'middleware' => [

        'cookies' => [
            /*
            |--------------------------------------------------------------------------
            | Cookie encryter middleware
            |--------------------------------------------------------------------------
            |
            */
            'encrypt' => \Illuminate\Cookie\Middleware\EncryptCookies::class,
            /*
            |--------------------------------------------------------------------------
            | Cookie Path
            |--------------------------------------------------------------------------
            |
            | The cookie path determines the path for which the cookie will
            | be regarded as available. Typically, this will be the root path of
            | your application but you are free to change this when necessary.
            |
            */

            'path' => '/',

            /*
            |--------------------------------------------------------------------------
            | Cookie Domain
            |--------------------------------------------------------------------------
            |
            | Here you may change the domain of the cookie used to identify a session
            | in your application. This will determine which domains the cookie is
            | available to in your application. A sensible default has been set.
            |
            */

            'domain' => env('COOKIE_DOMAIN'),

            /*
            |--------------------------------------------------------------------------
            | HTTPS Only Cookies
            |--------------------------------------------------------------------------
            |
            | By setting this option to true, session cookies will only be sent back
            | to the server if the browser has a HTTPS connection. This will keep
            | the cookie from being sent to you when it can't be done securely.
            |
            */

            'secure' => env('SECURE_COOKIE'),

            /*
            |--------------------------------------------------------------------------
            | HTTP Access Only
            |--------------------------------------------------------------------------
            |
            | Setting this value to true will prevent JavaScript from accessing the
            | value of the cookie and the cookie will only be accessible through
            | the HTTP protocol. You are free to modify this option if needed.
            |
            */

            'http_only' => true,

            /*
            |----------------------------------------------
            | Cookies lifetime
            |----------------------------------------------
            | It defines total number of minutes used in
            | calculating cookies expiration
            */
            'lifetime' => 1440,
        ],
        /*
        |--------------------------------------------------------------------------
        | Csrf Token verification middleware
        |--------------------------------------------------------------------------
        |
        | Based on your application needs you may provides csrf token validation
        | middleware or derfault to Laravel framework implementation if running
        | in laravel environment
        |
        */
        'verify_csrf_token' => \Drewlabs\Auth\JwtGuard\Middleware\VerifyCsrfToken::class,
        /*
        |--------------------------------------------------------------------------
        | Stateful Domains
        |--------------------------------------------------------------------------
        |
        | Requests from the following domains / hosts will receive stateful API
        | authentication cookies. Typically, these should include your local
        | and production domains which access your API via a frontend SPA.
        |
        */
        'stateful' => explode(
            ',',
            env(
                'STATEFUL_DOMAINS',
                sprintf(
                    '%s',
                    'localhost,localhost:3000,127.0.0.1,127.0.0.1:8000,::1',
                )
            )
        ),
    ],
];
