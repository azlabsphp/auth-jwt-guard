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

namespace Drewlabs\Auth\JwtGuard\Middleware;

use Drewlabs\Auth\Jwt\Contracts\CsrfTokenAware;
use Drewlabs\Auth\Jwt\Contracts\TokenManagerInterface;
use Drewlabs\Auth\JwtGuard\BearerToken;
use Drewlabs\Auth\JwtGuard\Exceptions\CsrfTokenMismatchException;
use Drewlabs\Cookies\Cookie;
use Drewlabs\Cookies\FactoryProxy as CookieFactory;
use Drewlabs\Core\Helpers\ImmutableDateTime;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

final class VerifyCsrfToken extends BaseMiddleware
{
    /**
     * The encrypter implementation.
     *
     * @var Encrypter
     */
    private $encrypter;

    /**
     * @var array
     */
    private $config = [];

    /**
     * @var TokenManagerInterface
     */
    private $tokens;

    /**
     * Creates middleware instance.
     */
    public function __construct(
        Encrypter $encrypter,
        TokenManagerInterface $tokens,
        array $config = []
    ) {
        $this->tokens = $tokens;
        $this->config = $config ?? [];
        $this->encrypter = $encrypter;
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param array                    $expect  the URIs that should be excluded from CSRF verification
     *
     * @throws \InvalidArgumentException
     * @throws DecryptException
     * @throws CsrfTokenMismatchException
     *
     * @return ResponseInterface|Response
     */
    public function __invoke($request, \Closure $next, ...$expect)
    {
        // Query csrf token from request
        $accessToken = $this->tokens->decodeToken((string) BearerToken::fromRequest($request));
        $csrfToken = $accessToken instanceof CsrfTokenAware ? $accessToken->csrfToken() : $request->session()->token();

        if (
            $this->isReading($request)
            || $this->inExceptArray($request, $expect)
            || $this->tokensMatch($request, $csrfToken)
        ) {
            return $this->addCookieToResponse($next($request), $csrfToken);
        }

        throw new CsrfTokenMismatchException();
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @throws CsrfTokenMismatchException
     *
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        return $this->__invoke($request, $next);
    }

    /**
     * Determine if the HTTP request uses a ‘read’ verb.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return bool
     */
    private function isReading($request)
    {
        return \in_array($request->getMethod(), ['HEAD', 'GET', 'OPTIONS'], true);
    }

    /**
     * Determine if the request has a URI that should pass through CSRF verification.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return bool
     */
    private function inExceptArray($request, array $excepts = [])
    {
        foreach ($excepts as $except) {
            if ('/' !== $except) {
                $except = trim($except, '/');
            }

            if ($request->is($except)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the session and input CSRF tokens match.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return bool
     */
    private function tokensMatch($request, ?string $csrfToken)
    {
        $token = $this->getTokenFromRequest($request);

        return \is_string($csrfToken) && \is_string($token) && hash_equals($csrfToken, $token);
    }

    /**
     * Get the CSRF token from the request.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return string
     */
    private function getTokenFromRequest($request)
    {
        $token = $request->input('_token') ?: $this->getRequestHeader($request, 'X-CSRF-TOKEN');
        if (!$token && $header = $this->getRequestHeader($request, 'X-XSRF-TOKEN')) {
            $token = $this->encrypter->decrypt($header);
        }
        if (null === $token) {
            $token = $this->getRequestCookie($request, 'XSRF-TOKEN');
        }

        return $token;
    }

    private function addCookieToResponse(Response $response, string $csrfToken)
    {
        $cookie = CookieFactory::create(
            'XSRF-TOKEN',
            $csrfToken,
            ImmutableDateTime::nowTz()->getTimestamp() + 60 * $this->config['lifetime'] ?? 3600,
            $this->config['domain'] ?? null,
            $this->config['path'] ?? '/',
            $this->config['secure'] ?? true,
            $this->config['http_only'] ?? false,
            $this->config['same_site'] ?? Cookie::SAME_SITE_LAX
        );
        $response->headers->set('Set-Cookie', (string) $cookie);

        // Return transformed response
        return $response;
    }
}
