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

use Drewlabs\Core\Helpers\Arr;
use Drewlabs\Core\Helpers\Str;
use Illuminate\Container\Container;
use Illuminate\Contracts\Pipeline\Pipeline;
use Psr\Http\Message\ServerRequestInterface;

final class EnsureRequestsAreStateful extends BaseMiddleware
{
    /**
     * @var array
     */
    private $config = [];

    /**
     * @var Pipeline
     */
    private $pipeline;

    /**
     * Create middlewre class instance.
     */
    public function __construct(Pipeline $pipeline, array $config = [])
    {
        $this->config = $config;
        $this->pipeline = $pipeline;
    }

    /**
     * Handle the incoming requests.
     *
     * @param \Illuminate\Http\Request $request
     * @param callable                 $next
     *
     * @return \Illuminate\Http\Response
     */
    public function __invoke($request, $next)
    {
        $this->configureSecureCookieSessions();
        $container = Container::getInstance();

        return $this->pipeline
            ->send($request)
            ->through(static::fromFrontend($request) ? [
                static function ($request, $next) {
                    if ($request instanceof ServerRequestInterface) {
                        $body = \is_object($body_ = $request->getParsedBody()) ? get_object_vars($body_) : $body_;
                        $request = $request->withParsedBody(array_merge([
                            $body,
                            ['drewlabs:jwt', true],
                        ]));
                    } else {
                        $request->attributes->set('drewlabs:jwt', true);
                    }

                    return $next($request);
                },
                $this->config['encrypt_cookies'] ?? \Illuminate\Cookie\Middleware\EncryptCookies::class,
                \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
                $this->config['verify_csrf_token'] ?? VerifyCsrfToken::class,
            ] : [])
            ->then(static function ($request) use ($next) {
                return $next($request);
            });
    }

    /**
     * Handle the incoming requests.
     *
     * @param \Illuminate\Http\Request $request
     * @param callable                 $next
     *
     * @return \Illuminate\Http\Response
     */
    public function handle($request, $next)
    {
        return $this->__invoke($request, $next);
    }

    /**
     * Checks if pattern matches.
     *
     * @param mixed $pattern
     * @param mixed $value
     *
     * @return bool
     */
    protected function match($pattern, $value)
    {
        $patterns = Arr::wrap($pattern);
        $value = (string) $value;
        if (empty($patterns)) {
            return false;
        }
        foreach ($patterns as $pattern) {
            $pattern = (string) $pattern;
            if ($pattern === $value) {
                return true;
            }
            $pattern = preg_quote($pattern, '#');
            $pattern = str_replace('\*', '.*', $pattern);
            if (1 === preg_match('#^'.$pattern.'\z#u', $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Configure secure cookie sessions.
     *
     * @return void
     */
    private function configureSecureCookieSessions()
    {
        $this->config = array_merge($this->config ?? [], ['http_only' => true, 'same_site' => 'Lax']);
    }

    /**
     * Determine if the given request is from the first-party application frontend.
     *
     * @param \Illuminate\Http\Request|ServerRequestInterface $request
     *
     * @return bool
     */
    private function fromFrontend($request)
    {
        $domain = $this->getRequestHeader($request, 'referer') ?: $this->getRequestHeader($request, 'origin');
        if (null === $domain) {
            return false;
        }
        $domain = Str::contains($domain, 'https://') ? Str::after('https://', $domain) : $domain;
        $domain = Str::contains($domain, 'http://') ? Str::after('http://', $domain) : $domain;
        $domain = Str::endsWith($domain, '/') ? $domain : "{$domain}/";
        $stateful = array_filter($this->config['stateful'] ?? []);

        return $this->match(array_map(static function ($uri) {
            return trim($uri).'/*';
        }, $stateful ?? []), $domain);
    }
}
