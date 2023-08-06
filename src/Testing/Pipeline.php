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

 namespace Drewlabs\Auth\JwtGuard\Testing;

use Illuminate\Contracts\Pipeline\Pipeline as PipelinePipeline;

class Pipeline implements PipelinePipeline
{
    /**
     * @var mixed
     */
    private $traveler;

    /**
     * @var callable[]
     */
    private $pipeline;

    public function send($traveler)
    {
        $this->traveler = $traveler;

        return $this;
    }

    public function through($stops)
    {
        $this->pipeline = $stops;

        return $this;
    }

    public function via($method)
    {
        // TODO: Throw not implemented exception
    }

    public function then(\Closure $destination)
    {
        $assertOperatorType = static function ($operator) {
            if (!\is_callable($operator)) {
                throw new \RuntimeException('Operator function must be a callable instance');
            }
        };
        $pipeline = function ($request, $next) use ($assertOperatorType) {
            $nextFunc = static function ($req, callable $interceptor) {
                return $interceptor($req, static function ($req) {
                    return $req;
                });
            };
            $stack = [static function ($request) use ($next) {
                return $next($request);
            }];
            if (0 === \count($this->pipeline)) {
                $this->pipeline = [static function ($request, callable $callback) {
                    return $callback($request);
                }];
            }
            foreach (array_reverse($this->pipeline) as $func) {
                if (\is_string($func)) {
                    continue;
                }
                $previous = array_pop($stack);
                $assertOperatorType($previous);
                $stack[] = static function ($request) use ($func, $previous) {
                    return $func($request, $previous);
                };
            }

            return $nextFunc($request, array_pop($stack));
        };

        return $pipeline($this->traveler, $destination);
    }
}
