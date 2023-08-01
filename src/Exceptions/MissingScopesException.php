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

namespace Drewlabs\Auth\JwtGuard\Exceptions;

class MissingScopesException extends \Exception
{
    /**
     * @var string[]
     */
    private $abilities = [];

    /**
     * @param string[] $abilities
     *
     * @return self
     */
    public function __construct(array $abilities)
    {
        $this->abilities = $abilities;
        parent::__construct(sprintf('Token has missing scopes: %s', implode(', ', $abilities ?? [])));
    }

    /**
     * Returns the list of abilities missing from the given token.
     *
     * @return array
     */
    public function getAbilities()
    {
        return $this->abilities ?? [];
    }
}
