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

class JwtAuthGlobals
{
    /**
     * @var mixed
     */
    private static $storageDirectory;

    /**
     * @var string
     */
    private static $dbDateFormat = 'Y-m-d H:i:s';

    /**
     * @var string
     */
    private static $GUARD = 'drewlabs:jwt';

    /**
     * Set/Get the name of the HTTP guard instance.
     *
     * @return string
     */
    public static function guard(string $name = null)
    {
        if (null !== $name) {
            static::$GUARD = $name;
        }

        return static::$GUARD;
    }

    /**
     * Set / Get the project or application storage directory.
     *
     * @return string
     */
    public static function storageDir(string $directory = null)
    {
        if (null !== $directory) {
            static::$storageDirectory = $directory;
        }

        return static::$storageDirectory;
    }

    /**
     * Return the path to where to generate encryption keys.
     *
     * @throws \LogicException
     *
     * @return string
     */
    public static function keyPath(string $name)
    {
        $name = ltrim($name, '/\\');
        if (null === static::$storageDirectory) {
            throw new \LogicException('Application must configure the storage directory before calling keyPath method, please in your global service configurator call \Drewlabs\Auth\JwtGuard\JwtAuthGlobals::storageDir(...) before calling the current method');
        }

        return rtrim(static::$storageDirectory, '/\\').\DIRECTORY_SEPARATOR.$name;
    }

    /**
     * Defines the global database format to be used by the library.
     *
     * @return void
     */
    public static function useDBDateFormat(string $format)
    {
        static::$dbDateFormat = $format;
    }

    /**
     * @return string
     */
    public static function getDBDateFormat()
    {
        return static::$dbDateFormat;
    }
}
