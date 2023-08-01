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

namespace Drewlabs\Auth\JwtGuard\Console\Commands;

use Drewlabs\Auth\JwtGuard\JwtAuthGlobals;
use Illuminate\Console\Command;
use Illuminate\Support\Arr;
use phpseclib\Crypt\RSA as LegacyRSA;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;

class KeysCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'drewlabs-jwt:keys
                                      {--force : Overwrite keys they already exist}
                                      {--length=4096 : The length of the private key}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create the encryption keys for API authentication';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        [$publicKey, $privateKey] = [JwtAuthGlobals::keyPath('oauth-public.key'), JwtAuthGlobals::keyPath('oauth-private.key')];

        if ((file_exists($publicKey) || file_exists($privateKey)) && !$this->option('force')) {
            $this->error('Encryption keys already exist. Use the --force option to overwrite them.');

            return 1;
        }

        if (class_exists(LegacyRSA::class)) {
            $keys = (new LegacyRSA())->createKey($this->input ? (int) $this->option('length') : 4096);
            file_put_contents($publicKey, Arr::get($keys, 'publickey'));
            file_put_contents($privateKey, Arr::get($keys, 'privatekey'));
        } else {
            /**
             * @var PrivateKey
             */
            $key = RSA::createKey($this->input ? (int) $this->option('length') : 4096);
            file_put_contents($publicKey, (string) $key->getPublicKey());
            file_put_contents($privateKey, (string) $key);
        }

        $this->info('Encryption keys generated successfully.');

        return 0;
    }
}
