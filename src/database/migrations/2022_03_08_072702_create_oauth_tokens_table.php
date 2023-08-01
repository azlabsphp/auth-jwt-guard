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

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateOAuthTokensTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('oauth_tokens', static function (Blueprint $table) {
            $table->id();
            $table->text('scopes')->default(json_encode([]));
            $table->foreignUuid('sub')->nullable();
            $table->string('issuer');
            $table->string('jti', 64)->index();
            $table->dateTimeTz('expires_at');
            $table->dateTimeTz('issued_at');
            $table->boolean('revoked')->default(false);
            $table->dateTimeTz('last_used_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('oauth_tokens');
    }
}
