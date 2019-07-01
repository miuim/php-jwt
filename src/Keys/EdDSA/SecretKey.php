<?php

declare(strict_types=1);

/*
 * Copyright (c) 2019 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace fkooman\Jwt\Keys\EdDSA;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;

class SecretKey
{
    /** @var string */
    private $secretKey;

    public function __construct(string $secretKey)
    {
        switch (Binary::safeStrlen($secretKey)) {
            case SODIUM_CRYPTO_SIGN_SECRETKEYBYTES:
                $this->secretKey = $secretKey;
                break;
            case SODIUM_CRYPTO_SIGN_SEEDBYTES:
                $this->secretKey = Binary::safeSubstr(\sodium_crypto_sign_seed_keypair($secretKey), 0, 64);
                break;
            case SODIUM_CRYPTO_SIGN_KEYPAIRBYTES:
                $this->secretKey = Binary::safeSubstr($secretKey, 0, 64);
                break;
            default:
                throw new \LengthException('invalid secret key length');
        }
    }

    public static function generate(): self
    {
        return new self(
            \sodium_crypto_sign_secretkey(
                \sodium_crypto_sign_keypair()
            )
        );
    }

    public function encode(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->secretKey);
    }

    public static function fromEncodedString(string $encodedString): self
    {
        return new self(Base64UrlSafe::decode($encodedString));
    }

    public function getPublicKey(): PublicKey
    {
        return new PublicKey(
            \sodium_crypto_sign_publickey_from_secretkey($this->secretKey)
        );
    }

    public function raw(): string
    {
        return $this->secretKey;
    }
}
