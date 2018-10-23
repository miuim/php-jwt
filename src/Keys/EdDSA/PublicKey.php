<?php

/*
 * Copyright (c) 2018 François Kooman <fkooman@tuxed.net>
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

use LengthException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use TypeError;

class PublicKey
{
    /** @var string */
    private $publicKey;

    /**
     * @param string $publicKey
     */
    public function __construct($publicKey)
    {
        if (!\is_string($publicKey)) {
            throw new TypeError('argument 1 must be string');
        }
        if (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== Binary::safeStrlen($publicKey)) {
            throw new LengthException('invalid public key length');
        }
        $this->publicKey = $publicKey;
    }

    /**
     * @return string
     */
    public function encode()
    {
        return Base64UrlSafe::encodeUnpadded($this->publicKey);
    }

    /**
     * @param string $encodedString
     *
     * @return self
     */
    public static function fromEncodedString($encodedString)
    {
        if (!\is_string($encodedString)) {
            throw new TypeError('argument 1 must be string');
        }

        return new self(Base64UrlSafe::decode($encodedString));
    }

    /**
     * @return string
     */
    public function getKid()
    {
        return Base64UrlSafe::encodeUnpadded(
            \hash(
                'sha256',
                $this->raw(),
                true
            )
        );
    }

    /**
     * @return string
     */
    public function raw()
    {
        return $this->publicKey;
    }
}
