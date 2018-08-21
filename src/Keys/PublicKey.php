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

namespace fkooman\Jwt\Keys;

use fkooman\Jwt\Exception\KeyException;
use fkooman\Jwt\Util;

class PublicKey
{
    /** @var resource */
    private $publicKey;

    /** @var string */
    private $e;

    /** @var string */
    private $n;

    /**
     * @param string $publicKeyStr
     */
    public function __construct($publicKeyStr)
    {
        if (false === $publicKey = \openssl_pkey_get_public($publicKeyStr)) {
            throw new KeyException('invalid public key');
        }

        /* @var false|array<string,int|array<string,string>> */
        if (false === $keyDetails = \openssl_pkey_get_details($publicKey)) {
            throw new KeyException('unable to get public key details');
        }
        if (OPENSSL_KEYTYPE_RSA !== $keyDetails['type']) {
            throw new KeyException('not an RSA key');
        }
        /** @var array<string,string> */
        $rsaInfo = $keyDetails['rsa'];
        $this->e = $rsaInfo['e'];
        $this->n = $rsaInfo['n'];
        $this->publicKey = $publicKey;
    }

    /**
     * @return resource
     */
    public function getKey()
    {
        return $this->publicKey;
    }

    /**
     * @return string
     */
    public function getJwkSet()
    {
        return Util::encodeJson(
            [
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'n' => Util::encodeUnpadded($this->n),
                        'e' => Util::encodeUnpadded($this->e),
                    ],
                ],
            ]
        );
    }
}
