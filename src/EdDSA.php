<?php

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

namespace fkooman\Jwt;

use fkooman\Jwt\Exception\JwtException;
use fkooman\Jwt\Keys\EdDSA\PublicKey;
use fkooman\Jwt\Keys\EdDSA\SecretKey;
use TypeError;

class EdDSA extends Jwt
{
    /** @var string */
    const JWT_ALGORITHM = 'EdDSA';

    /** @var Keys\EdDSA\PublicKey */
    private $publicKey;

    /** @var Keys\EdDSA\SecretKey|null */
    private $secretKey;

    /**
     * @param Keys\EdDSA\PublicKey      $publicKey
     * @param Keys\EdDSA\SecretKey|null $secretKey
     */
    public function __construct(PublicKey $publicKey, SecretKey $secretKey = null)
    {
        $this->publicKey = $publicKey;
        $this->secretKey = $secretKey;
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    protected function sign($inputStr)
    {
        if (!\is_string($inputStr)) {
            throw new TypeError('argument 1 must be string');
        }
        if (null === $this->secretKey) {
            throw new JwtException('secret key not set');
        }

        return \sodium_crypto_sign_detached($inputStr, $this->secretKey->raw());
    }

    /**
     * @param string $inputStr
     * @param string $signatureIn
     *
     * @return bool
     */
    protected function verify($inputStr, $signatureIn)
    {
        if (!\is_string($inputStr)) {
            throw new TypeError('argument 1 must be string');
        }
        if (!\is_string($signatureIn)) {
            throw new TypeError('argument 2 must be string');
        }

        return \sodium_crypto_sign_verify_detached($signatureIn, $inputStr, $this->publicKey->raw());
    }
}
