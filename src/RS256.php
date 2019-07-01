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

namespace fkooman\Jwt;

use fkooman\Jwt\Exception\JwtException;
use fkooman\Jwt\Keys\RS256\PrivateKey;
use fkooman\Jwt\Keys\RS256\PublicKey;
use RuntimeException;

class RS256 extends Jwt
{
    /** @var \fkooman\Jwt\Keys\RS256\PublicKey */
    private $publicKey;

    /** @var ?\fkooman\Jwt\Keys\RS256\PrivateKey */
    private $privateKey;

    public function __construct(PublicKey $publicKey, ?PrivateKey $privateKey = null)
    {
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
    }

    protected static function getAlgorithm(): string
    {
        return 'RS256';
    }

    protected function sign(string $inputStr): string
    {
        if (null === $privateKey = $this->privateKey) {
            throw new JwtException('private key not set');
        }
        $signatureOut = '';
        if (false === \openssl_sign($inputStr, $signatureOut, $privateKey->raw(), OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('OpenSSL: unable to sign');
        }

        return $signatureOut;
    }

    protected function verify(string $inputStr, string $signatureIn): bool
    {
        $verifyResult = \openssl_verify($inputStr, $signatureIn, $this->publicKey->raw(), OPENSSL_ALGO_SHA256);
        if (1 === $verifyResult) {
            return true;
        }
        if (0 === $verifyResult) {
            return false;
        }

        $errorMsg = 'OpenSSL: ';
        while (false !== $errorString = \openssl_error_string()) {
            $errorMsg .= $errorString;
        }

        throw new RuntimeException($errorMsg);
    }
}
