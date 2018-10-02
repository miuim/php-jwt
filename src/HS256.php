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

namespace fkooman\Jwt;

use fkooman\Jwt\Keys\SecretKey;
use TypeError;

class HS256 extends Jwt
{
    /** @var string */
    const JWT_ALGORITHM = 'HS256';

    /** @var Keys\SecretKey */
    private $secretKey;

    /**
     * @param Keys\SecretKey $secretKey
     */
    public function __construct(SecretKey $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    /**
     * @param string $inputStr
     *
     * @return string
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    protected function sign($inputStr)
    {
        if (!\is_string($inputStr)) {
            throw new TypeError('argument 1 must be string');
        }

        return \hash_hmac('sha256', $inputStr, $this->secretKey->getKey(), true);
    }

    /**
     * @param string $inputStr
     * @param string $signatureIn
     *
     * @return bool
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    protected function verify($inputStr, $signatureIn)
    {
        if (!\is_string($inputStr)) {
            throw new TypeError('argument 1 must be string');
        }
        if (!\is_string($signatureIn)) {
            throw new TypeError('argument 2 must be string');
        }

        return \hash_equals(self::sign($inputStr), $signatureIn);
    }
}
