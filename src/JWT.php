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

namespace fkooman\JWT;

use fkooman\JWT\Exception\JWTException;
use ParagonIE\ConstantTime\Base64UrlSafe;

abstract class JWT
{
    /**
     * @param array $jsonData
     *
     * @return string
     */
    public function encode(array $jsonData)
    {
        $headerData = [
            'alg' => static::JWT_ALGORITHM,
            'typ' => 'JWT',
        ];
        $jwtHeader = Base64UrlSafe::encodeUnpadded(Util::encodeJson($headerData));
        $jwtPayload = Base64UrlSafe::encodeUnpadded(Util::encodeJson($jsonData));
        $jwtSignature = Base64UrlSafe::encodeUnpadded($this->sign($jwtHeader.'.'.$jwtPayload));

        return $jwtHeader.'.'.$jwtPayload.'.'.$jwtSignature;
    }

    /**
     * @param string $jwtStr
     *
     * @return array
     */
    public function decode($jwtStr)
    {
        $jwtParts = \explode('.', $jwtStr);
        if (3 !== \count($jwtParts)) {
            throw new JWTException('JWT: invalid JWT token');
        }
        // we do not care what is in the header, verify "as is"
        if (false === $this->verify($jwtParts[0].'.'.$jwtParts[1], Base64UrlSafe::decode($jwtParts[2]))) {
            throw new JWTException('JWT: invalid signature');
        }

        // now we have a valid signed JWT, so let's continue
        return Util::decodeJson(Base64UrlSafe::decode($jwtParts[1]));
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    abstract protected function sign($inputStr);

    /**
     * @param string $inputStr
     * @param string $signatureIn
     *
     * @return bool
     */
    abstract protected function verify($inputStr, $signatureIn);
}
