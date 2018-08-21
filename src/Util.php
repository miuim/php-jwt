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

use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

class Util
{
    /**
     * @param array $jsonData
     *
     * @return string
     */
    public static function encodeJson(array $jsonData)
    {
        $jsonString = \json_encode($jsonData);
        if (false === $jsonString) {
            throw new RuntimeException('JSON: encode error');
        }

        return $jsonString;
    }

    /**
     * @param string $jsonString
     *
     * @return array
     */
    public static function decodeJson($jsonString)
    {
        /** @psalm-suppress MixedAssignment */
        $jsonData = \json_decode($jsonString, true);
        if (null === $jsonData) {
            if (JSON_ERROR_NONE !== \json_last_error()) {
                throw new RuntimeException('JSON: decode error');
            }
        }
        if (!\is_array($jsonData)) {
            throw new RuntimeException('JSON: not a JSON object');
        }

        return $jsonData;
    }

    /**
     * @param string $str
     *
     * @return string
     */
    public static function encodeUnpadded($str)
    {
        // For encodeUnpadded we need paragonie/constant_time_encoding
        // >= 1.0.3, >= 2.2.0
        // Ubuntu 18.04: php-constant-time (2.2.0-1) [universe]
        // Fedora 28: php-paragonie-constant-time-encoding-2.2.2-4.fc28
        // Debian 9: php-constant-time (2.0.3-1)
        // CentOS: php-paragonie-constant-time-encoding-1.0.3-1.el7
        // return Base64UrlSafe::encodeUnpadded($str);
        return \rtrim(Base64UrlSafe::encode($str), '=');
    }
}
