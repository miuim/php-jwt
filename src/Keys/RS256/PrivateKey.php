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

namespace fkooman\Jwt\Keys\RS256;

use fkooman\Jwt\Exception\KeyException;
use ParagonIE\ConstantTime\Binary;
use RuntimeException;

class PrivateKey
{
    /** @var resource */
    private $privateKey;

    /**
     * @param string $privateKeyStr
     */
    public function __construct(string $privateKeyStr)
    {
        if (false === $privateKey = \openssl_pkey_get_private($privateKeyStr)) {
            throw new KeyException('invalid private key');
        }
        /* @var false|array<string,int|array<string,string>> */
        if (false === $keyInfo = \openssl_pkey_get_details($privateKey)) {
            throw new KeyException('unable to get key information');
        }
        if (!\array_key_exists('type', $keyInfo) || OPENSSL_KEYTYPE_RSA !== $keyInfo['type']) {
            throw new KeyException('not an RSA key');
        }
        /** @var array<string,string> */
        $rsaInfo = $keyInfo['rsa'];
        // RSA key MUST be at least 2048 bits
        // @see https://tools.ietf.org/html/rfc7518#section-4.2
        if (256 > Binary::safeStrlen($rsaInfo['n'])) {
            throw new KeyException('invalid RSA key, must be >= 2048 bits');
        }
        $this->privateKey = $privateKey;
    }

    /**
     * @param string $fileName
     *
     * @return self
     */
    public static function load(string $fileName): self
    {
        $fileData = @\file_get_contents($fileName);
        if (false === $fileData) {
            throw new RuntimeException(\sprintf('unable to read key file "%s"', $fileName));
        }

        return new self($fileData);
    }

    /**
     * @return resource
     */
    public function raw()
    {
        return $this->privateKey;
    }
}
