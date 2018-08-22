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
use ParagonIE\ConstantTime\Binary;
use RuntimeException;

class SymmetricKey
{
    const KEY_LENGTH_BYTES = 32;

    /** @var string */
    private $symmetricKey;

    /**
     * @param string $symmetricKey
     */
    public function __construct($symmetricKey)
    {
        if (32 !== Binary::safeStrlen($symmetricKey)) {
            throw new KeyException('invalid key length');
        }
        $this->symmetricKey = $symmetricKey;
    }

    /**
     * @return self
     */
    public static function generate()
    {
        return new self(\random_bytes(self::KEY_LENGTH_BYTES));
    }

    /**
     * @param string $fileName
     *
     * @return self
     */
    public static function load($fileName)
    {
        // https://github.com/vimeo/psalm/issues/570
        /** @var false|string */
        $fileData = @\file_get_contents($fileName);
        if (false === $fileData) {
            throw new RuntimeException(\sprintf('unable to read key file "%s"', $fileName));
        }

        return new self($fileData);
    }

    /**
     * @param string $fileName
     *
     * @return void
     */
    public function save($fileName)
    {
        if (false === @\file_put_contents($fileName, $this->getKey())) {
            throw new RuntimeException(\sprintf('unable to write key file "%s"', $fileName));
        }
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->symmetricKey;
    }
}
