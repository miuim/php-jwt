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

use DateTime;
use fkooman\Jwt\Exception\JwtException;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * The base class that MUST be extended by the classes that actually implement
 * the signing/verifying, e.g. HS256 and RS256.
 */
abstract class Jwt
{
    /** @var \DateTime|null */
    protected $dateTime;

    /** @var string|null */
    protected $keyId;

    /**
     * Override the "DateTime" for unit testing. Do NOT use this in your
     * application.
     *
     * @param \DateTime $dateTime
     *
     * @return void
     */
    public function setDateTime(DateTime $dateTime): void
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param string $keyId
     *
     * @return void
     */
    public function setKeyId(string $keyId): void
    {
        $this->keyId = $keyId;
    }

    /**
     * @param array $jsonData
     *
     * @return string
     */
    public function encode(array $jsonData): string
    {
        $headerData = [
            'alg' => static::getAlgorithm(),
            'typ' => 'JWT',
        ];

        if (null !== $this->keyId) {
            $headerData['kid'] = $this->keyId;
        }

        $jwtHeader = Base64UrlSafe::encodeUnpadded(Json::encode($headerData));
        $jwtPayload = Base64UrlSafe::encodeUnpadded(Json::encode($jsonData));
        $jwtSignature = Base64UrlSafe::encodeUnpadded($this->sign($jwtHeader.'.'.$jwtPayload));

        return $jwtHeader.'.'.$jwtPayload.'.'.$jwtSignature;
    }

    /**
     * @param string $jwtStr
     *
     * @return array
     */
    public function decode(string $jwtStr): array
    {
        $jwtParts = self::parseToken($jwtStr);
        self::validateHeader($jwtParts[0]);
        if (false === $this->verify($jwtParts[0].'.'.$jwtParts[1], Base64UrlSafe::decode($jwtParts[2]))) {
            throw new JwtException('invalid signature');
        }
        $payloadData = Json::decode(Base64UrlSafe::decode($jwtParts[1]));
        $this->checkToken($payloadData);

        return $payloadData;
    }

    /**
     * @param string $jwtStr
     *
     * @return string|null
     */
    public static function extractKeyId(string $jwtStr): ?string
    {
        $jwtParts = self::parseToken($jwtStr);
        $jwtHeaderData = self::validateHeader($jwtParts[0]);
        if (!\array_key_exists('kid', $jwtHeaderData)) {
            return null;
        }
        if (!\is_string($jwtHeaderData['kid'])) {
            throw new JwtException('"kid" value must be string');
        }

        return $jwtHeaderData['kid'];
    }

    /**
     * @return string
     */
    abstract protected static function getAlgorithm(): string;

    /**
     * @param string $inputStr
     *
     * @return string
     */
    abstract protected function sign(string $inputStr): string;

    /**
     * @param string $inputStr
     * @param string $signatureIn
     *
     * @return bool
     */
    abstract protected function verify(string $inputStr, string $signatureIn): bool;

    /**
     * @param string $jwtStr
     *
     * @return array<string>
     */
    private static function parseToken(string $jwtStr)
    {
        $jwtParts = \explode('.', $jwtStr);
        if (3 !== \count($jwtParts)) {
            throw new JwtException('invalid JWT token');
        }

        return $jwtParts;
    }

    /**
     * @param string $jwtHeaderStr
     *
     * @return array
     */
    private static function validateHeader(string $jwtHeaderStr): array
    {
        $jwtHeaderData = Json::decode(Base64UrlSafe::decode($jwtHeaderStr));
        if (!\array_key_exists('alg', $jwtHeaderData)) {
            throw new JwtException('"alg" header key missing');
        }
        if (static::getAlgorithm() !== $jwtHeaderData['alg']) {
            throw new JwtException('unexpected "alg" value');
        }
        if (\array_key_exists('crit', $jwtHeaderData)) {
            throw new JwtException('"crit" header key not supported');
        }

        return $jwtHeaderData;
    }

    /**
     * Verify the "exp" and "nbf" keys iff they are set.
     *
     * @param array $payloadData
     *
     * @return void
     */
    private function checkToken(array $payloadData): void
    {
        $dateTime = $this->dateTime ?? new DateTime();

        // exp
        if (\array_key_exists('exp', $payloadData)) {
            if (!\is_int($payloadData['exp'])) {
                throw new JwtException('"exp" not an integer');
            }
            if ($dateTime->getTimestamp() >= $payloadData['exp']) {
                throw new JwtException('token no longer valid');
            }
        }

        // nbf
        if (\array_key_exists('nbf', $payloadData)) {
            if (!\is_int($payloadData['nbf'])) {
                throw new JwtException('"nbf" not an integer');
            }
            if ($dateTime->getTimestamp() < $payloadData['nbf']) {
                throw new JwtException('token not yet valid');
            }
        }
    }
}
