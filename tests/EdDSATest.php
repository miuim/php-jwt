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

namespace fkooman\Jwt\Tests;

use fkooman\Jwt\EdDSA;
use fkooman\Jwt\Keys\EdDSA\PublicKey;
use fkooman\Jwt\Keys\EdDSA\SecretKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
final class EdDSATest extends TestCase
{
    public function testSimple(): void
    {
        $secretKey = SecretKey::generate();
        $dsa = new EdDSA(
            $secretKey->getPublicKey(),
            $secretKey
        );
        $payloadData = [
            'sub' => '1234567890',
            'name' => 'John Doe',
            'admin' => true,
            'iat' => 1516239022,
        ];
        $jwtStr = $dsa->encode($payloadData);
        static::assertSame(
            $payloadData,
            $dsa->decode($jwtStr)
        );
    }

    public function testExistingKey(): void
    {
        $secretKey = SecretKey::fromEncodedString('UxJdluQhRcMczkh0p4AZd4CQtPd7lW0VH6jMD1kpuqq9CmlI27UTQOVj5MC8sXKlHV9Kyzj5svXMgf8F2NCCwg');
        $dsa = new EdDSA(
            $secretKey->getPublicKey(),
            $secretKey
        );
        $payloadData = [
            'sub' => '1234567890',
            'name' => 'John Doe',
            'admin' => true,
            'iat' => 1516239022,
        ];
        static::assertSame('eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.69y2OskGoDK1fDNvSBRkFxXm17rFPou3Q6XbJV2EeCvx0-9hFrCPcXIIhY54MwgCM9ibprOqqHG6A682c9pgBA', $dsa->encode($payloadData));
    }

    public function testKeys(): void
    {
        $secretKey = new SecretKey(Hex::decode('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
        $publicKey = new PublicKey(Hex::decode('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));
        static::assertSame($secretKey->getPublicKey()->encode(), $publicKey->encode());
    }

    public function testTestVectorSign(): void
    {
        $secretKey = new SecretKey(Hex::decode('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
        $dsa = new TestEdDSA(
            $secretKey->getPublicKey(),
            $secretKey
        );
        static::assertSame('hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg', Base64UrlSafe::encodeUnpadded($dsa->sign('eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc')));
    }

    public function testTestVectorVerify(): void
    {
        $publicKey = new PublicKey(Hex::decode('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));
        $dsa = new TestEdDSA($publicKey);
        static::assertTrue(
            $dsa->verify(
                'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc',
                Base64UrlSafe::decode(
                    'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'
                )
            )
        );
    }
}
