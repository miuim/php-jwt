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

require_once \dirname(__DIR__).'/vendor/autoload.php';

use fkooman\Jwt\EdDSA;
use fkooman\Jwt\Keys\EdDSA\SecretKey;

// generating an EdDSA key
$secretKey = SecretKey::generate();
$encodedSecretKey = $secretKey->encode();

// you can store the encoded key for later use, KEEP IT SAFE!
echo 'Secret Key: '.$encodedSecretKey.PHP_EOL;

// loading an EdDSA key
$secretKey = SecretKey::fromEncodedString($encodedSecretKey);
$publicKey = $secretKey->getPublicKey();
echo 'Public Key: '.$publicKey->encode().PHP_EOL;

$jwt = new EdDSA(
	$publicKey,
	$secretKey // OPTIONAL secret key, only needed when *signing* a token
);

// set the Key ID in the JWT header
$jwt->setKeyId('my_key_id');

// create the JWT
$jwtStr = $jwt->encode(['foo' => 'bar']);
echo 'JWT: '.$jwtStr.PHP_EOL;

// extract and show the Key ID from the JWT header if it exists, the Key ID can
// be used to select the right public key to verify a JWT token, e.g. in a
// "key rollover" scenario
if (null !== $keyId = EdDSA::extractKeyId($jwtStr)) {
	echo 'Key ID: '.$keyId.PHP_EOL;
}

// Verify the signature over the JWT and get the contents
\var_dump($jwt->decode($jwtStr));
