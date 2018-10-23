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

require_once \dirname(__DIR__).'/vendor/autoload.php';

use fkooman\Jwt\EdDSA;
use fkooman\Jwt\HS256;
use fkooman\Jwt\Keys\EdDSA\SecretKey as EdDSASecretKey;
use fkooman\Jwt\Keys\HS256\SecretKey as HS256SecretKey;
use fkooman\Jwt\Keys\RS256\PrivateKey as RS256PrivateKey;
use fkooman\Jwt\Keys\RS256\PublicKey as RS256PublicKey;
use fkooman\Jwt\RS256;

try {
    $claimList = [
        'foo' => 'bar',
        'exp' => \time() + 3600,    // special claim (expiry)
    ];

    // RS256
    $r = new RS256(
        RS256PublicKey::load(__DIR__.'/rsa.pub'),
        RS256PrivateKey::load(__DIR__.'/rsa.key')
    );
    $jwtStr = $r->encode($claimList);
    echo 'RS256: '.$jwtStr.PHP_EOL;
    if ($claimList === $r->decode($jwtStr)) {
        echo 'OK'.PHP_EOL;
    }

    // HS256
    $h = new HS256(
        HS256SecretKey::fromEncodedString('5SBq2gMQFsy6ToGH0SS8CLFPCGxxFl8uohZUooCq5ps')
    );
    $jwtStr = $h->encode($claimList);
    echo 'HS256: '.$jwtStr.PHP_EOL;
    if ($claimList === $h->decode($jwtStr)) {
        echo 'OK'.PHP_EOL;
    }

    // EdDSA
    $secretKey = EdDSASecretKey::fromEncodedString('yvo12M7L4puipaUwuuDz_1SMDLz7VPcgcny-OkOHnIEamcDtjH31m6Xlw6a9Ib5dp5A-vHMdzIhUQxUMreqxPg');
    $h = new EdDSA(
        $secretKey->getPublicKey(),
        $secretKey
    );
    $jwtStr = $h->encode($claimList);
    echo 'EdDSA: '.$jwtStr.PHP_EOL;
    if ($claimList === $h->decode($jwtStr)) {
        echo 'OK'.PHP_EOL;
    }
} catch (Exception $e) {
    echo 'ERROR: '.$e->getMessage().PHP_EOL;
}
