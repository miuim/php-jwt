<?php

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

use fkooman\Jwt\EdDSA;
use fkooman\Jwt\HS256;
use fkooman\Jwt\Keys\EdDSA\SecretKey as EdDSASecretKey;
use fkooman\Jwt\Keys\HS256\SecretKey as HS256SecretKey;
use fkooman\Jwt\Keys\RS256\PrivateKey as RS256PrivateKey;
use fkooman\Jwt\Keys\RS256\PublicKey as RS256PublicKey;
use fkooman\Jwt\RS256;

/**
 * @BeforeMethods({"initHS256","initRS256","initEdDSA"})
 */
class SignBench
{
    /** @var \fkooman\Jwt\HS256 */
    private $hs256;

    /** @var \fkooman\Jwt\RS256 */
    private $rs256;

    /** @var \fkooman\Jwt\EdDSA */
    private $eddsa;

    public function initHS256()
    {
        $this->hs256 = new HS256(HS256SecretKey::generate());
    }

    public function initRS256()
    {
        $this->rs256 = new RS256(RS256PublicKey::load(__DIR__.'/data/rsa.pub'), RS256PrivateKey::load(__DIR__.'/data/rsa.key'));
    }

    public function initEdDSA()
    {
        $secretKey = EdDSASecretKey::generate();
        $this->eddsa = new EdDSA($secretKey->getPublicKey(), $secretKey);
    }

    /**
     * @Revs(1000)
     * @Iterations(5)
     * @OutputTimeUnit("seconds")
     * @OutputMode("throughput")
     *
     * @return void
     */
    public function benchSignHS256()
    {
        $this->hs256->encode(['foo' => 'bar']);
    }

    /**
     * @Revs(1000)
     * @Iterations(5)
     * @OutputTimeUnit("seconds")
     * @OutputMode("throughput")
     *
     * @return void
     */
    public function benchSignRS256()
    {
        $this->rs256->encode(['foo' => 'bar']);
    }

    /**
     * @Revs(1000)
     * @Iterations(5)
     * @OutputTimeUnit("seconds")
     * @OutputMode("throughput")
     *
     * @return void
     */
    public function benchSignEdDSA()
    {
        $this->eddsa->encode(['foo' => 'bar']);
    }
}
