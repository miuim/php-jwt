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

	public function initHS256(): void
	{
		$this->hs256 = new HS256(HS256SecretKey::fromEncodedString(\file_get_contents(__DIR__.'/keys/hs256.key')));
	}

	public function initRS256(): void
	{
		$this->rs256 = new RS256(RS256PublicKey::load(__DIR__.'/keys/rs256.crt'), RS256PrivateKey::load(__DIR__.'/keys/rs256.key'));
	}

	public function initEdDSA(): void
	{
		$secretKey = EdDSASecretKey::fromEncodedString(\file_get_contents(__DIR__.'/keys/eddsa.key'));
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
	public function benchSignHS256(): void
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
	public function benchVerifyHS256(): void
	{
		$this->hs256->decode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.Jyw18klPA0nFJpoRFua0mAyCyq_AwG0Y7AUiAzqrtmc');
	}

	/**
	 * @Revs(1000)
	 * @Iterations(5)
	 * @OutputTimeUnit("seconds")
	 * @OutputMode("throughput")
	 *
	 * @return void
	 */
	public function benchSignRS256(): void
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
	public function benchVerifyRS256(): void
	{
		$this->rs256->decode('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.n_jnlmY2z7EjRogmcNvqVVjd8beDohEOrb03AHapeoOmUPISQrpwQ91yfZ7c5aoa8R1HvFtv7SYfAPRHXaDB1tKeCafD1fCyuH6d2PDqy68TRzA-ILsa78zqtigNQ3w72yarZ4BTZu2OuJdJ7TJg-OXn8cYeUIWN9gn7dF4zT0NjHAhsaF1QQEfkDu44YVvjmZo-uqDlFSezmkNpUGffap-hMb7z_4FwfIWxExjYKUwKOxUD8Hx8R6uJ0KoV_hLQOjFUfKM6EDtv2PPCiOm-5gWxnoL9s4sF-01W1On0RQhhJDAeRLXCpZfT_NylpYd_gUL2WQkxSD3MVUFtHjRpxQ');
	}

	/**
	 * @Revs(1000)
	 * @Iterations(5)
	 * @OutputTimeUnit("seconds")
	 * @OutputMode("throughput")
	 *
	 * @return void
	 */
	public function benchSignEdDSA(): void
	{
		$this->eddsa->encode(['foo' => 'bar']);
	}

	/**
	 * @Revs(1000)
	 * @Iterations(5)
	 * @OutputTimeUnit("seconds")
	 * @OutputMode("throughput")
	 *
	 * @return void
	 */
	public function benchVerifyEdDSA(): void
	{
		$this->eddsa->decode('eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.9DE3hlp2G1IG5E8sX3VfANjmOdPTip6rKsYO2CAEOr1GNsZmGi_eA-pmZmibkMRibVwmtkcUDtNjQDoBAACwCw');
	}
}
