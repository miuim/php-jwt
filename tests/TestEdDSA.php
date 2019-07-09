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

/**
 * This class extends EdDSA to be able to (directly) test the "sign" and
 * "verify" methods as they are protected and should not be exposed to the
 * API user, but we still want to test them.
 */
class TestEdDSA extends EdDSA
{
	/**
	 * @param string $inputStr
	 *
	 * @return string
	 */
	public function sign(string $inputStr): string
	{
		return parent::sign($inputStr);
	}

	/**
	 * @param string $inputStr
	 * @param string $signatureIn
	 *
	 * @return bool
	 */
	public function verify(string $inputStr, string $signatureIn): bool
	{
		return parent::verify($inputStr, $signatureIn);
	}
}
