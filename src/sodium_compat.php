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

if (!\defined('SODIUM_CRYPTO_SIGN_KEYPAIRBYTES')) {
    \define('SODIUM_CRYPTO_SIGN_KEYPAIRBYTES', \Sodium\CRYPTO_SIGN_KEYPAIRBYTES);
}

if (!\defined('SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES')) {
    \define('SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES', \Sodium\CRYPTO_SIGN_PUBLICKEYBYTES);
}

if (!\defined('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES')) {
    \define('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES', \Sodium\CRYPTO_SIGN_SECRETKEYBYTES);
}

if (!\defined('SODIUM_CRYPTO_SIGN_SEEDBYTES')) {
    \define('SODIUM_CRYPTO_SIGN_SEEDBYTES', \Sodium\CRYPTO_SIGN_SEEDBYTES);
}

if (!\is_callable('sodium_crypto_sign_detached')) {
    /**
     * @param string $message
     * @param string $sk
     *
     * @return string
     */
    function sodium_crypto_sign_detached($message, $sk)
    {
        return \Sodium\crypto_sign_detached($message, $sk);
    }
}

if (!\is_callable('sodium_crypto_sign_keypair')) {
    /**
     * @return string
     */
    function sodium_crypto_sign_keypair()
    {
        return \Sodium\crypto_sign_keypair();
    }
}

if (!\is_callable('sodium_crypto_sign_publickey_from_secretkey')) {
    /**
     * @param string $sk
     *
     * @return string
     */
    function sodium_crypto_sign_publickey_from_secretkey($sk)
    {
        return \Sodium\crypto_sign_publickey_from_secretkey($sk);
    }
}

if (!\is_callable('sodium_crypto_sign_secretkey')) {
    /**
     * @param string $keypair
     *
     * @return string
     */
    function sodium_crypto_sign_secretkey($keypair)
    {
        return \Sodium\crypto_sign_secretkey($keypair);
    }
}

if (!\is_callable('sodium_crypto_sign_seed_keypair')) {
    /**
     * @param string $seed
     *
     * @return string
     */
    function sodium_crypto_sign_seed_keypair($seed)
    {
        return \Sodium\crypto_sign_seed_keypair($seed);
    }
}

if (!\is_callable('sodium_crypto_sign_verify_detached')) {
    /**
     * @param string $signature
     * @param string $message
     * @param string $pk
     *
     * @return bool
     */
    function sodium_crypto_sign_verify_detached($signature, $message, $pk)
    {
        return \Sodium\crypto_sign_verify_detached($signature, $message, $pk);
    }
}
