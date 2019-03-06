# Introduction

This is small JSON Web Token implementation. It only supports signatures with 
the following signature algorithms:

* `HS256` (`HMAC` using `SHA-256`)
* `RS256` (`RSASSA-PKCS1-v1_5` using `SHA-256`)
* `EdDSA` (`Ed25519`, [RFC 8037](https://tools.ietf.org/html/rfc8037))

The first two seem to be the most widely deployed JWT signature algorithms. The
library does _NOT_ support encryption/decryption due to the can of worms that
would open. It _MAY_ support encryption/decryption in the future, but not with
RSA.

# Why?

Quite a number of JWT implementations exist for PHP, varying in quality. 
However, JWT can be [insecure](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid), 
so it is very important to get things right and as simple as possible from a 
security perspective. This means implementing the absolute minimum to support 
JWT, in a secure way. Simplicity and security is more important than fully 
supporting every nook and cranny of the specification.

# How?

* Only supports `RS256`, `HS256` and `EdDSA` through separate classes, the 
  header is _NOT_ used to determine the algorithm when verifying signatures;
* All keys are validated before use and wrapped in "Key" objects to make sure 
  they are of the correct format. Helper methods are provided to load / save / 
  generate keys;
* Does NOT support the [crit](https://tools.ietf.org/html/rfc7515#section-4.1.11) 
  header key. If a token is presented with the `crit` header key it will be 
  rejected;
* Verifies the `exp` and `nbf` payload field if present to make sure the token 
  is already and still valid.

# Requirements

* PHP >= 5.4.8 
* `php-hash` (for `HS256`)
* `php-openssl` (for `RS256`)
* `php-pecl-libsodium` with PHP < 7.2 or `php-sodium` with PHP >= 7.2 
  (for `EdDSA`)

On modern PHP versions only `paragonie/constant_time_encoding` is a dependency,
on older versions some polyfills are used. See `composer.json`.

## Use

Currently php-jwt is not hosted on [Packagist](https://packagist.org/). It may
be added in the future. In your `composer.json`:

    "repositories": [
        {
            "type": "vcs",
            "url": "https://git.tuxed.net/fkooman/php-jwt"
        },
        ...
    ],

    "require": {
        "fkooman/jwt": "^1",
        ...
    },

You can also download the signed source code archive 
[here](https://software.tuxed.net/php-jwt/download.html).

# Keys

Below we show how to generate keys for the various JWT algorithms. Do NOT use
any other way unless you know what you are doing!

## RS256 (RSA)

Use the `openssl` command line to generate they public and private key:

```bash
$ openssl genrsa --out rsa.key 2048
$ openssl rsa -in rsa.key -pubout -out rsa.pub
```

The RSA key MUST have 
[at least](https://tools.ietf.org/html/rfc7518#section-4.2) 2048 bits. The 
above command will generate a private key in `rsa.key` and the public key in 
`rsa.pub`. Those files can be used with the `PublicKey` and `PrivateKey` key 
wrapping classes.

To inspect a public key:

```bash
$ openssl rsa -pubin -in rsa.pub -noout -text
```

## HS256 (HMAC)

As this is a HMAC, there is only one key both for signing and verifying the 
JWT.

```php
<?php

// generating and saving a key
$secretKey = \fkooman\Jwt\Keys\HS256\SecretKey::generate();
$encodedString = $secretKey->encode();

// loading a key
$secretKey = \fkooman\Jwt\Keys\HS256\SecretKey::fromEncodedString($encodedString);
```

## EdDSA (Ed25519)

```php
<?php

// generating and saving a key
$secretKey = \fkooman\Jwt\Keys\EdDSA\SecretKey::generate();
$encodedString = $secretKey->encode();

// loading a key
$secretKey = \fkooman\Jwt\Keys\EdDSA\SecretKey::fromEncodedString($encodedString);
```

The public key can be obtained from the secret key by calling the 
`getPublicKey` method on the `SecretKey` object.

# API

This section describes how to use the various JWT types.

## RS256

```php
<?php

$r = new \fkooman\Jwt\RS256(
    \fkooman\Jwt\Keys\RS256\PublicKey::load('rsa.pub'),
    \fkooman\Jwt\Keys\RS256\PrivateKey::load('rsa.key')
);
$jwtStr = $r->encode(['foo' => 'bar']);
var_dump($r->decode($jwtStr));
```

The `PrivateKey` parameter is optional. Do not specify it if you only want to
verify JWTs. Of course, you need to specify it when you want to sign JWTs.

## HS256

```php
<?php

$h = new \fkooman\Jwt\HS256(
    \fkooman\Jwt\Keys\HS256\SecretKey::fromEncodedString(
        '5SBq2gMQFsy6ToGH0SS8CLFPCGxxFl8uohZUooCq5ps'
    )
);
$jwtStr = $h->encode(['foo' => 'bar']);
var_dump($h->decode($jwtStr));
```

## EdDSA (Ed25519)

```php
<?php

$secretKey = \fkooman\Jwt\Keys\EdDSA\SecretKey::fromEncodedString(
    'yvo12M7L4puipaUwuuDz_1SMDLz7VPcgcny-OkOHnIEamcDtjH31m6Xlw6a9Ib5dp5A-vHMdzIhUQxUMreqxPg'
);
$publicKey = $secretKey->getPublicKey();

$r = new \fkooman\Jwt\EdDSA(
    $publicKey,
    $secretKey
);
$jwtStr = $r->encode(['foo' => 'bar']);
var_dump($r->decode($jwtStr));
```

The `SecretKey` parameter is optional. Do not specify it if you only want to
verify JWTs. Of course, you need to specify it when you want to sign a JWT.

# Example

See the `example/` directory for a working example.

# Testing

You can run the included test suite after cloning the repository:

    $ /path/to/composer install
    $ vendor/bin/phpunit

# Benchmark

You can use [PHPBench](https://phpbench.readthedocs.io/en/latest/) to run some 
benchmarks comparing the various signature algorithms.

    $ /path/to/phpbench run
