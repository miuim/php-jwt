# Introduction


This project is forked from [fkooman/php-jwt](https://git.tuxed.net/fkooman/php-jwt/).

Then I changed the algorithm of `EdDSA` to `Ed25519` in `src\EdDSA.php` file.

That's all.

The following is original readme.

----

This is small JSON Web Token implementation. It only supports signatures with 
the following signature algorithms:

* `HS256` (`HMAC` using `SHA-256`)
* `RS256` (`RSASSA-PKCS1-v1_5` using `SHA-256`)
* `EdDSA` (`Ed25519`, [RFC 8037](https://tools.ietf.org/html/rfc8037))

The first two seem to be the most widely deployed JWT signature algorithms. The
library does _NOT_ support encryption/decryption due to the can of worms that
would open. It _MAY_ support encryption/decryption in the future, but 
definitely not with RSA.

# Which Algorithm to Use?

If you are both the signer and the verifier of the JWT use `HS256`. If you 
issue JWTs that have to be verified by third parties (as well), use `EdDSA`. Do
[NOT](https://blog.trailofbits.com/2019/07/08/fuck-rsa/) use `RS256` if you can 
help it.

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

# Versions 

| Version | PHP    | OS                                |
|---------|--------|-----------------------------------|
| 1.x     | >= 5.4 | CentOS >= 7 (+EPEL), Debian >= 9  |
| 2.x     | >= 7.2 | CentOS >= 8 (+EPEL), Debian >= 10 |

# Requirements

* PHP >= 7.2
* `php-hash` (for `HS256`)
* `php-openssl` (for `RS256`)
* `php-sodium` (for `EdDSA`)

Only `paragonie/constant_time_encoding` is a dependency.

# Installation

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
        "fkooman/jwt": "^2",
        ...
    },

You can also download the signed source code archive 
[here](https://software.tuxed.net/php-jwt/download.html).

# API

See the `example/` directory for working examples on how to generate keys, 
set the Key ID and create and validate JWT tokens.

# Testing

You can run the included test suite after cloning the repository:

    $ /path/to/composer install
    $ vendor/bin/phpunit

# Benchmark

You can use [PHPBench](https://phpbench.readthedocs.io/en/latest/) to run some 
benchmarks comparing the various signature algorithms.

    $ /path/to/phpbench run
