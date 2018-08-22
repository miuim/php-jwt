# Introduction

This is small and secure JWT implementation. It only supports `HS256` and 
`RS256` as those seem to be the most widely deployed JWT signature algorithms.

# What?

A secure JWT library for generating and verifying JSON Web Tokens:

* Only supports `RS256` and `HS256` through separate classes;
* All keys are validated before use to make sure they are of the correct 
  format;
* Does NOT support the `crit` header key, token validation will fail;
* Does NOT support encryption, that's a lost cause with JWE;
* Verifies the `exp` payload field to make sure the token is not expired;

There is no "algorithm" toggle. You use either the `HS256` or `RS256` class
directly. You have to know which token algorithm you expect before verifying 
it.

**NOTE**: this is not a complete JWT implementation. It is NOT compliant with
the specification, nor aims to be, but it does work.

# Why?

JWT can be [insecure](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).
In order to solve some of the issues we wrote a library that solves some of 
these problems. It will directly verify the signature with the chosen algorithm 
and key, and not check the header to see which algorithm was used.

# Keys

## RS256 (RSA)

```bash
    $ openssl genrsa --out jwt.key
    $ openssl rsa -in jwt.key -pubout -out jwt.pub
```

To inspect a public key:

```bash
    $ openssl rsa -pubin -in jwt.pub -noout -text
```

This will generate a private key in `jwt.key` and the public key in `jwt.pub`.
Those files can be used with `PublicKey` and `PrivateKey`.

## HS256 (HMAC)

You can use the PHP function `random_bytes(32)` to generate a key. It MUST be 
32 bytes long (256 bits), the `SymmetricKey` function will reject any other 
length.

```php
    <?php

    $symmetricKey = new SymmetricKey(random_bytes(32));
```

If you want to store this key, other than in its binary form, you can use for
example Base64 encoding. Make sure you use a "constant time" implementation 
when loading a key from somewhere, e.g.:

```php
    <?php

    use ParagonIE\ConstantTime\Base64;
    
    $encodedKey = Base64::encode(random_bytes(32));
    
    // ...

    $symmetricKey = new SymmetricKey(Base64::decode($encodedKey));
```

# API

## RS256

```php
    <?php

    $r = new RS256(
        new PublicKey(file_get_contents('jwt.crt')),
        new PrivateKey(file_get_contents('jwt.key'))
    );
    $jwtStr = $r->encode(['foo' => 'bar']);
    var_dump($r->decode($jwtStr));
```

The `PrivateKey` parameter is optional. Do not specify it if you only want to
verify JWTs. Of course, you need to specify it when you want to sign a JWT.

## HS256

```php
    <?php

    $h = new HS256(new SymmetricKey(random_bytes(32)));
    $jwtStr = $h->encode(['foo' => 'bar']);
    var_dump($h->decode($jwtStr));
```
