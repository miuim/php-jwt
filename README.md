# Introduction

**NOTE**: this is a WIP!

This is small and secure JWT implementation. It supports `HS256` and `RS256` 
only as those seem to be the most widely deploy JWT algorithms.

# What?

A secure JWT library for generating and verifying JSON Web Tokens:

* Only supports `RS256` and `HS256` through separate classes;
* All keys are validated before use to make sure they are of the correct 
  format;
* No header parsing;

There is no "algorithm" toggle. You use either the `HS256` or `RS256` class
directly. You have to know which token algorithm you expect before verifying 
it.

**NOTE**: this is not a complete JWT implementation. It is NOT compliant with
the specification, nor aims to be, but does work.

# TODO

* check `exp` and maybe `nbf`? if it is set in the JWT when verifying to make
  sure the JWT is (still) valid;
* implement check for `crit` JWT header and throw exception when it occurs, 
  we do NOT want to deal with this mess.

# Why?

JWT is [insecure](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).
In order to solve some of the issues we wrote a library that does not even 
parse the JWT header. It will directly verify the signature with the chosen 
algorithm and key. No discovery, no attacks.

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

```bash
    $ php -r 'echo base64_encode(random_bytes(32)) . PHP_EOL';
```

**NOTE** you need to feed the key to the `SymmetricKey` class as a 32 byte 
(256 bits) string, so decode it before using it if you encoded it as e.g. 
Base64!

# API

## RS256

```php
    
    $r = new RS256(new PublicKey('jwt.crt'), new PrivateKey('jwt.key'));
    $jwtStr = $r->encode(['foo' => 'bar']);
    var_dump($r->decode($jwtStr));
```

The `PrivateKey` parameter is optional. Do not specify it if you only want to
verify JWTs. Of course, you need to specify it when you want to sign a JWT.

## HS256

```php
    $h = new HS256(new SymmetricKey(random_bytes(32)));
    $jwtStr = $h->encode(['foo' => 'bar']);
    var_dump($h->decode($jwtStr));
```
