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
the specification, but does work.

**NOTE**: currently claim validity is not checked, i.e. `exp` is not verified.

**NOTE**: currently it does not support the `crit` JWT header key, which is a 
potential security problem... I guess we have to parse the header anyway, 
check if there is a `crit` key and then reject the token... We do not want
to support crappy extensions, it is bad enough as it is.

It doesn't seem many implementations support `crit`?

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

## HS256

```php
    $h = new HS256(new SymmetricKey(random_bytes(32)));
    $jwtStr = $h->encode(['foo' => 'bar']);
    var_dump($h->decode($jwtStr));
```
