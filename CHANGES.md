# ChangeLog

## 2.0.0 (...)
- require PHP >= 7.2
- enable strict types
- add verify benchmarks
- better way to expose algorithm from the subclasses
- add Phan static type checking configuration file
- require `php-sodium`

## 1.0.0 (2019-03-06)
- remove redundant type checks
- update README

## 0.3.0 (2019-02-08)
- add ability to set key ID
- remove "automatic" key ID from Key classes

## 0.2.2 (2018-10-23)
- add missing polyfill

## 0.2.1 (2018-10-23)
- implement libsodium < 2 support

## 0.2.0 (2018-10-23)
- move Keys to their own namespace
- implement `EdDSA` (RFC 8037, curve Ed25519)

## 0.1.0 (2018-09-28)
- initial release
