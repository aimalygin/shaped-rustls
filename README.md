<p align="center">
  <img width="460" height="300" src="https://raw.githubusercontent.com/rustls/rustls/main/admin/rustls-logo-web.png">
</p>

<p align="center">
Rustls is a modern TLS library written in Rust.
</p>

# shaped-rustls

shaped-rustls is a fork of [rustls](https://github.com/rustls/rustls) with an
opt-in API for shaping the TLS ClientHello, so that a client can send the hello
of a browser or of a uTLS profile byte for byte. It is not affiliated with or
endorsed by the rustls project: please report its bugs
[here](https://github.com/aimalygin/shaped-rustls/issues), not upstream.

This release is rustls `0.23.46` with the shaping API on top. Everything below
the next heading is upstream's own README.

The shaping API is dormant unless an application installs a
`ClientHelloCustomizer` on its `ClientConfig`; without one the crate behaves as
upstream does. `admin/check-clienthello-compat` compares the default
ClientHello of this checkout with the upstream tag byte for byte, normalizing
only the fields that must vary (the random, the session ID and the key share
bytes).

## Using it

The package is named `shaped-rustls`, and its library is still named `rustls`,
so code written for rustls compiles against it unchanged:

```toml
[dependencies]
rustls = { package = "shaped-rustls", version = "0.23.4600" }
```

Crates that depend on the `rustls` package itself, such as tokio-rustls, quinn
or hyper-rustls, keep using upstream rustls, and its types are not
interchangeable with this crate's. A shaped hello under one of them needs an
adapter built against this crate.

## What it adds

* fixed ClientHello random and session ID values;
* custom and advertised cipher suites;
* supported versions, supported groups, and signature algorithm shaping;
* custom extension ordering, disabling, forced/raw/exact extensions, and ALPS;
* GREASE values and GREASE extension placement;
* raw key shares and fixed X25519 key shares, including the classical X25519
  component inside hybrid `X25519MLKEM768` key shares;
* padding, including BoringSSL's rule evaluated anew for each flight;
* a retried ClientHello, after a HelloRetryRequest that names a group, with
  that group's key share alone, as uTLS sends it;
* raw ClientHello capture for byte-level verification.

## Versions

A version is `0.23.PPRR`: `PP` is the upstream rustls patch release this one
is based on and `RR` counts the fork's own releases on that base. `0.23.4600`
is the first release on rustls `0.23.46`; a fix of the fork alone would be
`0.23.4601`, and a move to rustls `0.23.47` would be `0.23.4700`. A `^0.23`
requirement therefore follows both, as it would for rustls.

Security fixes of upstream rustls reach this crate only when it is rebased.
RustSec advisories are filed against `rustls`, and tools such as `cargo audit`
do not match them to `shaped-rustls`: check the upstream base named above.

# Status

Rustls is used in production at many organizations and projects. We aim to maintain
reasonable API surface stability but the API may evolve as we make changes to accommodate
new features or performance improvements.

We have a [roadmap](https://github.com/rustls/rustls/blob/rel-0.23/ROADMAP.md) for our future plans. We also have [benchmarks](https://github.com/rustls/rustls/blob/rel-0.23/BENCHMARKING.md) to
prevent performance regressions and to let you evaluate rustls on your target hardware.

If you'd like to help out, please see [CONTRIBUTING.md](https://github.com/rustls/rustls/blob/rel-0.23/CONTRIBUTING.md).

[![Build Status](https://github.com/rustls/rustls/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rustls/rustls/actions/workflows/build.yml?query=branch%3Amain)
[![Coverage Status (codecov.io)](https://codecov.io/gh/rustls/rustls/branch/main/graph/badge.svg)](https://codecov.io/gh/rustls/rustls/)
[![Documentation](https://docs.rs/rustls/badge.svg)](https://docs.rs/rustls/)
[![Chat](https://img.shields.io/discord/976380008299917365?logo=discord)](https://discord.gg/MCSB76RU96)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9034/badge)](https://www.bestpractices.dev/projects/9034)

## Changelog

The detailed list of changes in each release can be found at
https://github.com/rustls/rustls/releases.

# Documentation

https://docs.rs/rustls/

# Approach

Rustls is a TLS library that aims to provide a good level of cryptographic security,
requires no configuration to achieve that security, and provides no unsafe features or
obsolete cryptography by default.

Rustls implements TLS1.2 and TLS1.3 for both clients and servers. See [the full
list of protocol features](https://docs.rs/rustls/latest/rustls/manual/_04_features/index.html).

### Platform support

While Rustls itself is platform independent, by default it uses [`aws-lc-rs`] for implementing
the cryptography in TLS.  See [the aws-lc-rs FAQ][aws-lc-rs-platforms-faq] for more details of the
platform/architecture support constraints in aws-lc-rs.

[`ring`] is also available via the `ring` crate feature: see
[the supported `ring` target platforms][ring-target-platforms].

By providing a custom instance of the [`crypto::CryptoProvider`] struct, you
can replace all cryptography dependencies of rustls.  This is a route to being portable
to a wider set of architectures and environments, or compliance requirements.  See the
[`crypto::CryptoProvider`] documentation for more details.

Specifying `default-features = false` when depending on rustls will remove the implicit
dependency on aws-lc-rs.

Rustls requires Rust 1.71 or later. It has an optional dependency on zlib-rs which requires 1.75 or later.

[ring-target-platforms]: https://github.com/briansmith/ring/blob/2e8363b433fa3b3962c877d9ed2e9145612f3160/include/ring-core/target.h#L18-L64
[`crypto::CryptoProvider`]: https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html
[`ring`]: https://crates.io/crates/ring
[aws-lc-rs-platforms-faq]: https://aws.github.io/aws-lc-rs/faq.html#can-i-run-aws-lc-rs-on-x-platform-or-architecture
[`aws-lc-rs`]: https://crates.io/crates/aws-lc-rs

### Cryptography providers

Since Rustls 0.22 it has been possible to choose the provider of the cryptographic primitives
that Rustls uses. This may be appealing if you have specific platform, compliance or feature
requirements that aren't met by the default provider, [`aws-lc-rs`].

Users that wish to customize the provider in use can do so when constructing `ClientConfig`
and `ServerConfig` instances using the `with_crypto_provider` method on the respective config
builder types. See the [`crypto::CryptoProvider`] documentation for more details.

#### Built-in providers

Rustls ships with two built-in providers controlled by associated crate features:

* [`aws-lc-rs`] - enabled by default, available with the `aws_lc_rs` crate feature enabled.
* [`ring`] - available with the `ring` crate feature enabled.

See the documentation for [`crypto::CryptoProvider`] for details on how providers are
selected.

#### Third-party providers

The community has also started developing third-party providers for Rustls:

* [`boring-rustls-provider`] - a work-in-progress provider that uses [`boringssl`] for
cryptography.
* [`rustls-graviola`] - a provider that uses [`graviola`] for cryptography.
* [`rustls-mbedtls-provider`] - a provider that uses [`mbedtls`] for cryptography.
* [`rustls-openssl`] - a provider that uses [OpenSSL] for cryptography.
* [`rustls-rustcrypto`] - an experimental provider that uses the crypto primitives
from [`RustCrypto`] for cryptography.
* [`rustls-symcrypt`] - a provider that uses Microsoft's [SymCrypt] library.
* [`rustls-wolfcrypt-provider`] - a work-in-progress provider that uses [`wolfCrypt`] for cryptography.

[`rustls-graviola`]: https://crates.io/crates/rustls-graviola
[`graviola`]: https://github.com/ctz/graviola
[`rustls-mbedtls-provider`]: https://github.com/fortanix/rustls-mbedtls-provider
[`mbedtls`]: https://github.com/Mbed-TLS/mbedtls
[`rustls-openssl`]: https://github.com/tofay/rustls-openssl
[OpenSSL]: https://openssl-library.org/
[`rustls-symcrypt`]: https://github.com/microsoft/rustls-symcrypt
[SymCrypt]: https://github.com/microsoft/SymCrypt
[`boring-rustls-provider`]: https://github.com/janrueth/boring-rustls-provider
[`boringssl`]: https://github.com/google/boringssl
[`rustls-rustcrypto`]: https://github.com/RustCrypto/rustls-rustcrypto
[`RustCrypto`]: https://github.com/RustCrypto
[`rustls-wolfcrypt-provider`]: https://github.com/wolfSSL/rustls-wolfcrypt-provider
[`wolfCrypt`]: https://www.wolfssl.com/products/wolfcrypt

#### Custom provider

We also provide a simple example of writing your own provider in the [custom provider example].
This example implements a minimal provider using parts of the [`RustCrypto`] ecosystem.

See the [Making a custom CryptoProvider] section of the documentation for more information
on this topic.

[custom provider example]: https://github.com/rustls/rustls/tree/main/provider-example/
[`RustCrypto`]: https://github.com/RustCrypto
[Making a custom CryptoProvider]: https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html#making-a-custom-cryptoprovider

# Example code

Our [examples] directory contains demos that show how to handle I/O using the
[`stream::Stream`] helper, as well as more complex asynchronous I/O using [`mio`].
If you're already using Tokio for an async runtime you may prefer to use
[`tokio-rustls`] instead of interacting with rustls directly.

The [`mio`] based examples are the most complete, and discussed below. Users
new to Rustls may prefer to look at the simple client/server examples before
diving in to the more complex MIO examples.

[examples]: examples/
[`stream::Stream`]: https://docs.rs/rustls/latest/rustls/struct.Stream.html
[`mio`]: https://docs.rs/mio/latest/mio/
[`tokio-rustls`]: https://docs.rs/tokio-rustls/latest/tokio_rustls/

## Client example program

The MIO client example program is named `tlsclient-mio`.

Some sample runs:

```
$ cargo run --bin tlsclient-mio -- --http mozilla-modern.badssl.com
HTTP/1.1 200 OK
Server: nginx/1.6.2 (Ubuntu)
Date: Wed, 01 Jun 2016 18:44:00 GMT
Content-Type: text/html
Content-Length: 644
(...)
```

or

```
$ cargo run --bin tlsclient-mio -- --http expired.badssl.com
TLS error: InvalidCertificate(Expired)
Connection closed
```

Run `cargo run --bin tlsclient-mio -- --help` for more options.

## Server example program

The MIO server example program is named `tlsserver-mio`.

Here's a sample run; we start a TLS echo server, then connect to it with
`openssl` and `tlsclient-mio`:

```
$ cargo run --bin tlsserver-mio -- --certs test-ca/rsa-2048/end.fullchain --key test-ca/rsa-2048/end.key -p 8443 echo &
$ echo hello world | openssl s_client -ign_eof -quiet -connect localhost:8443
depth=2 CN = ponytown RSA CA
verify error:num=19:self signed certificate in certificate chain
hello world
^C
$ echo hello world | cargo run --bin tlsclient-mio -- --cafile test-ca/rsa-2048/ca.cert --port 8443 localhost
hello world
^C
```

Run `cargo run --bin tlsserver-mio -- --help` for more options.

# License

Rustls is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.

# Project Membership

- Joe Birr-Pixton ([@ctz], Project Founder - full-time funded by [Prossimo])
- Dirkjan Ochtman ([@djc], Co-maintainer)
- Daniel McCarney ([@cpu], Co-maintainer)
- Josh Aas ([@bdaehlie], Project Management)

[@ctz]: https://github.com/ctz
[@djc]: https://github.com/djc
[@cpu]: https://github.com/cpu
[@bdaehlie]: https://github.com/bdaehlie
[Prossimo]: https://www.memorysafety.org/initiative/rustls/

# Code of conduct

This project adopts the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
Please email rustls-mod@googlegroups.com to report any instance of misconduct, or if you
have any comments or questions on the Code of Conduct.
