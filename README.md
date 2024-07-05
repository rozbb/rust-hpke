rust-hpke
=========
[![Version](https://img.shields.io/crates/v/hpke.svg)](https://crates.io/crates/hpke)
[![Docs](https://docs.rs/hpke/badge.svg)](https://docs.rs/hpke)
[![CI](https://github.com/rozbb/rust-hpke/workflows/CI/badge.svg)](https://github.com/rozbb/rust-hpke/actions)

This is an implementation of the [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) hybrid encryption standard (RFC 9180).

Warning
-------

This crate has not been formally audited. Cloudflare [did a security](https://blog.cloudflare.com/using-hpke-to-encrypt-request-payloads/) review of version 0.8, though:

> The HPKE implementation we decided on comes with the caveat of not yet being
> formally audited, so we performed our own internal security review. We
> analyzed the cryptography primitives being used and the corresponding
> libraries. Between the composition of said primitives and secure programming
> practices like correctly zeroing memory and safe usage of random number
> generators, we found no security issues.

What it implements
------------------

This implementation complies with the [HPKE standard](https://www.rfc-editor.org/rfc/rfc9180.html) (RFC 9180).

Here are all the primitives listed in the spec. The primitives with checked boxes are the ones that are implemented.

* KEMs
    - [X] DHKEM(Curve25519, HKDF-SHA256)
    - [ ] DHKEM(Curve448, HKDF-SHA512)
    - [X] DHKEM(P-256, HKDF-SHA256)
    - [X] DHKEM(P-384, HKDF-SHA384)
    - [X] DHKEM(P-521, HKDF-SHA512)
    - [X] DHKEM(secp256k1, HKDF-SHA256)
* KDFs
    - [X] HKDF-SHA256
    - [X] HKDF-SHA384
    - [X] HKDF-SHA512
* AEADs
    - [X] AES-GCM-128
    - [X] AES-GCM-256
    - [X] ChaCha20Poly1305

Crate Features
--------------

Default features flags: `alloc`, `x25519`, `p256`.

Feature flag list:

* `alloc` - Includes allocating methods like `AeadCtxR::open()` and `AeadCtxS::seal()`
* `x25519` - Enables X25519-based KEMs
* `p256` - Enables NIST P-256-based KEMs
* `p384` - Enables NIST P-384-based KEMs
* `p521` - Enables NIST P-521-based KEMs
* `std` - Includes an implementation of `std::error::Error` for `HpkeError`. Also does what `alloc` does.

For info on how to omit or include feature flags, see the [cargo docs on features](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choosing-features).

Usage Examples
--------------

See the [client-server](examples/client_server.rs) example for an idea of how to use HPKE.

Breaking changes
----------------

### Breaking changes in v0.12

The `serde_impls` feature was removed. If you were using this and require backwards compatible serialization/deserialization, see the wiki page [here](https://github.com/rozbb/rust-hpke/wiki/Migrating-away-from-the-serde_impls-feature).

MSRV
----

The current minimum supported Rust version (MSRV) is 1.65.0 (897e37553 2022-11-02).

Changelog
---------

See [CHANGELOG.md](CHANGELOG.md) for a list of changes made throughout past versions.

Tests
-----

To run all tests, execute `cargo test --all-features`. This includes known-answer tests, which test against `test-vector-COMMIT_ID.json`,where `COMMIT_ID` is the short commit of the version of the [spec](https://github.com/cfrg/draft-irtf-cfrg-hpke) that the test vectors came from. The finalized spec uses commit 5f503c5. See the [reference implementation](https://github.com/cisco/go-hpke) for information on how to generate a test vector.

Benchmarks
----------

To run all benchmarks, execute `cargo bench --all-features`. If you set your own feature flags, the benchmarks will still work, and run the subset of benches that it is able to. The results of a benchmark can be read as a neat webpage at `target/criterion/report/index.html`.

Ciphersuites benchmarked:

* NIST Ciphersuite with 128-bit security: AES-GCM-128, HKDF-SHA256, ECDH-P256
* Non-NIST Ciphersuite with 128-bit security: ChaCha20-Poly1305, HKDF-SHA256, X25519

Functions benchmarked in each ciphersuite:

* `Kem::gen_keypair`
* `setup_sender` with OpModes of Base, Auth, Psk, and AuthPsk
* `setup_receiver` with OpModes of Base, Auth, Psk, and AuthPsk
* `AeadCtxS::seal` with plaintext length 64 and AAD length 64
* `AeadCtxR::open` with ciphertext length 64 and AAD length 64

Agility
-------

A definition: *crypto agility* refers to the ability of a cryptosystem or protocol to vary its underlying primitives. For example, TLS has "crypto agility" in that you can run the protocol with many different ciphersuites.

This crate does not support crypto agility out of the box. This is because the cryptographic primitives are encoded as types satisfying certain constraints, and types need to be determined at compile time (broadly speaking). That said, there is nothing preventing you from implementing agility yourself. There is a [sample implementation](examples/agility.rs) in the examples folder. The sample implementation is messy because agility is messy.

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
