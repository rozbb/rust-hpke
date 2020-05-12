rust-hpke
=========
[![Version](https://img.shields.io/crates/v/hpke.svg)](https://crates.io/crates/hpke)
[![Docs](https://docs.rs/hpke/badge.svg)](https://docs.rs/hpke)
![CI](https://github.com/rozbb/rust-hpke/workflows/CI/badge.svg)
[![Coverage](https://codecov.io/gh/rozbb/rust-hpke/branch/master/graph/badge.svg)](https://codecov.io/gh/rozbb/rust-hpke)

This is an **work-in-progress** implementation of the [HPKE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke/) hybrid encryption standard.

What it implements
------------------

This implementation complies with the [HPKE draft](https://github.com/cfrg/draft-irtf-cfrg-hpke) up to commit e955931cdc4e9708da2fd4d905dd920fc4668c85.

Here are all the primitives listed in the spec. The primitives with checked boxes are the ones that are implemented.

* KEMs
    - [X] DHKEM(Curve25519, HKDF-SHA256)
    - [ ] DHKEM(Curve448, HKDF-SHA512)
    - [ ] DHKEM(P-256, HKDF-SHA256)
    - [ ] DHKEM(P-384, HKDF-SHA384)
    - [ ] DHKEM(P-521, HKDF-SHA512)
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

This crate supports `no_std`. However, the `std` feature is enabled by default.

For info on how to omit or include feature flags, see the [cargo docs on features](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choosing-features).

Tests
-----

To run tests, execute `cargo test`. This includes known-answer tests, which test against `test-vector-COMMIT_ID.json`,where `COMMIT_ID` is the short commit of the version of the [spec](https://github.com/cfrg/draft-irtf-cfrg-hpke) that the test vectors came from. See the [reference implementation](https://github.com/bifurcation/hpke) for information on how to generate a test vector.

Examples
--------

See the [client-server](examples/client_server.rs) example for an idea of how to use HPKE.

Agility
-------

A definition: *crypto agility* refers to the ability of a cryptosystem or protocol to vary its underlying primitives. For example, TLS has "crypto agility" in that you can run the protocol with many different ciphersuites.

This crate does not support crypto agility out of the box. This is because the cryptographic primitives are encoded as types satisfying certain constraints, and types need to be determined at compile time (broadly speaking). That said, there is nothing preventing you from implementing agility yourself. There is a [sample implementation](examples/agility.rs) in the examples folder. The sample implementation is messy because agility is messy.

What's next
-----------

* Add support for more KEMs
* Make feature flags for primitives, so you don't have bloat from algorithms you don't need

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Warning
-------

This code has not been audited in any sense of the word. Use at your own discretion.
