rust-hpke
=========
![CI](https://github.com/rozbb/rust-hpke/workflows/CI/badge.svg)
[![Coverage](https://codecov.io/gh/rozbb/rust-hpke/branch/master/graph/badge.svg)](https://codecov.io/gh/rozbb/rust-hpke)

This is an work-in-progress implementation of the [HPKE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke/) hybrid encryption standard. Once this is passing official known-answer tests, I'll publish it as a crate.

What it implements
------------------

Currently, all of draft02 functionality is implemented, besides the single-shot API. In addition, the exporter API is implemented.

Not many algorithms are currently supported. Here's what we have:

* KEMs
    * DHKEM(Curve25519)
* KDFs
    * HKDF-SHA256
    * HKDF-SHA384
    * HKDF-SHA512
* AEADs
    * AES-GCM-128
    * AES-GCM-256
    * ChaCha20Poly1305

**THIS IMPLEMENTATION IS NOT KNOWN TO COMPLY WITH ANY STANDARDS...YET**

Crate Features
--------------

This crate supports `no_std`. However, the `std` feature is enabled by default.

For info on how to omit or include feature flags, see the [cargo docs on features](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choosing-features).

Tests
-----

To run tests, execute `cargo test`. This includes known-answer tests, which test against `test-vector-COMMIT_ID.json`,where `COMMIT_ID` is the short commit of the [reference implementation](https://github.com/bifurcation/hpke) version that created that test vector. Please see the reference implementation for information on how to generate a test vector.

Currently, file `test-vector-modified.json` is derived from a modified version of the reference implementation. Once the necessary changes are made upstream, the file will be updated.

Agility
-------

A definition: *crypto agility* refers to the ability of a cryptosystem or protocol to vary its underlying primitives. For example, TLS has "crypto agility" in that you can run the protocol with many different ciphersuites.

This crate does not support crypto agility out of the box. This is because the cryptographic primitives are encoded as types satisfying certain constraints, and types need to be determined at compile time (broadly speaking). That said, there is nothing preventing you from implementing agility yourself. There is a [sample implementation](examples/agility.rs) in the examples folder. The sample implementation is messy because agility is messy.

What's next
-----------

- [ ] Implement the single-shot API
- [ ] Add support for more KEMs
- [ ] Make feature flags for primitives, so you don't have bloat from algorithms you don't need

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Warning
-------

This code has not been audited in any sense of the word. Use at your own discretion.
