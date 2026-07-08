rust-hpke
=========
[![Version](https://img.shields.io/crates/v/hpke.svg)](https://crates.io/crates/hpke)
[![Docs](https://docs.rs/hpke/badge.svg)](https://docs.rs/hpke)
[![CI](https://github.com/rozbb/rust-hpke/workflows/CI/badge.svg)](https://github.com/rozbb/rust-hpke/actions)

This is an implementation of the [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) hybrid encryption standard (RFC 9180).

What it implements
------------------

This implementation complies with the [HPKE standard](https://www.rfc-editor.org/rfc/rfc9180.html) (RFC 9180). It also implements the pure post-quantum KEMs defined in [draft-ietf-hpke-pq-04](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04), and the hybrid post-quantum KEMs defined in  [draft-connolly-cfrg-xwing-kem-10](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10), [draft-irtf-cfrg-concrete-hybrid-kems-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-03), and [draft-irtf-cfrg-hybrid-kems-11](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-11) (this is all quite confusing, see Filippo's [summary](https://filippo.io/hpke-pq) of it).

Here are all the primitives listed in the spec. The primitives with checked boxes are the ones that are implemented.

* Classical KEMs
    - [X] DHKEM(Curve25519, HKDF-SHA256)
    - [ ] DHKEM(Curve448, HKDF-SHA512)
    - [X] DHKEM(P-256, HKDF-SHA256)
    - [X] DHKEM(P-384, HKDF-SHA384)
    - [X] DHKEM(P-521, HKDF-SHA512)
* Post-quantum and hybrid KEMs
    - [X] ML-KEM-768
    - [X] ML-KEM-1024
    - [X] MLKEM768-X25519, aka X-Wing
    - [X] MLKEM768-P256
    - [X] MLKEM1024-P384
* KDFs
    - [X] HKDF-SHA256
    - [X] HKDF-SHA384
    - [X] HKDF-SHA512
    - [X] SHAKE128
    - [X] SHAKE256
* AEADs
    - [X] AES-GCM-128
    - [X] AES-GCM-256
    - [X] ChaCha20Poly1305

Crate Features
--------------

The feature flags in this crate allow end-users to avoid pulling in dependencies they don't want. We thus take an **additive approach** to features: if you want hybrid post-quantum KEMs, you need to pull in the individual features it relies on. All is explained below.

### Feature Flags

Default features flags: `getrandom`, `alloc`, `chacha`, `x25519`, `mlkem`. Note this combination means that XWing is enabled by default, as well as all (Turbo)SHAKE KDFs.

* `alloc` - Exposes allocating methods like `AeadCtxR::open()` and `AeadCtxS::seal()`
* `getrandom` (default) - Enables top-level functions that use `getrandom` for random number generation, rather than taking in an explicit RNG
* AEADs:
  * `chacha` — Enables ChaCha20-Poly1305
  * `aes` — Enables AES-GCM-128/256
* KEMs:
  * `x25519` — Enables the X25519 DHKEM (also enables `hkdfsha2`)
  * `nistp` — Enables the ECDH-NIST P-256, P-384, and P-521 DHKEMs (also enables `hkdfsha2`)
  * `mlkem` — Enables the ML-KEM-768 and ML-KEM-1024 post-quantum KEMs (also enables `shake`)
* KDFs:
  * `hkdfsha2` — Enables HKDF-SHA256/384/512
  * `shake` — Enables SHAKE128/256 and TurboSHAKE128/256
* `kat` - Used only to enabled known-answer tests, which require `std`. Only use with `cargo test`

### Feature Combinations

We list the additional functionality that certain feature combinations enable:
* `x25519,mlkem` (default) — Enables the ML-KEM-768+X25519 (aka XWing) hybrid post-quantum KEM
* `nistp,mlkem` — Enables the ML-KEM + NIST-P hybrid post-quantum KEMs

For info on how to omit or include feature flags, see the [cargo docs on features](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choosing-features).

Usage Examples
--------------

See the [client-server](examples/client_server.rs) example for an idea of how to use HPKE.

Breaking changes
----------------

## Breaking changes in v0.14.0-pre.2

* Renamed every function that took an RNG to `*_with_rng`, and removed the `rng` parameter from the function with the original name (gated by `getrandom`)
* Feature-gated AES-GCM and ChaCha20Poly1305 behind `aes` and `chacha` features, respectively

## Breaking changes in v0.14.0-pre.1

* Updated `rand` and `rand_core` dependencies
* Replaced `generic-array` with `hybrid-array`
* Renamed all `_in_place` symmetric encryption/decryption algorithms to `_inout`. Also replaced `&mut [u8]` inputs in these functions with `inout::InOut<'_, '_, u8>`.
* Bumped MSRV to 1.85.0 (2025-02-20)

### Breaking changes in v0.13

* `PskBundle` now has a constructor that validates that the inputs are either both empty or nonempty.
* `rand_core` was updated to v0.9

### Breaking changes in v0.12

The `serde_impls` feature was removed. If you were using this and require backwards compatible serialization/deserialization, see the wiki page [here](https://github.com/rozbb/rust-hpke/wiki/Migrating-away-from-the-serde_impls-feature).

MSRV
----

The current minimum supported Rust version (MSRV) is 1.85.0 (2025-02-20).

Changelog
---------

See [CHANGELOG.md](CHANGELOG.md) for a list of changes made throughout past versions.

Tests
-----

To run all tests, execute `cargo test --all-features`. This includes known-answer tests.

Classical (i.e., non-post-quantum) ciphersuites test against `test-vectors/origrfc-COMMIT_ID.json`,where `COMMIT_ID` is the short commit of the version of the [spec](https://github.com/cfrg/draft-irtf-cfrg-hpke) that the test vectors came from. The finalized spec uses commit `5f503c5`. See the [reference implementation](https://github.com/cisco/go-hpke) for information on how to generate a test vector.

Post-quantum ciphersuites (including hybrid), test against `test-vectors/pq-COMMIT_ID.json` in the same way. The commit ID refers to the [reference implementation](https://github.com/hpkewg/hpke-pq) repo of the PQ extension standard.

Hybrid ciphersuites are additionally tested against `test-vectors/hybrid-COMMIT_ID.json`. The commit ID refers to the concrete hybrid HPKE spec [repo](https://github.com/cfrg/draft-irtf-cfrg-concrete-hybrid-kems).

Benchmarks
----------

To run all benchmarks, execute `cargo bench --all-features`. If you set your own feature flags, the benchmarks will still work, and run the subset of benches that it is able to. The results of a benchmark can be read as a neat webpage at `target/criterion/report/index.html`.

Ciphersuites benchmarked:

* Classical NIST Ciphersuite with 128-bit security: AES-GCM-128, HKDF-SHA256, ECDH-P256
* Classical Non-NIST Ciphersuite with 128-bit security: ChaCha20-Poly1305, HKDF-SHA256, X25519
* Pure-PQ NIST Ciphersuite with 128-bit security: AES-GCM-128, SHAKE128, MLKEM768
* Pure-PQ NIST Ciphersuite with 256-bit security: AES-GCM-256, SHAKE256, MLKEM1024
* Hybrid-PQ NIST Ciphersuite with 128-bit security: AES-GCM-128, SHAKE128, MLKEM768-P256
* Hybrid-PQ NIST Ciphersuite with 256-bit security: AES-GCM-256, SHAKE256, MLKEM1024-P384
* Hybrid-PQ Non-NIST Ciphersuite with 128-bit security: ChaCha20-Poly1305, TurboSHAKE128, XWing

Functions benchmarked in each ciphersuite:

* `Kem::gen_keypair`
* `setup_sender` with OpModes of Base, Auth, Psk, and AuthPsk (Auth* modes omitted if unsupported)
* `setup_receiver` with OpModes of Base, Auth, Psk, and AuthPsk (Auth* modes omitted if unsupported)
* `AeadCtxS::seal` with plaintext length 64 and AAD length 64
* `AeadCtxR::open` with ciphertext length 64 and AAD length 64

Audit History
-------------

To the authors' knowledge, nobody has performed a paid audit of this crate. However, Cloudflare [did a security](https://blog.cloudflare.com/using-hpke-to-encrypt-request-payloads/) review of version 0.8, saying:

> The HPKE implementation we decided on comes with the caveat of not yet being
> formally audited, so we performed our own internal security review. We
> analyzed the cryptography primitives being used and the corresponding
> libraries. Between the composition of said primitives and secure programming
> practices like correctly zeroing memory and safe usage of random number
> generators, we found no security issues.

Agility
-------

A definition: *crypto agility* refers to the ability of a cryptosystem or protocol to vary its underlying primitives. For example, TLS has "crypto agility" in that you can run the protocol with many different ciphersuites.

This crate does not support crypto agility out of the box. This is because the cryptographic primitives are encoded as types satisfying certain constraints, and types need to be determined at compile time (broadly speaking). Purely for the sake of demonstration, there is a [sample implementation](examples/agility.rs) in the examples folder. The sample implementation is messy because agility is messy.

If you want agility, you can use the [`hpke-dispatch`](https://crates.io/crates/hpke-dispatch) crate.

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
