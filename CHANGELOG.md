# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2023-10-11

### Removals

* Removed the redundant re-export of the first encapsulated key type as `kem::EncappedKey`

### Changes

* Updated `x25519-dalek` to 2.0
* Updated `subtle` to 2.5

## [0.10.0] - 2022-10-01

### Additions
* Added `alloc` feature and feature-gated the `open()` and `seal()` methods behind it

### Changes
* Bumped MSRV from 1.56.1 (`59eed8a2a` 2021-11-01) to 1.57.0 (`f1edd0429` 2021-11-29)
* Updated dependencies and weakened `zeroize` dependency from `>=1.3` to just `^1`
* Improved documentation for the AEAD `export()` method and the KDF `labeled_expand()` method

## [0.9.0] - 2022-05-04

### Additions
* Refactored some internals so end users can theoretically define their own KEMs. See PR [#27](https://github.com/rozbb/rust-hpke/pull/27).

### Changes
* Bumped MSRV from 1.51.0 (`2fd73fabe` 2021-03-23) to 1.56.1 (`59eed8a2a` 2021-11-01)
* Updated dependencies
