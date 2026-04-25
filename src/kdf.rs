//! Traits and structs for key derivation functions

use crate::{
    aead::{Aead, AeadCtx},
    kem::{Kem as KemTrait, SharedSecret},
    op_mode::OpMode,
    util::KemSuiteId,
    HpkeError,
};

use hybrid_array::{
    typenum::{U32, U48, U64},
    Array, ArraySize,
};
use sha2::{Sha256, Sha384, Sha512};

pub(crate) mod one_stage_kdf;
mod two_stage_kdf;

pub(crate) const VERSION_LABEL: &[u8] = b"HPKE-v1";

// This is the maximum value of Nh. It is achieved by HKDF-SHA512 in RFC 9180 §7.2.
pub(crate) const MAX_DIGEST_SIZE: usize = 64;

// Pretty much all the KDF functionality is covered by the hkdf crate

/// Represents key derivation functionality
pub trait Kdf: Sized {
    /// The algorithm identifier for a KDF implementation
    #[doc(hidden)]
    const KDF_ID: u16;

    /// The security strength of the KDF, in bytes
    #[doc(hidden)]
    type Nh: ArraySize;

    /// Combines the context of the given mode and info string into the shared secret. Produces an
    /// encryption context using the resulting key material.
    ///
    /// # Panics
    /// Panics if `info.len() + mode.get_psk_id().len() + 5` ≥ 2¹⁶
    #[doc(hidden)]
    fn combine_secrets<A, Kem, O>(
        mode: &O,
        shared_secret: SharedSecret<Kem>,
        info: &[u8],
    ) -> AeadCtx<A, Self, Kem>
    where
        A: Aead,
        Kem: KemTrait,
        O: OpMode<Kem>;

    /// Extracts randomness from `ikm`, binds it to the given suite ID and info string, and expands
    /// the result to fill the output buffer.  If `out.len()` is more than 255x the digest size (in
    /// bytes) of the underlying hash function, returns an `Err(hkdf::InvalidLength)`.
    #[doc(hidden)]
    fn extract_and_expand(
        ikm: &[u8],
        suite_id: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength>;

    /// Derives bytes for a use as a P256/P384/P521 ephemeral secret. Counter is because it may
    /// require multiple attempts to find a valid scalar. The keying material SHOULD have as many
    /// bits of entropy as the bit length of a secret key.
    #[doc(hidden)]
    fn derive_nistp_sk_eph_bytes<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize>;

    /// Derives bytes for a use as an x25519 ephemeral secret. There is no counter because no
    /// retries are necessary; every output is a valid secret key. The keying material SHOULD have
    /// as many bits of entropy as the bit length of a secret key, i.e., 256.
    #[doc(hidden)]
    fn derive_x25519_sk_eph_bytes(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32];

    /// Constructs the export secret of an encryption context. Returns
    /// `Err(HpkeError::KdfOutputTooLong)` if `out_buf.len()` ≥ 2¹⁶.
    #[doc(hidden)]
    fn export(
        exporter_secret: &[u8],
        suite_id: &[u8],
        exporter_ctx: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(), HpkeError>;
}

// We use Kdf as a type parameter, so this is to avoid ambiguity.
use sha3::{Shake128, Shake256};
use Kdf as KdfTrait;

// Convenience types for the functions below
//pub(crate) type DigestArray<Kdf> =
//    Array<u8, <<<Kdf as KdfTrait>::HashImpl as EagerHash>::Core as OutputSizeUser>::OutputSize>;
pub(crate) type DigestArray<Kdf> = Array<u8, <Kdf as KdfTrait>::Nh>;

//
// Implement KdfTrait for all our KDFs. Call the one- or two-stage implementation for each of them
//

/// The implementation of HKDF-SHA256
pub struct HkdfSha256 {}

impl KdfTrait for HkdfSha256 {
    // RFC 9180 §7.2: HKDF-SHA256
    const KDF_ID: u16 = 0x0001;
    type Nh = U32;

    fn combine_secrets<A, Kem, O>(
        mode: &O,
        shared_secret: SharedSecret<Kem>,
        info: &[u8],
    ) -> AeadCtx<A, Self, Kem>
    where
        A: Aead,
        Kem: KemTrait,
        O: OpMode<Kem>,
    {
        two_stage_kdf::combine_secrets::<_, Sha256, _, _, _>(mode, shared_secret, info)
    }

    fn extract_and_expand(
        ikm: &[u8],
        suite_id: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength> {
        two_stage_kdf::extract_and_expand::<Sha256>(ikm, suite_id, info, out)
    }

    fn derive_x25519_sk_eph_bytes(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        two_stage_kdf::derive_x25519_sk_eph_bytes::<Sha256>(suite_id, ikm)
    }

    fn derive_nistp_sk_eph_bytes<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        two_stage_kdf::derive_nistp_sk_eph_bytes::<Sha256, PrivateKeySize>(suite_id, ikm, counter)
    }

    fn export(
        exporter_secret: &[u8],
        suite_id: &[u8],
        exporter_ctx: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(), HpkeError> {
        two_stage_kdf::export::<Sha256>(exporter_secret, suite_id, exporter_ctx, out_buf)
    }
}

/// The implementation of HKDF-SHA384
pub struct HkdfSha384 {}

impl KdfTrait for HkdfSha384 {
    // RFC 9180 §7.2: HKDF-SHA384
    const KDF_ID: u16 = 0x0002;
    type Nh = U48;

    fn combine_secrets<A, Kem, O>(
        mode: &O,
        shared_secret: SharedSecret<Kem>,
        info: &[u8],
    ) -> AeadCtx<A, Self, Kem>
    where
        A: Aead,
        Kem: KemTrait,
        O: OpMode<Kem>,
    {
        two_stage_kdf::combine_secrets::<_, Sha384, _, _, _>(mode, shared_secret, info)
    }

    fn extract_and_expand(
        ikm: &[u8],
        suite_id: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength> {
        two_stage_kdf::extract_and_expand::<Sha384>(ikm, suite_id, info, out)
    }

    fn derive_x25519_sk_eph_bytes(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        two_stage_kdf::derive_x25519_sk_eph_bytes::<Sha384>(suite_id, ikm)
    }

    fn derive_nistp_sk_eph_bytes<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        two_stage_kdf::derive_nistp_sk_eph_bytes::<Sha384, PrivateKeySize>(suite_id, ikm, counter)
    }

    fn export(
        exporter_secret: &[u8],
        suite_id: &[u8],
        exporter_ctx: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(), HpkeError> {
        two_stage_kdf::export::<Sha384>(exporter_secret, suite_id, exporter_ctx, out_buf)
    }
}

/// The implementation of HKDF-SHA512
pub struct HkdfSha512 {}

impl KdfTrait for HkdfSha512 {
    // RFC 9180 §7.2: HKDF-SHA512
    const KDF_ID: u16 = 0x0003;
    type Nh = U64;

    fn combine_secrets<A, Kem, O>(
        mode: &O,
        shared_secret: SharedSecret<Kem>,
        info: &[u8],
    ) -> AeadCtx<A, Self, Kem>
    where
        A: Aead,
        Kem: KemTrait,
        O: OpMode<Kem>,
    {
        two_stage_kdf::combine_secrets::<_, Sha512, _, _, _>(mode, shared_secret, info)
    }

    fn extract_and_expand(
        ikm: &[u8],
        suite_id: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength> {
        two_stage_kdf::extract_and_expand::<Sha512>(ikm, suite_id, info, out)
    }

    fn derive_x25519_sk_eph_bytes(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        two_stage_kdf::derive_x25519_sk_eph_bytes::<Sha512>(suite_id, ikm)
    }

    fn derive_nistp_sk_eph_bytes<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        two_stage_kdf::derive_nistp_sk_eph_bytes::<Sha512, PrivateKeySize>(suite_id, ikm, counter)
    }

    fn export(
        exporter_secret: &[u8],
        suite_id: &[u8],
        exporter_ctx: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(), HpkeError> {
        two_stage_kdf::export::<Sha512>(exporter_secret, suite_id, exporter_ctx, out_buf)
    }
}

/// The implementation of SHAKE256 KDF
pub struct KdfShake128 {}

impl KdfTrait for KdfShake128 {
    // https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03#section-5
    const KDF_ID: u16 = 0x0010;
    type Nh = U32;

    fn combine_secrets<A, Kem, O>(
        mode: &O,
        shared_secret: SharedSecret<Kem>,
        info: &[u8],
    ) -> AeadCtx<A, Self, Kem>
    where
        A: Aead,
        Kem: KemTrait,
        O: OpMode<Kem>,
    {
        one_stage_kdf::combine_secrets::<_, Shake128, _, _, _>(mode, shared_secret, info)
    }

    fn extract_and_expand(
        ikm: &[u8],
        suite_id: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength> {
        one_stage_kdf::extract_and_expand::<Shake128>(ikm, suite_id, info, out);
        Ok(())
    }

    fn derive_x25519_sk_eph_bytes(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        one_stage_kdf::derive_x25519_sk_eph_bytes::<Shake128>(suite_id, ikm)
    }

    fn derive_nistp_sk_eph_bytes<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        one_stage_kdf::derive_nistp_sk_eph_bytes::<Shake128, PrivateKeySize>(suite_id, ikm, counter)
    }

    fn export(
        exporter_secret: &[u8],
        suite_id: &[u8],
        exporter_ctx: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(), HpkeError> {
        one_stage_kdf::export::<Shake128>(exporter_secret, suite_id, exporter_ctx, out_buf)
    }
}

/// The implementation of SHAKE256 KDF
pub struct KdfShake256 {}

impl KdfTrait for KdfShake256 {
    // https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03#section-5
    const KDF_ID: u16 = 0x0011;
    type Nh = U64;

    fn combine_secrets<A, Kem, O>(
        mode: &O,
        shared_secret: SharedSecret<Kem>,
        info: &[u8],
    ) -> AeadCtx<A, Self, Kem>
    where
        A: Aead,
        Kem: KemTrait,
        O: OpMode<Kem>,
    {
        one_stage_kdf::combine_secrets::<_, Shake256, _, _, _>(mode, shared_secret, info)
    }

    fn extract_and_expand(
        ikm: &[u8],
        suite_id: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength> {
        one_stage_kdf::extract_and_expand::<Shake256>(ikm, suite_id, info, out);
        Ok(())
    }

    fn derive_x25519_sk_eph_bytes(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        one_stage_kdf::derive_x25519_sk_eph_bytes::<Shake256>(suite_id, ikm)
    }

    fn derive_nistp_sk_eph_bytes<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        one_stage_kdf::derive_nistp_sk_eph_bytes::<Shake256, PrivateKeySize>(suite_id, ikm, counter)
    }

    fn export(
        exporter_secret: &[u8],
        suite_id: &[u8],
        exporter_ctx: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(), HpkeError> {
        one_stage_kdf::export::<Shake256>(exporter_secret, suite_id, exporter_ctx, out_buf)
    }
}
