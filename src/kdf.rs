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
    const KDF_ID: u16;
    type Nh: ArraySize;

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

    fn extract_and_expand(
        ikm: &[u8],
        suite_id: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength>;

    /// Derives 32 bytes for use as an X25519 secret key
    fn derive_candidate_nocounter(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32];

    /// Derives bytes for a use as a P256/P384/P521 secret key. Counter is because it may require
    /// multiple attempts to find a valid secret key.
    fn derive_candidate<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize>;

    /// Constructs the export secret of an encryption context
    fn export(
        exporter_secret: &[u8],
        suite_id: &[u8],
        exporter_ctx: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(), HpkeError>;
}

// We use Kdf as a type parameter, so this is to avoid ambiguity.
use sha3::Shake256;
use Kdf as KdfTrait;

// Convenience types for the functions below
//pub(crate) type DigestArray<Kdf> =
//    Array<u8, <<<Kdf as KdfTrait>::HashImpl as EagerHash>::Core as OutputSizeUser>::OutputSize>;
pub(crate) type DigestArray<Kdf> = Array<u8, <Kdf as KdfTrait>::Nh>;

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

    fn derive_candidate_nocounter(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        two_stage_kdf::derive_candidate_nocounter::<Sha256>(suite_id, ikm)
    }

    fn derive_candidate<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        two_stage_kdf::derive_candidate::<Sha256, PrivateKeySize>(suite_id, ikm, counter)
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

    fn derive_candidate_nocounter(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        two_stage_kdf::derive_candidate_nocounter::<Sha384>(suite_id, ikm)
    }

    fn derive_candidate<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        two_stage_kdf::derive_candidate::<Sha384, PrivateKeySize>(suite_id, ikm, counter)
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

    fn derive_candidate_nocounter(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        two_stage_kdf::derive_candidate_nocounter::<Sha512>(suite_id, ikm)
    }

    fn derive_candidate<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        two_stage_kdf::derive_candidate::<Sha512, PrivateKeySize>(suite_id, ikm, counter)
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

    fn derive_candidate_nocounter(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32] {
        one_stage_kdf::derive_candidate_nocounter::<Shake256>(suite_id, ikm)
    }

    fn derive_candidate<PrivateKeySize: ArraySize>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
        counter: u8,
    ) -> Array<u8, PrivateKeySize> {
        one_stage_kdf::derive_candidate::<Shake256, PrivateKeySize>(suite_id, ikm, counter)
    }

    fn export(
        exporter_secret: &[u8],
        suite_id: &[u8],
        exporter_ctx: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(), HpkeError> {
        one_stage_kdf::export::<Shake256>(exporter_secret, suite_id, exporter_ctx, out_buf);
        Ok(())
    }
}
