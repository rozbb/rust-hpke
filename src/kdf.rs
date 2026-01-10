//! Traits and structs for key derivation functions

use crate::{
    aead::{Aead, AeadCtx},
    kem::{Kem as KemTrait, SharedSecret},
    op_mode::OpMode,
    setup::ExporterSecret,
    util::{full_suite_id, write_u16_be},
};

use digest::{Digest, OutputSizeUser};
use hmac::EagerHash;
use hybrid_array::Array;
use sha2::{Sha256, Sha384, Sha512};

pub(crate) const VERSION_LABEL: &[u8] = b"HPKE-v1";

// This is the maximum value of Nh. It is achieved by HKDF-SHA512 in RFC 9180 §7.2.
pub(crate) const MAX_DIGEST_SIZE: usize = 64;

// Pretty much all the KDF functionality is covered by the hkdf crate

/// Represents key derivation functionality
pub trait Kdf: Sized {
    /// The underlying hash function
    #[doc(hidden)]
    type HashImpl: Clone + Digest + EagerHash;

    /// The algorithm identifier for a KDF implementation
    const KDF_ID: u16;

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
}

// We use Kdf as a type parameter, so this is to avoid ambiguity.
use Kdf as KdfTrait;

// Convenience types for the functions below
pub(crate) type DigestArray<Kdf> =
    Array<u8, <<<Kdf as KdfTrait>::HashImpl as EagerHash>::Core as OutputSizeUser>::OutputSize>;
pub(crate) type SimpleHkdf<Kdf> = hkdf::Hkdf<<Kdf as KdfTrait>::HashImpl>;
type SimpleHkdfExtract<Kdf> = hkdf::HkdfExtract<<Kdf as KdfTrait>::HashImpl>;

/// The implementation of HKDF-SHA256
pub struct HkdfSha256 {}

impl KdfTrait for HkdfSha256 {
    #[doc(hidden)]
    type HashImpl = Sha256;

    // RFC 9180 §7.2: HKDF-SHA256
    const KDF_ID: u16 = 0x0001;

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
        combine_secrets_two_stage(mode, shared_secret, info)
    }
}

/// The implementation of HKDF-SHA384
pub struct HkdfSha384 {}

impl KdfTrait for HkdfSha384 {
    #[doc(hidden)]
    type HashImpl = Sha384;

    // RFC 9180 §7.2: HKDF-SHA384
    const KDF_ID: u16 = 0x0002;

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
        combine_secrets_two_stage(mode, shared_secret, info)
    }
}

/// The implementation of HKDF-SHA512
pub struct HkdfSha512 {}

impl KdfTrait for HkdfSha512 {
    #[doc(hidden)]
    type HashImpl = Sha512;

    // RFC 9180 §7.2: HKDF-SHA512
    const KDF_ID: u16 = 0x0003;

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
        combine_secrets_two_stage(mode, shared_secret, info)
    }
}

// RFC 9180 §4.1
// def ExtractAndExpand(dh, kem_context):
//   eae_prk = LabeledExtract("", "eae_prk", dh)
//   shared_secret = LabeledExpand(eae_prk, "shared_secret",
//                                 kem_context, Nsecret)
//   return shared_secret

/// Uses the given IKM to extract a secret, and then uses that secret, plus the given suite ID and
/// info string, to expand to the output buffer
#[doc(hidden)]
pub fn extract_and_expand<Kdf: KdfTrait>(
    ikm: &[u8],
    suite_id: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    // Extract using given IKM
    let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"eae_prk", ikm);
    // Expand using given info string
    hkdf_ctx.labeled_expand(suite_id, b"shared_secret", info, out)
}

// RFC 9180 §4
// def LabeledExtract(salt, label, ikm):
//   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
//   return Extract(salt, labeled_ikm)

/// Returns the HKDF context derived from `(salt=salt, ikm="HPKE-v1"||suite_id||label||ikm)`
#[doc(hidden)]
pub fn labeled_extract<Kdf: KdfTrait>(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (DigestArray<Kdf>, SimpleHkdf<Kdf>) {
    // Call HKDF-Extract with the IKM being the concatenation of all of the above
    let mut extract_ctx = SimpleHkdfExtract::<Kdf>::new(Some(salt));
    extract_ctx.input_ikm(VERSION_LABEL);
    extract_ctx.input_ikm(suite_id);
    extract_ctx.input_ikm(label);
    extract_ctx.input_ikm(ikm);
    extract_ctx.finalize()
}

// This trait only exists so I can implement it for hkdf::Hkdf
#[doc(hidden)]
pub trait LabeledExpand {
    /// Does a `LabeledExpand` key derivation function using HKDF. If `out.len()` is more than 255x
    /// the digest size (in bytes) of the underlying hash function, returns an
    /// `Err(hkdf::InvalidLength)`.
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength>;
}

impl<D> LabeledExpand for hkdf::Hkdf<D>
where
    D: Clone + EagerHash,
{
    // RFC 9180 §4
    // def LabeledExpand(prk, label, info, L):
    //   labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
    //                         label, info)
    //   return Expand(prk, labeled_info, L)

    /// Does a `LabeledExpand` key derivation function using HKDF. If `out.len()` is more than 255x
    /// the digest size (in bytes) of the underlying hash function, returns an
    /// `Err(hkdf::InvalidLength)`.
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength> {
        // We need to write the length as a u16, so that's the de-facto upper bound on length
        if out.len() > u16::MAX as usize {
            // The error condition is met, since 2^16 is way bigger than 255 * digest_bytelen
            return Err(hkdf::InvalidLength);
        }

        // Encode the output length in the info string
        let mut len_buf = [0u8; 2];
        write_u16_be(&mut len_buf, out.len() as u16);

        // Call HKDF-Expand() with the info string set to the concatenation of all of the above
        let labeled_info = [&len_buf, VERSION_LABEL, suite_id, label, info];
        self.expand_multi_info(&labeled_info, out)
    }
}

// This is the KeySchedule function. It runs a KDF over all the parameters, inputs, and secrets,
// and spits out a key-nonce pair to be used for symmetric encryption.
fn combine_secrets_two_stage<A, Kdf, Kem, O>(
    mode: &O,
    shared_secret: SharedSecret<Kem>,
    info: &[u8],
) -> AeadCtx<A, Kdf, Kem>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
    O: OpMode<Kem>,
{
    // Put together the binding context used for all KDF operations
    let suite_id = full_suite_id::<A, Kdf, Kem>();

    // In KeySchedule(),
    //   psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    //   info_hash = LabeledExtract("", "info_hash", info)
    //   key_schedule_context = concat(mode, psk_id_hash, info_hash)

    // We concat without allocation by making a buffer of the maximum possible size, then
    // taking the appropriately sized slice.
    let (sched_context_buf, sched_context_size) = {
        let (psk_id_hash, _) =
            labeled_extract::<Kdf>(&[], &suite_id, b"psk_id_hash", mode.get_psk_id());
        let (info_hash, _) = labeled_extract::<Kdf>(&[], &suite_id, b"info_hash", info);

        // Yes it's overkill to bound the first input by MAX_DIGEST_SIZE, since it's only 1 byte.
        // But whatever, this is pretty clean.
        concat_with_known_maxlen!(
            MAX_DIGEST_SIZE,
            &[mode.mode_id()],
            psk_id_hash.as_slice(),
            info_hash.as_slice()
        )
    };
    let sched_context = &sched_context_buf[..sched_context_size];

    // In KeySchedule(),
    //   secret = LabeledExtract(shared_secret, "secret", psk)
    //   key = LabeledExpand(secret, "key", key_schedule_context, Nk)
    //   base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
    //   exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, Nh)
    // Instead of `secret` we derive an HKDF context which we run .expand() on to derive the
    // key-nonce pair.
    let (_, secret_ctx) =
        labeled_extract::<Kdf>(&shared_secret.0, &suite_id, b"secret", mode.get_psk_bytes());

    // Empty fixed-size buffers
    let mut key = crate::aead::AeadKey::<A>::default();
    let mut base_nonce = crate::aead::AeadNonce::<A>::default();
    let mut exporter_secret = <ExporterSecret<Kdf> as Default>::default();

    // Fill the key, base nonce, and exporter secret. This only errors if the output values are
    // 255x the digest size of the hash function. Since these values are fixed at compile time, we
    // don't worry about it.
    secret_ctx
        .labeled_expand(&suite_id, b"key", sched_context, key.0.as_mut_slice())
        .expect("aead key len is way too big");
    secret_ctx
        .labeled_expand(
            &suite_id,
            b"base_nonce",
            sched_context,
            base_nonce.0.as_mut_slice(),
        )
        .expect("nonce len is way too big");
    secret_ctx
        .labeled_expand(
            &suite_id,
            b"exp",
            sched_context,
            exporter_secret.0.as_mut_slice(),
        )
        .expect("exporter secret len is way too big");

    AeadCtx::new(&key, base_nonce, exporter_secret)
}
