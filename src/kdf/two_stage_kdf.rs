//! Helper functions for two-stage KDFs

use crate::{
    aead::{Aead, AeadCtx},
    kdf::{KdfTrait, MAX_DIGEST_SIZE, VERSION_LABEL},
    kem::{Kem as KemTrait, SharedSecret},
    op_mode::OpMode,
    setup::ExporterSecret,
    util::{full_suite_id, write_u16_be, KemSuiteId},
    HpkeError,
};

use hkdf::{hmac::EagerHash, Hkdf, HkdfExtract};
use hybrid_array::{Array, ArraySize};
use sha2::digest::{Digest, OutputSizeUser};

// RFC 9180 §4.1
// def ExtractAndExpand(dh, kem_context):
//   eae_prk = LabeledExtract("", "eae_prk", dh)
//   shared_secret = LabeledExpand(eae_prk, "shared_secret",
//                                 kem_context, Nsecret)
//   return shared_secret

/// Uses the given IKM to extract a secret, and then uses that secret, plus the given suite ID and
/// info string, to expand to the output buffer. Uses HKDF rather than XOF.
///
/// If `out.len()` is more than 255x the digest size (in bytes) of the underlying hash function,
/// returns an `Err(hkdf::InvalidLength)`.
pub(crate) fn extract_and_expand<H>(
    ikm: &[u8],
    suite_id: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), hkdf::InvalidLength>
where
    H: Clone + Digest + EagerHash,
{
    // Extract using given IKM
    let (_, hkdf_ctx) = labeled_extract::<H>(&[], suite_id, b"eae_prk", ikm);
    // Expand using given info string
    labeled_expand(&hkdf_ctx, suite_id, b"shared_secret", info, out)
}

// RFC 9180 §4
// def LabeledExtract(salt, label, ikm):
//   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
//   return Extract(salt, labeled_ikm)

/// Returns the HKDF context derived from `(salt=salt, ikm="HPKE-v1"||suite_id||label||ikm)`
fn labeled_extract<H>(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (
    Array<u8, <<H as EagerHash>::Core as OutputSizeUser>::OutputSize>,
    Hkdf<H>,
)
where
    H: Clone + Digest + EagerHash,
{
    // Call HKDF-Extract with the IKM being the concatenation of all of the above
    let mut extract_ctx = HkdfExtract::<H>::new(Some(salt));
    extract_ctx.input_ikm(VERSION_LABEL);
    extract_ctx.input_ikm(suite_id);
    extract_ctx.input_ikm(label);
    extract_ctx.input_ikm(ikm);
    extract_ctx.finalize()
}

// RFC 9180 §4
// def LabeledExpand(prk, label, info, L):
//   labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
//                         label, info)
//   return Expand(prk, labeled_info, L)

/// Does a `LabeledExpand` key derivation function using HKDF. If `out.len()` is more than 255x the
/// digest size (in bytes) of the underlying hash function, returns an `Err(hkdf::InvalidLength)`.
fn labeled_expand<D: Clone + EagerHash>(
    hkdf_ctx: &Hkdf<D>,
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
    hkdf_ctx.expand_multi_info(&labeled_info, out)
}

// This is the KeySchedule function. It runs a KDF over all the parameters, inputs, and secrets,
// and spits out a key-nonce pair to be used for symmetric encryption.
pub(crate) fn combine_secrets<A, H, Kdf, Kem, O>(
    mode: &O,
    shared_secret: SharedSecret<Kem>,
    info: &[u8],
) -> AeadCtx<A, Kdf, Kem>
where
    A: Aead,
    H: Clone + Digest + EagerHash,
    Kdf: KdfTrait,
    Kem: KemTrait,
    O: OpMode<Kem>,
{
    // Put together the binding context used for all KDF operations
    let suite_id = full_suite_id::<A, Kdf, Kem>();

    // In KeySchedule() in RFC 9180,
    //   psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    //   info_hash = LabeledExtract("", "info_hash", info)
    //   key_schedule_context = concat(mode, psk_id_hash, info_hash)

    // We concat without allocation by making a buffer of the maximum possible size, then
    // taking the appropriately sized slice.
    let (sched_context_buf, sched_context_size) = {
        let (psk_id_hash, _) =
            labeled_extract::<H>(&[], &suite_id, b"psk_id_hash", mode.get_psk_id());
        let (info_hash, _) = labeled_extract::<H>(&[], &suite_id, b"info_hash", info);

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
        labeled_extract::<H>(&shared_secret.0, &suite_id, b"secret", mode.get_psk_bytes());

    // Empty fixed-size buffers
    let mut key = crate::aead::AeadKey::<A>::default();
    let mut base_nonce = crate::aead::AeadNonce::<A>::default();
    let mut exporter_secret = <ExporterSecret<Kdf> as Default>::default();

    // Fill the key, base nonce, and exporter secret. This only errors if the output values are
    // 255x the digest size of the hash function. Since these values are fixed at compile time, we
    // don't worry about it.
    labeled_expand(
        &secret_ctx,
        &suite_id,
        b"key",
        sched_context,
        key.0.as_mut_slice(),
    )
    .expect("aead key len is way too big");
    labeled_expand(
        &secret_ctx,
        &suite_id,
        b"base_nonce",
        sched_context,
        base_nonce.0.as_mut_slice(),
    )
    .expect("nonce len is way too big");
    labeled_expand(
        &secret_ctx,
        &suite_id,
        b"exp",
        sched_context,
        exporter_secret.0.as_mut_slice(),
    )
    .expect("exporter secret len is way too big");

    AeadCtx::new(&key, base_nonce, exporter_secret)
}

// RFC 9180 §7.1.3
// def DeriveKeyPair(ikm):
//   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
//   sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
//   return (sk, pk(sk))

/// Derive secret key bytes for x25519 using a two-stage KDF
pub(crate) fn derive_x25519_sk_eph_bytes<H>(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32]
where
    H: Clone + Digest + EagerHash,
{
    // Write the label into a byte buffer and extract from the IKM
    let (_, hkdf_ctx) = labeled_extract::<H>(&[], suite_id, b"dkp_prk", ikm);
    // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
    let mut buf = [0u8; 32];
    labeled_expand(&hkdf_ctx, suite_id, b"sk", &[], &mut buf).unwrap();

    buf
}

// RFC 9180 §7.1.3:
// def DeriveKeyPair(ikm):
//   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
//   sk = 0
//   counter = 0
//   while sk == 0 or sk >= order:
//     if counter > 255:
//       raise DeriveKeyPairError
//     bytes = LabeledExpand(dkp_prk, "candidate",
//                           I2OSP(counter, 1), Nsk)
//     bytes[0] = bytes[0] & bitmask
//     sk = OS2IP(bytes)
//     counter = counter + 1
//   return (sk, pk(sk))
// where `bitmask` is defined to be 0xFF for P-256 and P-384, and 0x01 for P-521

/// Derive candidate secret key bytes for p256/p384/p521 using a two-stage KDF
pub(crate) fn derive_nistp_sk_eph_bytes<H, PrivateKeySize>(
    suite_id: &KemSuiteId,
    ikm: &[u8],
    counter: u8,
) -> Array<u8, PrivateKeySize>
where
    H: Clone + Digest + EagerHash,
    PrivateKeySize: ArraySize,
{
    // Write the label into a byte buffer and extract from the IKM
    let (_, hkdf_ctx) = labeled_extract::<H>(&[], suite_id, b"dkp_prk", ikm);

    // The buffer we hold the candidate scalar bytes in. This is the size of a
    // private key.
    let mut buf = Array::<u8, PrivateKeySize>::default();

    // This unwrap is fine. It only triggers if buf is way too big. It's only
    // 32 bytes.
    labeled_expand(&hkdf_ctx, suite_id, b"candidate", &[counter], &mut buf).unwrap();

    buf
}

// RFC 9180 §5.3
// def Context.Export(exporter_context, L):
//   return LabeledExpand(self.exporter_secret, "sec",
//                        exporter_context, L)

/// Derive an exporter secret using a two-stage KDF. Returns `Err(HpkeError::KdfOutputTooLong)` if
/// `out_buf.len()` ≥ 2¹⁶.
pub(crate) fn export<H>(
    exporter_secret: &[u8],
    suite_id: &[u8],
    exporter_ctx: &[u8],
    out_buf: &mut [u8],
) -> Result<(), HpkeError>
where
    H: Clone + Digest + EagerHash,
{
    // Use our exporter secret as the PRK for an HKDF-Expand op. The only time this fails is
    // when the length of the PRK is not the the underlying hash function's digest size. But
    // that's guaranteed by the type system, so we can unwrap().
    let hkdf_ctx = Hkdf::<H>::from_prk(exporter_secret).unwrap();

    // This call either succeeds or returns hkdf::InvalidLength (iff the buffer length is more
    // than 255x the digest size of the underlying hash function)
    labeled_expand(&hkdf_ctx, suite_id, b"sec", exporter_ctx, out_buf)
        .map_err(|_| HpkeError::KdfOutputTooLong)
}
