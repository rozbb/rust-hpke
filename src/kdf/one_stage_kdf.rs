//! Helper functions for one-stage KDFs

use crate::{
    aead::{Aead, AeadCtx},
    kdf::{KdfTrait, VERSION_LABEL},
    kem::{Kem as KemTrait, SharedSecret},
    op_mode::OpMode,
    setup::ExporterSecret,
    util::{full_suite_id, write_u16_be, KemSuiteId},
    HpkeError,
};

use hybrid_array::{Array, ArraySize};
use sha3::digest::{ExtendableOutput, XofReader};

// §4.1 in https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02
//
// def ExtractAndExpand_OneStage(dh, kem_context):
//   return LabeledDerive(dh, "shared_secret", kem_context, Nsecret)

/// Uses the given IKM to extract a secret, and then uses that secret, plus the given suite ID and
/// info string, to expand to the output buffer. Uses XOF rather  than HKDF.
pub(crate) fn extract_and_expand<H>(ikm: &[u8], suite_id: &[u8], info: &[u8], out: &mut [u8])
where
    H: ExtendableOutput + Default,
{
    labeled_derive::<H>(suite_id, &[ikm], b"shared_secret", &[info], out)
}

// From https://www.ietf.org/archive/id/draft-ietf-hpke-hpke-02.html#section-4-9
//
// # For use with one-stage KDFs
// def LabeledDerive(ikm, label, context, L):
//   labeled_ikm = concat(
//     ikm,
//     "HPKE-v1",
//     suite_id,
//     lengthPrefixed(label),
//     I2OSP(L, 2)
//     context,
//   )
//   return Derive(labeled_ikm, L)

/// Does some domain separation, hashes in all the data, and writes to `out` until `out` is filled
/// with new bytes.
///
/// # Panics
/// Panics if `label.len()` ≥ 2¹⁶ or `out.len()` ≥ 2¹⁶.
pub(crate) fn labeled_derive<H>(
    suite_id: &[u8],
    ikm: &[&[u8]],
    label: &[u8],
    context: &[&[u8]],
    out: &mut [u8],
) where
    H: ExtendableOutput + Default,
{
    // Encode the label and output buffer lengths
    let label_len = buf_len_u16(label);
    let out_len = buf_len_u16(out);

    let mut h = H::default();
    ikm.iter().for_each(|k| h.update(k));
    h.update(VERSION_LABEL);
    h.update(suite_id);
    h.update(&label_len);
    h.update(label);
    h.update(&out_len);
    context.iter().for_each(|c| h.update(c));

    h.finalize_xof().read(out);
}

// §5.1 in https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02
//
// # For use with a one-stage KDF
// def CombineSecrets_OneStage(mode, shared_secret, info, psk, psk_id):
//   secrets = concat(
//     lengthPrefixed(psk),
//     lengthPrefixed(shared_secret),
//   )
//   context = concat(
//     mode,
//     lengthPrefixed(psk_id),
//     lengthPrefixed(info),
//   )
//
//   secret = LabeledDerive(secrets, "secret", context, Nk + Nn + Nh)
//
//   key = secret[:Nk]
//   base_nonce = secret[Nk:(Nk + Nn)]
//   exporter_secret = secret[(Nk + Nn):]
//
//   return (key, base_nonce, exporter_secret)

/// This is the KeySchedule function. It runs a KDF over all the parameters, inputs, and secrets,
/// and spits out a symmetric encryption context.
///
/// # Panics
/// Panics if `info.len() + mode.get_psk_id().len() + 5` ≥ 2¹⁶
pub(crate) fn combine_secrets<A, H, Kdf, Kem, O>(
    mode: &O,
    shared_secret: SharedSecret<Kem>,
    info: &[u8],
) -> AeadCtx<A, Kdf, Kem>
where
    A: Aead,
    H: ExtendableOutput + Default,
    Kdf: KdfTrait,
    Kem: KemTrait,
    O: OpMode<Kem>,
{
    // Put together the binding context used for all KDF operations
    let suite_id = full_suite_id::<A, Kdf, Kem>();

    let psk = mode.get_psk_bytes();
    let psk_id = mode.get_psk_id();
    let secrets = &[
        &buf_len_u16(psk),
        psk,
        &buf_len_u16(&shared_secret.0),
        &shared_secret.0,
    ];
    let context = &[
        &[mode.mode_id()][..],
        &buf_len_u16(psk_id),
        psk_id,
        &buf_len_u16(info),
        info,
    ];

    // Make buffers for the values we need to derive
    let mut key = crate::aead::AeadKey::<A>::default();
    let key_len = key.0.len();
    let mut base_nonce = crate::aead::AeadNonce::<A>::default();
    let base_nonce_len = base_nonce.0.len();
    let mut exporter_secret = <ExporterSecret<Kdf> as Default>::default();
    let exporter_secret_len = exporter_secret.0.len();

    // We can't make an array with length Nk + Nn + Nh, so we make an array with the maximum
    // possible length, and slice it
    let mut digest_backing_arr = [0u8; 32 + 12 + 64];
    let digest = &mut digest_backing_arr[..key_len + base_nonce_len + exporter_secret_len];

    labeled_derive::<H>(&suite_id, secrets, b"secret", context, digest);

    // Copy the secret bytes into the appropriate places
    let mut cursor = 0;
    key.0.copy_from_slice(&digest[cursor..cursor + key_len]);
    cursor += key_len;

    base_nonce
        .0
        .copy_from_slice(&digest[cursor..cursor + base_nonce_len]);
    cursor += base_nonce_len;

    exporter_secret
        .0
        .copy_from_slice(&digest[cursor..cursor + exporter_secret_len]);

    AeadCtx::new(&key, base_nonce, exporter_secret)
}

// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-7.1.3-9
//
// def DeriveKeyPair_OneStage(ikm):
//   sk = LabeledDerive(ikm, "sk", "", Nsk)
//   return (sk, pk(sk))

/// Derive secret key bytes for x25519 using a one-stage KDF
pub(crate) fn derive_x25519_sk_eph_bytes<H>(suite_id: &KemSuiteId, ikm: &[u8]) -> [u8; 32]
where
    H: Default + ExtendableOutput,
{
    let mut sk_bytes = [0u8; 32];
    labeled_derive::<H>(suite_id, &[ikm], b"sk", &[b""], &mut sk_bytes);
    sk_bytes
}

// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-7.1.3-4
//
// def DeriveCandidate_OneStage(ikm, counter):
//   return LabeledDerive(ikm, "candidate", I2OSP(counter, 1), Nsk)

/// Derive candidate secret key bytes for p256/p384/p521 using a two-stage KDF
pub(crate) fn derive_nistp_sk_eph_bytes<H, PrivateKeySize>(
    suite_id: &KemSuiteId,
    ikm: &[u8],
    counter: u8,
) -> Array<u8, PrivateKeySize>
where
    H: Default + ExtendableOutput,
    PrivateKeySize: ArraySize,
{
    let mut sk_bytes = Array::default();
    labeled_derive::<H>(suite_id, &[ikm], b"candidate", &[&[counter]], &mut sk_bytes);
    sk_bytes
}

// §5.3 in https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02
//
// def Context.Export_OneStage(exporter_context, L):
//   return LabeledDerive(self.exporter_secret, "sec",
//                        exporter_context, L)

/// Derive an exporter secret using a one-stage KDF. Returns `Err(HpkeError::KdfOutputTooLong)` if
/// `out_buf.len()` ≥ 2¹⁶.
pub(crate) fn export<H>(
    exporter_secret: &[u8],
    suite_id: &[u8],
    exporter_ctx: &[u8],
    out_buf: &mut [u8],
) -> Result<(), HpkeError>
where
    H: ExtendableOutput + Default,
{
    if out_buf.len() >= 2usize.pow(16) {
        return Err(HpkeError::KdfOutputTooLong);
    }

    labeled_derive::<H>(
        suite_id,
        &[exporter_secret],
        b"sec",
        &[exporter_ctx],
        out_buf,
    );

    Ok(())
}

/// Returns I2OSP(buf, 2), i.e., the big-endian 2-byte representation of buf.len()
///
/// # Panics
/// Panics if `buf.len()` ≥ 2¹⁶
pub(crate) fn buf_len_u16(buf: &[u8]) -> [u8; 2] {
    let len = u16::try_from(buf.len()).expect("buf len was more than 2 bytes");
    let mut serialized_len = [0u8; 2];
    write_u16_be(&mut serialized_len, len);
    serialized_len
}
