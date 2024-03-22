use crate::{
    aead::{Aead, AeadCtx, AeadCtxR, AeadCtxS},
    kdf::{labeled_extract, DigestArray, Kdf as KdfTrait, LabeledExpand, MAX_DIGEST_SIZE},
    kem::{Kem as KemTrait, SharedSecret},
    op_mode::{OpMode, OpModeR, OpModeS},
    util::full_suite_id,
    HpkeError,
};

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Secret generated in `derive_enc_ctx` and stored in `AeadCtx`
pub(crate) struct ExporterSecret<K: KdfTrait>(pub(crate) DigestArray<K>);

// We use this to get an empty buffer we can read secret bytes into
impl<K: KdfTrait> Default for ExporterSecret<K> {
    fn default() -> ExporterSecret<K> {
        ExporterSecret(DigestArray::<K>::default())
    }
}

impl<K: KdfTrait> Clone for ExporterSecret<K> {
    fn clone(&self) -> ExporterSecret<K> {
        ExporterSecret(self.0.clone())
    }
}

// Zero exporter secrets on drop
impl<K: KdfTrait> Drop for ExporterSecret<K> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// RFC 9180 §5.1
// def KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id):
//   VerifyPSKInputs(mode, psk, psk_id)
//
//   psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
//   info_hash = LabeledExtract("", "info_hash", info)
//   key_schedule_context = concat(mode, psk_id_hash, info_hash)
//
//   secret = LabeledExtract(shared_secret, "secret", psk)
//
//   key = LabeledExpand(secret, "key", key_schedule_context, Nk)
//   base_nonce = LabeledExpand(secret, "base_nonce",
//                              key_schedule_context, Nn)
//   exporter_secret = LabeledExpand(secret, "exp",
//                                   key_schedule_context, Nh)
//
//   return Context<ROLE>(key, base_nonce, 0, exporter_secret)

// This is the KeySchedule function. It runs a KDF over all the parameters, inputs, and secrets,
// and spits out a key-nonce pair to be used for symmetric encryption.
fn derive_enc_ctx<A, Kdf, Kem, O>(
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

// RFC 9180 §5.1.4:
// def SetupAuthPSKS(pkR, info, psk, psk_id, skS):
//   shared_secret, enc = AuthEncap(pkR, skS)
//   return enc, KeyScheduleS(mode_auth_psk, shared_secret, info,
//                            psk, psk_id)

/// Initiates an encryption context to the given recipient public key
///
/// Return Value
/// ============
/// On success, returns an encapsulated public key (intended to be sent to the recipient), and an
/// encryption context. If an error happened during key encapsulation, returns
/// `Err(HpkeError::EncapError)`. This is the only possible error.
pub fn setup_sender<A, Kdf, Kem, R>(
    mode: &OpModeS<Kem>,
    pk_recip: &Kem::PublicKey,
    info: &[u8],
    csprng: &mut R,
) -> Result<(Kem::EncappedKey, AeadCtxS<A, Kdf, Kem>), HpkeError>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
    R: CryptoRng + RngCore,
{
    // If the identity key is set, use it
    let sender_id_keypair = mode.get_sender_id_keypair();
    // Do the encapsulation
    let (shared_secret, encapped_key) = Kem::encap(pk_recip, sender_id_keypair, csprng)?;
    // Use everything to derive an encryption context
    let enc_ctx = derive_enc_ctx::<_, _, Kem, _>(mode, shared_secret, info);

    Ok((encapped_key, enc_ctx.into()))
}

// RFC 9180 §5.1.4
// def SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS):
//   shared_secret = AuthDecap(enc, skR, pkS)
//   return KeyScheduleR(mode_auth_psk, shared_secret, info,
//                       psk, psk_id)

/// Initiates a decryption context given a private key `sk_recip` and an encapsulated key which
/// was encapsulated to `sk_recip`'s corresponding public key
///
/// Return Value
/// ============
/// On success, returns a decryption context. If an error happened during key decapsulation,
/// returns `Err(HpkeError::DecapError)`. This is the only possible error.
pub fn setup_receiver<A, Kdf, Kem>(
    mode: &OpModeR<Kem>,
    sk_recip: &Kem::PrivateKey,
    encapped_key: &Kem::EncappedKey,
    info: &[u8],
) -> Result<AeadCtxR<A, Kdf, Kem>, HpkeError>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    // If the identity key is set, use it
    let pk_sender_id: Option<&Kem::PublicKey> = mode.get_pk_sender_id();
    // Do the decapsulation
    let shared_secret = Kem::decap(sk_recip, pk_sender_id, encapped_key)?;

    // Use everything to derive an encryption context
    let enc_ctx = derive_enc_ctx::<_, _, Kem, _>(mode, shared_secret, info);
    Ok(enc_ctx.into())
}

#[cfg(test)]
mod test {
    use super::{setup_receiver, setup_sender};
    use crate::test_util::{aead_ctx_eq, gen_rand_buf, new_op_mode_pair, OpModeKind};
    use crate::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::Kem as KemTrait};

    use rand::{rngs::StdRng, SeedableRng};

    /// This tests that `setup_sender` and `setup_receiver` derive the same context. We do this by
    /// testing that `gen_ctx_kem_pair` returns identical encryption contexts
    macro_rules! test_setup_correctness {
        ($test_name:ident, $aead_ty:ty, $kdf_ty:ty, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type A = $aead_ty;
                type Kdf = $kdf_ty;
                type Kem = $kem_ty;

                let mut csprng = StdRng::from_entropy();

                let info = b"why would you think in a million years that that would actually work";

                // Generate the receiver's long-term keypair
                let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);

                // Try a full setup for all the op modes
                for op_mode_kind in &[
                    OpModeKind::Base,
                    OpModeKind::Auth,
                    OpModeKind::Psk,
                    OpModeKind::AuthPsk,
                ] {
                    // Generate a mutually agreeing op mode pair
                    let (psk, psk_id) = (gen_rand_buf(), gen_rand_buf());
                    let (sender_mode, receiver_mode) =
                        new_op_mode_pair::<Kdf, Kem>(*op_mode_kind, &psk, &psk_id);

                    // Construct the sender's encryption context, and get an encapped key
                    let (encapped_key, mut aead_ctx1) = setup_sender::<A, Kdf, Kem, _>(
                        &sender_mode,
                        &pk_recip,
                        &info[..],
                        &mut csprng,
                    )
                    .unwrap();

                    // Use the encapped key to derive the reciever's encryption context
                    let mut aead_ctx2 = setup_receiver::<A, Kdf, Kem>(
                        &receiver_mode,
                        &sk_recip,
                        &encapped_key,
                        &info[..],
                    )
                    .unwrap();

                    // Ensure that the two derived contexts are equivalent
                    assert!(aead_ctx_eq(&mut aead_ctx1, &mut aead_ctx2));
                }
            }
        };
    }

    /// Tests that using different input data gives you different encryption contexts
    macro_rules! test_setup_soundness {
        ($test_name:ident, $aead:ty, $kdf:ty, $kem:ty) => {
            #[test]
            fn $test_name() {
                type A = $aead;
                type Kdf = $kdf;
                type Kem = $kem;

                let mut csprng = StdRng::from_entropy();

                let info = b"why would you think in a million years that that would actually work";

                // Generate the receiver's long-term keypair
                let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);

                // Generate a mutually agreeing op mode pair
                let (psk, psk_id) = (gen_rand_buf(), gen_rand_buf());
                let (sender_mode, receiver_mode) =
                    new_op_mode_pair::<Kdf, Kem>(OpModeKind::Base, &psk, &psk_id);

                // Construct the sender's encryption context normally
                let (encapped_key, sender_ctx) =
                    setup_sender::<A, Kdf, Kem, _>(&sender_mode, &pk_recip, &info[..], &mut csprng)
                        .unwrap();

                // Now make a receiver with the wrong info string and ensure it doesn't match the
                // sender
                let bad_info = b"something else";
                let mut receiver_ctx = setup_receiver::<_, _, Kem>(
                    &receiver_mode,
                    &sk_recip,
                    &encapped_key,
                    &bad_info[..],
                )
                .unwrap();
                assert!(!aead_ctx_eq(&mut sender_ctx.clone(), &mut receiver_ctx));

                // Now make a receiver with the wrong secret key and ensure it doesn't match the
                // sender
                let (bad_sk, _) = Kem::gen_keypair(&mut csprng);
                let mut aead_ctx2 =
                    setup_receiver::<_, _, Kem>(&receiver_mode, &bad_sk, &encapped_key, &info[..])
                        .unwrap();
                assert!(!aead_ctx_eq(&mut sender_ctx.clone(), &mut aead_ctx2));

                // Now make a receiver with the wrong encapped key and ensure it doesn't match the
                // sender. The reason `bad_encapped_key` is bad is because its underlying key is
                // uniformly random, and therefore different from the key that the sender sent.
                let (bad_encapped_key, _) =
                    setup_sender::<A, Kdf, Kem, _>(&sender_mode, &pk_recip, &info[..], &mut csprng)
                        .unwrap();
                let mut aead_ctx2 = setup_receiver::<_, _, Kem>(
                    &receiver_mode,
                    &sk_recip,
                    &bad_encapped_key,
                    &info[..],
                )
                .unwrap();
                assert!(!aead_ctx_eq(&mut sender_ctx.clone(), &mut aead_ctx2));

                // Now make sure that this test was a valid test by ensuring that doing everything
                // the right way makes it pass
                let mut aead_ctx2 = setup_receiver::<_, _, Kem>(
                    &receiver_mode,
                    &sk_recip,
                    &encapped_key,
                    &info[..],
                )
                .unwrap();
                assert!(aead_ctx_eq(&mut sender_ctx.clone(), &mut aead_ctx2));
            }
        };
    }

    #[cfg(feature = "x25519")]
    mod x25519_tests {
        use super::*;

        test_setup_correctness!(
            test_setup_correctness_x25519,
            ChaCha20Poly1305,
            HkdfSha256,
            crate::kem::x25519_hkdfsha256::X25519HkdfSha256
        );
        test_setup_soundness!(
            test_setup_soundness_x25519,
            ChaCha20Poly1305,
            HkdfSha256,
            crate::kem::x25519_hkdfsha256::X25519HkdfSha256
        );
    }

    #[cfg(feature = "p256")]
    mod p256_tests {
        use super::*;

        test_setup_correctness!(
            test_setup_correctness_p256,
            ChaCha20Poly1305,
            HkdfSha256,
            crate::kem::dhp256_hkdfsha256::DhP256HkdfSha256
        );
        test_setup_soundness!(
            test_setup_soundness_p256,
            ChaCha20Poly1305,
            HkdfSha256,
            crate::kem::dhp256_hkdfsha256::DhP256HkdfSha256
        );
    }

    #[cfg(feature = "p384")]
    mod p384_tests {
        use super::*;
        use crate::kdf::HkdfSha384;

        test_setup_correctness!(
            test_setup_correctness_p384,
            ChaCha20Poly1305,
            HkdfSha384,
            crate::kem::dhp384_hkdfsha384::DhP384HkdfSha384
        );
        test_setup_soundness!(
            test_setup_soundness_p384,
            ChaCha20Poly1305,
            HkdfSha384,
            crate::kem::dhp384_hkdfsha384::DhP384HkdfSha384
        );
    }

    #[cfg(feature = "p521")]
    mod p521_tests {
        use super::*;
        use crate::kdf::HkdfSha512;

        test_setup_correctness!(
            test_setup_correctness_p521,
            ChaCha20Poly1305,
            HkdfSha512,
            crate::kem::dhp521_hkdfsha512::DhP521HkdfSha512
        );
        test_setup_soundness!(
            test_setup_soundness_p521,
            ChaCha20Poly1305,
            HkdfSha512,
            crate::kem::dhp521_hkdfsha512::DhP521HkdfSha512
        );
    }

    #[cfg(feature = "k256")]
    mod k256_tests {
        use super::*;

        test_setup_correctness!(
            test_setup_correctness_k256,
            ChaCha20Poly1305,
            HkdfSha256,
            crate::kem::dhk256_hkdfsha256::DhK256HkdfSha256
        );
        test_setup_soundness!(
            test_setup_soundness_k256,
            ChaCha20Poly1305,
            HkdfSha256,
            crate::kem::dhk256_hkdfsha256::DhK256HkdfSha256
        );
    }
}
