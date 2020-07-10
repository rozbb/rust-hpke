use crate::{
    aead::{Aead, AeadCtx, AeadCtxR, AeadCtxS},
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
    kem::{self, EncappedKey, Kem as KemTrait, SharedSecret},
    kex::KeyExchange,
    op_mode::{OpMode, OpModeR, OpModeS},
    util::full_suite_id,
    HpkeError,
};

use digest::{generic_array::GenericArray, Digest};
use rand::{CryptoRng, RngCore};

/// Secret generated in `derive_enc_ctx` and stored in `AeadCtx`
pub(crate) type ExporterSecret<K> =
    GenericArray<u8, <<K as KdfTrait>::HashImpl as Digest>::OutputSize>;

// This is the KeySchedule function defined in draft02 §6.1. It runs a KDF over all the parameters,
// inputs, and secrets, and spits out a key-nonce pair to be used for symmetric encryption
fn derive_enc_ctx<A, Kdf, Kem, O>(
    mode: &O,
    shared_secret: SharedSecret<Kem>,
    info: &[u8],
) -> AeadCtx<A, Kdf, Kem>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
    O: OpMode<Kem::Kex>,
{
    // A helper function that writes to a buffer and returns a slice containing the unwritten
    // portion. If this crate were allowed to use std, we'd just use std::io::Write instead.
    fn write_to_buf<'a>(buf: &'a mut [u8], to_write: &[u8]) -> &'a mut [u8] {
        buf[..to_write.len()].copy_from_slice(to_write);
        &mut buf[to_write.len()..]
    }

    // Put together the binding context used for all KDF operations
    let suite_id = full_suite_id::<A, Kdf, Kem>();

    // In KeySchedule(),
    //     pskID_hash = LabeledExtract(zero(0), "pskID", pskID)
    //     info_hash = LabeledExtract(zero(0), "info_hash", info)
    //     key_schedule_context = concat(mode, pskID_hash, info_hash)

    // Pick a buffer to hold a u8 and 2 digests, as described above
    let mut buf = [0u8; 1 + 2 * 512];
    let buf_len = buf.len();

    let sched_context: &[u8] = {
        //  Define a cursor with which to write to the above buffer
        let mut cursor = &mut buf[..];

        // Use the helper function to write the mode identifier (1 byte, so endianness doesn't
        // matter)
        cursor = write_to_buf(cursor, &[mode.mode_id()]);

        let (psk_id_hash, _) =
            labeled_extract::<Kdf>(&[], &suite_id, b"pskID_hash", mode.get_psk_id());
        let (info_hash, _) = labeled_extract::<Kdf>(&[], &suite_id, b"info_hash", info);

        cursor = write_to_buf(cursor, psk_id_hash.as_slice());
        cursor = write_to_buf(cursor, info_hash.as_slice());

        let bytes_written = buf_len - cursor.len();
        &buf[..bytes_written]
    };

    // In KeySchedule(),
    //   psk_hash = LabeledExtract(zero(0), "psk_hash", psk)
    //   secret = LabeledExtract(psk_hash, "secret", zz)
    //   key = LabeledExpand(secret, "key", key_schedule_context, Nk)
    //   nonce = LabeledExpand(secret, "nonce", key_schedule_context, Nn)
    //   exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, Nh)
    let (extracted_psk, _) =
        labeled_extract::<Kdf>(&[], &suite_id, b"psk_hash", mode.get_psk_bytes());
    // Instead of `secret` we derive an HKDF context which we run .expand() on to derive the
    // key-nonce pair.
    let (_, secret_ctx) =
        labeled_extract::<Kdf>(&extracted_psk, &suite_id, b"secret", &shared_secret);

    // Empty fixed-size buffers
    let mut key = crate::aead::AeadKey::<A>::default();
    let mut nonce = crate::aead::AeadNonce::<A>::default();
    let mut exporter_secret = <ExporterSecret<Kdf> as Default>::default();

    // Fill the key, nonce, and exporter secret. This only errors if the output values are 255x the
    // digest size of the hash function. Since these values are fixed at compile time, we don't
    // worry about it.
    secret_ctx
        .labeled_expand(&suite_id, b"key", &sched_context, key.as_mut_slice())
        .expect("aead key len is way too big");
    secret_ctx
        .labeled_expand(&suite_id, b"nonce", &sched_context, nonce.as_mut_slice())
        .expect("nonce len is way too big");
    secret_ctx
        .labeled_expand(
            &suite_id,
            b"exp",
            &sched_context,
            exporter_secret.as_mut_slice(),
        )
        .expect("exporter secret len is way too big");

    AeadCtx::new(&key, nonce, exporter_secret)
}

// From draft02 §6.5:
//     def SetupAuthPSKI(pkR, info, psk, pskID, skI):
//       zz, enc = AuthEncap(pkR, skI)
//       pkIm = Marshal(pk(skI))
//       return enc, KeySchedule(mode_psk_auth, pkR, zz, enc, info,
//                               psk, pskID, pkIm)
/// Initiates an encryption context to the given recipient. Does an "authenticated" encapsulation
/// if `sk_sender_id` is set. This ties the sender identity to the shared secret.
///
/// Return Value
/// ============
/// On success, returns an encapsulated public key (intended to be sent to the recipient), and an
/// encryption context. If an error happened during key exchange, returns
/// `Err(HpkeError::InvalidKeyExchange)`. This is the only possible error.
pub fn setup_sender<A, Kdf, Kem, R>(
    mode: &OpModeS<Kem::Kex>,
    pk_recip: &<Kem::Kex as KeyExchange>::PublicKey,
    info: &[u8],
    csprng: &mut R,
) -> Result<(EncappedKey<Kem::Kex>, AeadCtxS<A, Kdf, Kem>), HpkeError>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
    R: CryptoRng + RngCore,
{
    // If the identity key is set, use it
    let sender_id_keypair = mode.get_sender_id_keypair();
    // Do the encapsulation
    let (shared_secret, encapped_key) = kem::encap::<Kem, _>(pk_recip, sender_id_keypair, csprng)?;
    // Use everything to derive an encryption context
    let enc_ctx = derive_enc_ctx::<_, _, Kem, _>(mode, shared_secret, info);

    Ok((encapped_key, enc_ctx.into()))
}

//  From draft02 §6.5:
//     def SetupAuthPSKR(enc, skR, info, psk, pskID, pkI):
//       zz = AuthDecap(enc, skR, pkI)
//       pkIm = Marshal(pkI)
//       return KeySchedule(mode_psk_auth, pk(skR), zz, enc, info,
//                          psk, pskID, pkIm)
/// Initiates an encryption context given a private key `sk` and an encapsulated key which was
/// encapsulated to `sk`'s corresponding public key
///
/// Return Value
/// ============
/// On success, returns an encryption context. If an error happened during key exchange, returns
/// `Err(HpkeError::InvalidKeyExchange)`. This is the only possible error.
pub fn setup_receiver<A, Kdf, Kem>(
    mode: &OpModeR<Kem::Kex>,
    sk_recip: &<Kem::Kex as KeyExchange>::PrivateKey,
    encapped_key: &EncappedKey<Kem::Kex>,
    info: &[u8],
) -> Result<AeadCtxR<A, Kdf, Kem>, HpkeError>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    // If the identity key is set, use it
    let pk_sender_id: Option<&<Kem::Kex as KeyExchange>::PublicKey> = mode.get_pk_sender_id();
    // Do the decapsulation
    let shared_secret = kem::decap::<Kem>(sk_recip, pk_sender_id, encapped_key)?;

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
                type Kex = <Kem as KemTrait>::Kex;

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
                        new_op_mode_pair::<Kex, Kdf>(*op_mode_kind, &psk, &psk_id);

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
                type Kex = <Kem as KemTrait>::Kex;

                let mut csprng = StdRng::from_entropy();

                let info = b"why would you think in a million years that that would actually work";

                // Generate the receiver's long-term keypair
                let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);

                // Generate a mutually agreeing op mode pair
                let (psk, psk_id) = (gen_rand_buf(), gen_rand_buf());
                let (sender_mode, receiver_mode) =
                    new_op_mode_pair::<Kex, Kdf>(OpModeKind::Base, &psk, &psk_id);

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

    #[cfg(feature = "x25519-dalek")]
    test_setup_correctness!(
        test_setup_correctness_x25519,
        ChaCha20Poly1305,
        HkdfSha256,
        crate::kem::X25519HkdfSha256
    );
    #[cfg(feature = "p256")]
    test_setup_correctness!(
        test_setup_correctness_p256,
        ChaCha20Poly1305,
        HkdfSha256,
        crate::kem::DhP256HkdfSha256
    );

    #[cfg(feature = "x25519-dalek")]
    test_setup_soundness!(
        test_setup_soundness_x25519,
        ChaCha20Poly1305,
        HkdfSha256,
        crate::kem::X25519HkdfSha256
    );
    #[cfg(feature = "p256")]
    test_setup_soundness!(
        test_setup_soundness_p256,
        ChaCha20Poly1305,
        HkdfSha256,
        crate::kem::DhP256HkdfSha256
    );
}
