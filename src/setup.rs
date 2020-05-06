use crate::prelude::*;
use crate::{
    aead::{Aead, AeadCtx},
    dh::DiffieHellman,
    kdf::{labeled_extract, Kdf, LabeledExpand},
    kem::{self, EncappedKey, SharedSecret},
    op_mode::{OpMode, OpModeR, OpModeS},
    util::static_zeros,
};

use byteorder::{BigEndian, WriteBytesExt};
use digest::{generic_array::GenericArray, Digest};
use rand::{CryptoRng, RngCore};

/* struct {
        // Mode and algorithms
        uint8 mode;
        uint16 kem_id;
        uint16 kdf_id;
        uint16 aead_id;

        // Cryptographic hash of application-supplied pskID
        opaque pskID_hash[Nh];

        // Cryptographic hash of application-supplied info
        opaque info_hash[Nh];
    } HPKEContext;
*/

/// Secret generated in `derive_enc_ctx` and stored in `AeadCtx`
pub(crate) type ExporterSecret<K> = GenericArray<u8, <<K as Kdf>::HashImpl as Digest>::OutputSize>;

// This is the KeySchedule function defined in draft02 §6.1. It runs a KDF over all the parameters,
// inputs, and secrets, and spits out a key-nonce pair to be used for symmetric encryption
fn derive_enc_ctx<A: Aead, Dh: DiffieHellman, K: Kdf, O: OpMode<Dh, K>>(
    mode: &O,
    shared_secret: SharedSecret<Dh>,
    info: &[u8],
) -> AeadCtx<A, K> {
    // In KeySchedule(),
    //     ciphersuite = concat(encode_big_endian(kem_id, 2),
    //                          encode_big_endian(kdf_id, 2),
    //                          encode_big_endian(aead_id, 2))
    //     pskID_hash = LabeledExtract(zero(Nh), "pskID", pskID)
    //     info_hash = LabeledExtract(zero(Nh), "info", info)
    //     context = concat(ciphersuite, mode, pskID_hash, info_hash)
    let context_bytes: Vec<u8> = {
        let mut buf = Vec::new();

        // This relies on <Vec<u8> as Write>, which never errors, so unwrap() is justified
        buf.write_u16::<BigEndian>(Dh::KEM_ID).unwrap();
        buf.write_u16::<BigEndian>(K::KDF_ID).unwrap();
        buf.write_u16::<BigEndian>(A::AEAD_ID).unwrap();

        buf.write_u8(mode.mode_id()).unwrap();

        let zeros = static_zeros::<K>();
        let (psk_id_hash, _) = labeled_extract::<K>(zeros, b"pskID", mode.get_psk_id());
        let (info_hash, _) = labeled_extract::<K>(zeros, b"info", info);

        buf.extend(psk_id_hash.as_slice());
        buf.extend(info_hash.as_slice());

        buf
    };

    // In KeySchedule(),
    //   extracted_psk = LabeledExtract(zero(Nh), "psk", psk)
    //   secret = LabeledExtract(extracted_psk, "zz", zz)
    //   key = LabeledExpand(secret, "key", context, Nk)
    //   nonce = LabeledExpand(secret, "nonce", context, Nn)
    //   exporter_secret = LabeledExpand(secret, "exp", context, Nh)
    //   return Context(key, nonce, exporter_secret)
    //
    // Instead of `secret` we derive an HKDF context which we run .expand() on to derive the
    // key-nonce pair.
    let (extracted_psk, _) =
        labeled_extract::<K>(static_zeros::<K>(), b"psk", mode.get_psk_bytes());
    let (_, secret_ctx) = labeled_extract::<K>(&extracted_psk, b"zz", &shared_secret);

    // Empty fixed-size buffers
    let mut key = crate::aead::AeadKey::<A>::default();
    let mut nonce = crate::aead::AeadNonce::<A>::default();
    let mut exporter_secret = <ExporterSecret<K> as Default>::default();

    // Fill the key, nonce, and exporter secret. This only errors if the output values are 255x the
    // digest size of the hash function. Since these values are fixed at compile time, we don't
    // worry about it.
    secret_ctx
        .labeled_expand(b"key", &context_bytes, key.as_mut_slice())
        .expect("aead key len is way too big");
    secret_ctx
        .labeled_expand(b"nonce", &context_bytes, nonce.as_mut_slice())
        .expect("nonce len is way too big");
    secret_ctx
        .labeled_expand(b"exp", &context_bytes, exporter_secret.as_mut_slice())
        .expect("exporter secret len is way too big");

    AeadCtx::new(key, nonce, exporter_secret)
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
/// Returns an encapsulated public key (intended to be sent to the recipient), and an encryption
/// context.
pub fn setup_sender<A, Dh, K, R>(
    mode: &OpModeS<Dh, K>,
    pk_recip: &Dh::PublicKey,
    info: &[u8],
    csprng: &mut R,
) -> (EncappedKey<Dh>, AeadCtx<A, K>)
where
    A: Aead,
    Dh: DiffieHellman,
    K: Kdf,
    R: CryptoRng + RngCore,
{
    // If the identity key is set, use it
    let sender_id_keypair = mode.get_sender_id_keypair();
    // Do the encapsulation
    let (shared_secret, encapped_key) = kem::encap::<_, K, _>(pk_recip, sender_id_keypair, csprng);
    // Use everything to derive an encryption context
    let enc_ctx = derive_enc_ctx(mode, shared_secret, info);

    (encapped_key, enc_ctx)
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
/// Returns an encryption context
pub fn setup_receiver<A, Dh, K>(
    mode: &OpModeR<Dh, K>,
    sk_recip: &Dh::PrivateKey,
    pk_recip: &Dh::PublicKey,
    encapped_key: &EncappedKey<Dh>,
    info: &[u8],
) -> AeadCtx<A, K>
where
    A: Aead,
    Dh: DiffieHellman,
    K: Kdf,
{
    // If the identity key is set, use it
    let pk_sender_id: Option<&Dh::PublicKey> = mode.get_pk_sender_id();
    // Do the decapsulation
    let shared_secret = kem::decap::<_, K>(sk_recip, pk_recip, pk_sender_id, encapped_key);

    // Use everything to derive an encryption context
    derive_enc_ctx(mode, shared_secret, info)
}

#[cfg(test)]
mod test {
    use super::{setup_receiver, setup_sender};
    use crate::test_util::{aead_ctx_eq, gen_op_mode_pair, OpModeKind};
    use crate::{
        aead::{AesGcm128, AesGcm256, ChaCha20Poly1305},
        dh::{x25519::X25519, DiffieHellman},
        kdf::{HkdfSha256, HkdfSha384, HkdfSha512},
    };

    /// This tests that `setup_sender` and `setup_receiver` derive the same context. We do this by
    /// testing that `gen_ctx_kem_pair` returns identical encryption contexts
    macro_rules! test_setup_correctness {
        ($test_name:ident, $aead_ty:ty, $dh_ty:ty, $kdf_ty:ty) => {
            #[test]
            fn $test_name() {
                type A = $aead_ty;
                type Dh = $dh_ty;
                type K = $kdf_ty;

                let mut csprng = rand::thread_rng();

                let info = b"why would you think in a million years that that would actually work";

                // Generate the receiver's long-term keypair
                let (sk_recip, pk_recip) = <Dh as DiffieHellman>::gen_keypair(&mut csprng);

                // Try a full setup for all the op modes
                for op_mode_kind in &[
                    OpModeKind::Base,
                    OpModeKind::Auth,
                    OpModeKind::Psk,
                    OpModeKind::AuthPsk,
                ] {
                    // Generate a mutually agreeing op mode pair
                    let (sender_mode, receiver_mode) = gen_op_mode_pair::<Dh, K>(*op_mode_kind);

                    // Construct the sender's encryption context, and get an encapped key
                    let (encapped_key, mut aead_ctx1) = setup_sender::<A, Dh, _, _>(
                        &sender_mode,
                        &pk_recip,
                        &info[..],
                        &mut csprng,
                    );

                    // Use the encapped key to derive the reciever's encryption context
                    let mut aead_ctx2 = setup_receiver(
                        &receiver_mode,
                        &sk_recip,
                        &pk_recip,
                        &encapped_key,
                        &info[..],
                    );

                    // Ensure that the two derived contexts are equivalent
                    assert!(aead_ctx_eq(&mut aead_ctx1, &mut aead_ctx2));
                }
            }
        };
    }

    test_setup_correctness!(
        test_setup_correctness_chacha_sha256,
        ChaCha20Poly1305,
        X25519,
        HkdfSha256
    );
    test_setup_correctness!(
        test_setup_correctness_aes128_sha256,
        AesGcm128,
        X25519,
        HkdfSha256
    );
    test_setup_correctness!(
        test_setup_correctness_aes256_sha256,
        AesGcm256,
        X25519,
        HkdfSha256
    );
    test_setup_correctness!(
        test_setup_correctness_chacha_sha384,
        ChaCha20Poly1305,
        X25519,
        HkdfSha384
    );
    test_setup_correctness!(
        test_setup_correctness_aes128_sha384,
        AesGcm128,
        X25519,
        HkdfSha384
    );
    test_setup_correctness!(
        test_setup_correctness_aes256_sha384,
        AesGcm256,
        X25519,
        HkdfSha384
    );
    test_setup_correctness!(
        test_setup_correctness_chacha_sha512,
        ChaCha20Poly1305,
        X25519,
        HkdfSha512
    );
    test_setup_correctness!(
        test_setup_correctness_aes128_sha512,
        AesGcm128,
        X25519,
        HkdfSha512
    );
    test_setup_correctness!(
        test_setup_correctness_aes256_sha512,
        AesGcm256,
        X25519,
        HkdfSha512
    );

    /// Tests that using different input data gives you different encryption contexts
    #[test]
    fn test_setup_soundness() {
        type A = ChaCha20Poly1305;
        type Dh = X25519;
        type K = HkdfSha256;

        let mut csprng = rand::thread_rng();

        let info = b"why would you think in a million years that that would actually work";

        // Generate the receiver's long-term keypair
        let (sk_recip, pk_recip) = <Dh as DiffieHellman>::gen_keypair(&mut csprng);

        // Generate a mutually agreeing op mode pair
        let (sender_mode, receiver_mode) = gen_op_mode_pair::<Dh, K>(OpModeKind::Base);

        // Construct the sender's encryption context normally
        let (encapped_key, aead_ctx1) =
            setup_sender::<A, Dh, _, _>(&sender_mode, &pk_recip, &info[..], &mut csprng);

        // Now make a receiver with the wrong info string and ensure it doesn't match the sender
        let bad_info = b"something else";
        let mut aead_ctx2 = setup_receiver(
            &receiver_mode,
            &sk_recip,
            &pk_recip,
            &encapped_key,
            &bad_info[..],
        );
        assert!(!aead_ctx_eq(&mut aead_ctx1.clone(), &mut aead_ctx2));

        // Now make a receiver with the wrong secret key and ensure it doesn't match the sender
        let (bad_sk, _) = <Dh as DiffieHellman>::gen_keypair(&mut csprng);
        let mut aead_ctx2 =
            setup_receiver(&receiver_mode, &bad_sk, &pk_recip, &encapped_key, &info[..]);
        assert!(!aead_ctx_eq(&mut aead_ctx1.clone(), &mut aead_ctx2));

        // Now make a receiver with the wrong public key and ensure it doesn't match the sender
        let (_, bad_pk) = <Dh as DiffieHellman>::gen_keypair(&mut csprng);
        let mut aead_ctx2 =
            setup_receiver(&receiver_mode, &sk_recip, &bad_pk, &encapped_key, &info[..]);
        assert!(!aead_ctx_eq(&mut aead_ctx1.clone(), &mut aead_ctx2));

        // Now make a receiver with the wrong encapped key and ensure it doesn't match the sender.
        // The reason `bad_encapped_key` is bad is because its underlying key is uniformly random,
        // and therefore different from the key that the sender sent.
        let (bad_encapped_key, _) =
            setup_sender::<A, Dh, _, _>(&sender_mode, &pk_recip, &info[..], &mut csprng);
        let mut aead_ctx2 = setup_receiver(
            &receiver_mode,
            &sk_recip,
            &pk_recip,
            &bad_encapped_key,
            &info[..],
        );
        assert!(!aead_ctx_eq(&mut aead_ctx1.clone(), &mut aead_ctx2));

        // Now make sure that this test was a valid test by ensuring that doing everything the
        // right way makes it pass
        let mut aead_ctx2 = setup_receiver(
            &receiver_mode,
            &sk_recip,
            &pk_recip,
            &encapped_key,
            &info[..],
        );
        assert!(aead_ctx_eq(&mut aead_ctx1.clone(), &mut aead_ctx2));
    }
}
