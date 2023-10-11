use crate::{
    aead::{Aead, AeadTag},
    kdf::Kdf as KdfTrait,
    kem::Kem as KemTrait,
    op_mode::{OpModeR, OpModeS},
    setup::{setup_receiver, setup_sender},
    HpkeError,
};

use rand_core::{CryptoRng, RngCore};

// RFC 9180 §6.1
// def SealAuthPSK(pkR, info, aad, pt, psk, psk_id, skS):
//   enc, ctx = SetupAuthPSKS(pkR, info, psk, psk_id, skS)
//   ct = ctx.Seal(aad, pt)
//   return enc, ct

/// Does a `setup_sender` and `AeadCtxS::seal_in_place_detached` in one shot. That is, it does a
/// key encapsulation to the specified recipient and encrypts the provided plaintext in place. See
/// `setup::setup_sender` and `AeadCtxS::seal_in_place_detached` for more detail.
///
/// Return Value
/// ============
/// Returns `Ok((encapped_key, auth_tag))` on success. If an error happened during key
/// encapsulation, returns `Err(HpkeError::EncapError)`. If an error happened during encryption,
/// returns `Err(HpkeError::SealError)`. In this case, the contents of `plaintext` is undefined.
pub fn single_shot_seal_in_place_detached<A, Kdf, Kem, R>(
    mode: &OpModeS<Kem>,
    pk_recip: &Kem::PublicKey,
    info: &[u8],
    plaintext: &mut [u8],
    aad: &[u8],
    csprng: &mut R,
) -> Result<(Kem::EncappedKey, AeadTag<A>), HpkeError>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
    R: CryptoRng + RngCore,
{
    // Encap a key
    let (encapped_key, mut aead_ctx) =
        setup_sender::<A, Kdf, Kem, R>(mode, pk_recip, info, csprng)?;
    // Encrypt
    let tag = aead_ctx.seal_in_place_detached(plaintext, aad)?;

    Ok((encapped_key, tag))
}

/// Does a `setup_sender` and `AeadCtxS::seal` in one shot. That is, it does a key encapsulation to
/// the specified recipient and encrypts the provided plaintext. See `setup::setup_sender` and
/// `AeadCtxS::seal` for more detail.
///
/// Return Value
/// ============
/// Returns `Ok((encapped_key, ciphertext))` on success. If an error happened during key
/// encapsulation, returns `Err(HpkeError::EncapError)`. If an error happened during encryption,
/// returns `Err(HpkeError::SealError)`.
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn single_shot_seal<A, Kdf, Kem, R>(
    mode: &OpModeS<Kem>,
    pk_recip: &Kem::PublicKey,
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    csprng: &mut R,
) -> Result<(Kem::EncappedKey, crate::Vec<u8>), HpkeError>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
    R: CryptoRng + RngCore,
{
    // Encap a key
    let (encapped_key, mut aead_ctx) =
        setup_sender::<A, Kdf, Kem, R>(mode, pk_recip, info, csprng)?;
    // Encrypt
    let ciphertext = aead_ctx.seal(plaintext, aad)?;

    Ok((encapped_key, ciphertext))
}

// RFC 9180 §6.1
// def OpenAuthPSK(enc, skR, info, aad, ct, psk, psk_id, pkS):
//   ctx = SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS)
//   return ctx.Open(aad, ct)

/// Does a `setup_receiver` and `AeadCtxR::open_in_place_detached` in one shot. That is, it does a
/// key decapsulation for the specified recipient and decrypts the provided ciphertext in place.
/// See `setup::setup_reciever` and `AeadCtxR::open_in_place_detached` for more detail.
///
/// Return Value
/// ============
/// Returns `Ok()` on success. If an error happened during key decapsulation, returns
/// `Err(HpkeError::DecapError)`. If an error happened during decryption, returns
/// `Err(HpkeError::OpenError)`. In this case, the contents of `ciphertext` is undefined.
pub fn single_shot_open_in_place_detached<A, Kdf, Kem>(
    mode: &OpModeR<Kem>,
    sk_recip: &Kem::PrivateKey,
    encapped_key: &Kem::EncappedKey,
    info: &[u8],
    ciphertext: &mut [u8],
    aad: &[u8],
    tag: &AeadTag<A>,
) -> Result<(), HpkeError>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    // Decap the key
    let mut aead_ctx = setup_receiver::<A, Kdf, Kem>(mode, sk_recip, encapped_key, info)?;
    // Decrypt
    aead_ctx.open_in_place_detached(ciphertext, aad, tag)
}

/// Does a `setup_receiver` and `AeadCtxR::open` in one shot. That is, it does a key decapsulation
/// for the specified recipient and decrypts the provided ciphertext. See `setup::setup_reciever`
/// and `AeadCtxR::open` for more detail.
///
/// Return Value
/// ============
/// Returns `Ok(plaintext)` on success. If an error happened during key decapsulation, returns
/// `Err(HpkeError::DecapError)`. If an error happened during decryption, returns
/// `Err(HpkeError::OpenError)`.
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn single_shot_open<A, Kdf, Kem>(
    mode: &OpModeR<Kem>,
    sk_recip: &Kem::PrivateKey,
    encapped_key: &Kem::EncappedKey,
    info: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<crate::Vec<u8>, HpkeError>
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    // Decap the key
    let mut aead_ctx = setup_receiver::<A, Kdf, Kem>(mode, sk_recip, encapped_key, info)?;
    // Decrypt
    aead_ctx.open(ciphertext, aad)
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        aead::ChaCha20Poly1305,
        kem::Kem as KemTrait,
        op_mode::{OpModeR, OpModeS, PskBundle},
        test_util::gen_rand_buf,
    };

    use rand::{rngs::StdRng, SeedableRng};

    macro_rules! test_single_shot_correctness {
        ($test_name:ident, $aead:ty, $kdf:ty, $kem:ty) => {
            /// Tests that `single_shot_open` can open a `single_shot_seal` ciphertext. This
            /// doens't need to be tested for all ciphersuite combinations, since its correctness
            /// follows from the correctness of `seal/open` and `setup_sender/setup_receiver`.
            #[test]
            fn $test_name() {
                type A = $aead;
                type Kdf = $kdf;
                type Kem = $kem;

                let msg = b"Good night, a-ding ding ding ding ding";
                let aad = b"Five four three two one";

                let mut csprng = StdRng::from_entropy();

                // Set up an arbitrary info string, a random PSK, and an arbitrary PSK ID
                let info = b"why would you think in a million years that that would actually work";
                let (psk, psk_id) = (gen_rand_buf(), gen_rand_buf());
                let psk_bundle = PskBundle {
                    psk: &psk,
                    psk_id: &psk_id,
                };

                // Generate the sender's and receiver's long-term keypairs
                let (sk_sender_id, pk_sender_id) = Kem::gen_keypair(&mut csprng);
                let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);

                // Construct the sender's encryption context, and get an encapped key
                let sender_mode = OpModeS::<Kem>::AuthPsk(
                    (sk_sender_id, pk_sender_id.clone()),
                    psk_bundle.clone(),
                );

                // Use the encapped key to derive the reciever's encryption context
                let receiver_mode = OpModeR::<Kem>::AuthPsk(pk_sender_id, psk_bundle);

                // Encrypt with the first context
                let (encapped_key, ciphertext) = single_shot_seal::<A, Kdf, Kem, _>(
                    &sender_mode,
                    &pk_recip,
                    info,
                    msg,
                    aad,
                    &mut csprng,
                )
                .expect("single_shot_seal() failed");

                // Make sure seal() isn't a no-op
                assert!(&ciphertext[..] != &msg[..]);

                // Decrypt with the second context
                let decrypted = single_shot_open::<A, Kdf, Kem>(
                    &receiver_mode,
                    &sk_recip,
                    &encapped_key,
                    info,
                    &ciphertext,
                    aad,
                )
                .expect("single_shot_open() failed");
                assert_eq!(&decrypted, &msg);
            }
        };
    }

    #[cfg(feature = "x25519")]
    test_single_shot_correctness!(
        test_single_shot_correctness_x25519,
        ChaCha20Poly1305,
        crate::kdf::HkdfSha256,
        crate::kem::x25519_hkdfsha256::X25519HkdfSha256
    );

    #[cfg(feature = "p256")]
    test_single_shot_correctness!(
        test_single_shot_correctness_p256,
        ChaCha20Poly1305,
        crate::kdf::HkdfSha256,
        crate::kem::dhp256_hkdfsha256::DhP256HkdfSha256
    );

    #[cfg(feature = "p384")]
    test_single_shot_correctness!(
        test_single_shot_correctness_p384,
        ChaCha20Poly1305,
        crate::kdf::HkdfSha384,
        crate::kem::dhp384_hkdfsha384::DhP384HkdfSha384
    );
}
