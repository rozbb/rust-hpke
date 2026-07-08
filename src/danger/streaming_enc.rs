//! The underlying streaming/online encryption primitive defined in the HPKE spec.
//!
//! DO NOT use the same key for two sender contexts or two receiver contexts. Doing this
//! can lead to reflection attacks, i.e., replaying Alice's message to Alice herself,
//! pretending it came from Bob.
//!
//! Example use:
//! ```rust
//! # #[cfg(all(feature = "alloc", feature = "x25519", feature = "mlkem"))] {
//! # use hpke::{
//! #     aead::ChaCha20Poly1305,
//! #     kdf::KdfTurboShake128,
//! #     kem::XWing,
//! #     danger::streaming_enc::{
//! #         create_receiver_context, create_sender_context, ExporterSecret, AeadKey,
//! #         AeadNonce
//! #     },
//! #     Kem as KemTrait, OpModeR, OpModeS, setup_receiver, setup_sender,
//! # };
//! # use rand_core::Rng;
//! // These types define the ciphersuite Alice and Bob will be using
//! type Kem = XWing;
//! type Aead = ChaCha20Poly1305;
//! type Kdf = KdfTurboShake128;
//!
//! let mut csprng = rand::rng();
//!
//! // This is a description string for the session. Both Alice and Bob need to know this value.
//! // It's not secret.
//! let info_str = b"Alice and Bob's weekly chat";
//!
//! // Pick a random key, base nonce, and exporter secret for the streaming encryption context
//! let mut key = AeadKey::<Aead>::default();
//! let mut base_nonce = AeadNonce::default();
//! let mut exporter_secret = ExporterSecret::<Kdf>::default();
//! csprng.fill_bytes(key.0.as_mut_slice());
//! csprng.fill_bytes(base_nonce.0.as_mut_slice());
//! csprng.fill_bytes(exporter_secret.0.as_mut_slice());
//!
//! // Set up the sender and receiver contexts
//! let base_nonce_copy = AeadNonce::<Aead>(base_nonce.0);
//! let exporter_secret_copy = ExporterSecret::<Kdf>(exporter_secret.0);
//! let mut sender_ctx = create_sender_context::<_, _, Kem>(
//!     &key,
//!     base_nonce_copy,
//!     exporter_secret_copy,
//! );
//! let mut receiver_ctx = create_receiver_context::<_, _, Kem>(
//!     &key,
//!     base_nonce,
//!     exporter_secret,
//! );
//!
//! let msg = b"fronthand or backhand?";
//! let aad = b"a gentleman's game";
//!
//! // Encrypt in place with the sender context
//! let ciphertext = sender_ctx.seal(msg, aad).expect("seal() failed");
//! // Decrypt with the receiver context
//! let decrypted = receiver_ctx.open(&ciphertext, aad).expect("open() failed");
//!
//! // Check the decrypted message was what was sent
//! assert_eq!(&decrypted, msg);
//! # }
//! ```

use crate::{
    Kem as KemTrait,
    aead::{Aead, AeadCtx, AeadCtxR, AeadCtxS},
    kdf::Kdf as KdfTrait,
};

#[doc(inline)]
pub use crate::aead::{AeadKey, AeadNonce};

#[doc(inline)]
pub use crate::setup::ExporterSecret;

/// Creates a streaming encryption sender context from a key, nonce, and exporter secret.
///
/// ⚠️ DANGER
///
/// This is a low-level API. Only use this if you know what you are doing.
///
/// Use this method to set up an online/streaming encryption channel with shared secrets derived via
/// some key exchange. This is what the HPKE spec does when it instantiates a `ContextS` using (a
/// hash of) the KEM shared secret.
///
/// This method can also be used to create a response context like described in [section
/// 9.8](https://www.rfc-editor.org/rfc/rfc9180#name-bidirectional-encryption) of the HPKE spec.
pub fn create_sender_context<A: Aead, Kdf: KdfTrait, Kem: KemTrait>(
    key: &AeadKey<A>,
    base_nonce: AeadNonce<A>,
    exporter_secret: ExporterSecret<Kdf>,
) -> AeadCtxS<A, Kdf, Kem> {
    AeadCtx::new(key, base_nonce, exporter_secret).into()
}

/// Creates a streaming encryption receiver context from a key, nonce, and exporter secret.
///
/// ⚠️ DANGER
///
/// This is a low-level API. Only use this if you know what you are doing.
///
/// See the documentation for [`create_sender_context`] for more info.
pub fn create_receiver_context<A: Aead, Kdf: KdfTrait, Kem: KemTrait>(
    key: &AeadKey<A>,
    base_nonce: AeadNonce<A>,
    exporter_secret: ExporterSecret<Kdf>,
) -> AeadCtxR<A, Kdf, Kem> {
    AeadCtx::new(key, base_nonce, exporter_secret).into()
}

#[cfg(all(test, feature = "alloc"))]
mod test {
    use super::{
        AeadKey, AeadNonce, ExporterSecret, create_receiver_context, create_sender_context,
    };
    use rand_core::Rng;

    /// Tests that `open()` can decrypt things properly encrypted with `seal()`
    macro_rules! test_create_ctx_correctness {
        ($test_name:ident, $aead_ty:ty, $kdf_ty:ty, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type A = $aead_ty;
                type Kdf = $kdf_ty;
                type Kem = $kem_ty;

                let mut rng = rand::rng();

                let mut key = AeadKey::<A>::default();
                let mut base_nonce = AeadNonce::default();
                let mut exporter_secret = ExporterSecret::<Kdf>::default();

                rng.fill_bytes(key.0.as_mut_slice());
                rng.fill_bytes(base_nonce.0.as_mut_slice());
                rng.fill_bytes(exporter_secret.0.as_mut_slice());

                let base_nonce_copy = AeadNonce::<A>(base_nonce.0);
                let exporter_secret_copy = ExporterSecret::<Kdf>(exporter_secret.0);

                let mut sender_ctx =
                    create_sender_context::<_, _, Kem>(&key, base_nonce_copy, exporter_secret_copy);
                let mut receiver_ctx =
                    create_receiver_context::<_, _, Kem>(&key, base_nonce, exporter_secret);

                let msg = b"Love it or leave it, you better gain way";
                let aad = b"You better hit bull's eye, the kid don't play";

                // Encrypt with the sender context
                let ciphertext = sender_ctx.seal(msg, aad).expect("seal() failed");

                // Make sure seal() isn't a no-op
                assert_ne!(&ciphertext, msg);

                // Decrypt with the receiver context
                let decrypted = receiver_ctx.open(&ciphertext, aad).expect("open() failed");
                assert_eq!(&decrypted, msg);

                // Now try sending an invalid message followed by a valid message. The valid
                // message should decrypt correctly
                let invalid_ciphertext = [0x00; 32];
                assert!(receiver_ctx.open(&invalid_ciphertext, aad).is_err());

                // Now make sure a round trip succeeds
                let ciphertext = sender_ctx.seal(msg, aad).expect("second seal() failed");

                // Decrypt with the receiver context
                let decrypted = receiver_ctx
                    .open(&ciphertext, aad)
                    .expect("second open() failed");
                assert_eq!(&decrypted, msg);

                let mut shared_sender = [0u8; 32];
                let mut shared_receiver = [0u8; 32];

                sender_ctx.export(b"test", &mut shared_sender).unwrap();
                receiver_ctx.export(b"test", &mut shared_receiver).unwrap();

                assert_eq!(
                    shared_sender, shared_receiver,
                    "Sender and receiver don't have the same exported secret"
                );
                assert_ne!(shared_sender, [0u8; 32]);
            }
        };
    }

    #[cfg(all(feature = "x25519", feature = "alloc", feature = "aes"))]
    mod x25519_aes_tests {
        use super::*;
        use crate::aead::{AesGcm128, AesGcm256};
        use crate::kdf::HkdfSha256;

        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes128_x25519,
            AesGcm128,
            HkdfSha256,
            crate::kem::X25519HkdfSha256
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes256_x25519,
            AesGcm256,
            HkdfSha256,
            crate::kem::X25519HkdfSha256
        );
    }

    #[cfg(all(feature = "x25519", feature = "alloc", feature = "chacha"))]
    mod x25519_chacha_tests {
        use super::*;
        use crate::aead::ChaCha20Poly1305;
        use crate::kdf::HkdfSha256;

        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_x25519,
            ChaCha20Poly1305,
            HkdfSha256,
            crate::kem::X25519HkdfSha256
        );
    }

    #[cfg(all(feature = "nistp", feature = "alloc", feature = "aes"))]
    mod nistp_aes_tests {
        use super::*;
        use crate::aead::{AesGcm128, AesGcm256};
        use crate::kdf::HkdfSha256;

        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes128_p256,
            AesGcm128,
            HkdfSha256,
            crate::kem::DhP256HkdfSha256
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes256_p256,
            AesGcm256,
            HkdfSha256,
            crate::kem::DhP256HkdfSha256
        );

        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes128_p384,
            AesGcm128,
            HkdfSha256,
            crate::kem::DhP384HkdfSha384
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes256_p384,
            AesGcm256,
            HkdfSha256,
            crate::kem::DhP384HkdfSha384
        );

        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes128_p521,
            AesGcm128,
            HkdfSha256,
            crate::kem::DhP521HkdfSha512
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes256_p521,
            AesGcm256,
            HkdfSha256,
            crate::kem::DhP521HkdfSha512
        );
    }

    #[cfg(all(feature = "nistp", feature = "alloc", feature = "chacha"))]
    mod nistp_chacha_tests {
        use super::*;
        use crate::aead::ChaCha20Poly1305;
        use crate::kdf::{HkdfSha256, HkdfSha384, HkdfSha512};

        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_p256,
            ChaCha20Poly1305,
            HkdfSha256,
            crate::kem::DhP256HkdfSha256
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_p384,
            ChaCha20Poly1305,
            HkdfSha384,
            crate::kem::DhP384HkdfSha384
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_p521,
            ChaCha20Poly1305,
            HkdfSha512,
            crate::kem::DhP521HkdfSha512
        );
    }

    #[cfg(all(feature = "mlkem", feature = "chacha"))]
    mod mlkem_tests {
        use super::*;
        use crate::aead::ChaCha20Poly1305;
        use crate::kdf::{KdfShake128, KdfShake256};

        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_mlkem768,
            ChaCha20Poly1305,
            KdfShake128,
            crate::kem::MlKem768
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_mlkem1024,
            ChaCha20Poly1305,
            KdfShake256,
            crate::kem::MlKem1024
        );
    }

    #[cfg(all(
        feature = "mlkem",
        feature = "nistp",
        feature = "alloc",
        feature = "chacha"
    ))]
    mod mlkem_nistp_tests {
        use super::*;
        use crate::aead::ChaCha20Poly1305;
        use crate::kdf::{KdfShake128, KdfShake256};

        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_mlkem768p256,
            ChaCha20Poly1305,
            KdfShake128,
            crate::kem::MlKem768P256
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_mlkem1024p384,
            ChaCha20Poly1305,
            KdfShake256,
            crate::kem::MlKem1024P384
        );
    }

    #[cfg(all(feature = "mlkem", feature = "x25519", feature = "chacha"))]
    mod xwing_tests {
        use super::*;
        use crate::aead::ChaCha20Poly1305;
        use crate::kdf::KdfTurboShake128;

        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_xwing,
            ChaCha20Poly1305,
            KdfTurboShake128,
            crate::kem::XWing
        );
    }
}
