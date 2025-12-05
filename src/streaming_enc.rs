//! ⚠️ Hazmat:
//! This file exposes the underlying streaming/online encryption primitive defined in the HPKE spec.
//! Do NOT use this unless you really know what you're doing.
//!
//! Example use:
//! ```rust
//! # #[cfg(feature = "alloc")] {
//! # #[cfg(feature = "x25519")] {
//! # use hpke::{
//! #     aead::ChaCha20Poly1305,
//! #     kdf::HkdfSha384,
//! #     kem::X25519HkdfSha256,
//! #     streaming_enc::{
//! #         create_receiver_context, create_sender_context, ExporterSecret, AeadKey,
//! #         AeadNonce
//! #     },
//! #     Kem as KemTrait, OpModeR, OpModeS, setup_receiver, setup_sender,
//! # };
//! # use rand::RngCore;
//! // These types define the ciphersuite Alice and Bob will be using
//! type Kem = X25519HkdfSha256;
//! type Aead = ChaCha20Poly1305;
//! type Kdf = HkdfSha384;
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
//! # }}
//! ```

use crate::{
    aead::{Aead, AeadCtx, AeadCtxR, AeadCtxS},
    kdf::Kdf as KdfTrait,
    Kem as KemTrait,
};

#[doc(inline)]
pub use crate::aead::{AeadKey, AeadNonce};

#[doc(inline)]
pub use crate::setup::ExporterSecret;

/// Creates a streaming encryption sender context from a key, nonce, and exporter secret.
///
/// ⚠️ Warning: Hazmat!
///
/// This is a low-level API. Only use this if you know what you are doing.
///
/// Use this method to set up an online/streaming encryption channel with shared secrets derived via
/// some key exchange. This is what's done in the HPKE spec, using (hashes of) the KEM shared
/// secret.
///
/// In particular, this method can also be used to create a response context like described in
/// [section 9.8](https://www.rfc-editor.org/rfc/rfc9180#name-bidirectional-encryption) of the HPKE
/// spec.
pub fn create_sender_context<A: Aead, Kdf: KdfTrait, Kem: KemTrait>(
    key: &AeadKey<A>,
    base_nonce: AeadNonce<A>,
    exporter_secret: ExporterSecret<Kdf>,
) -> AeadCtxS<A, Kdf, Kem> {
    AeadCtx::new(key, base_nonce, exporter_secret).into()
}

/// Creates a streaming encryption receiver context from a key, nonce, and exporter secret.
///
/// ⚠️ Warning: Hazmat!
///
/// This is a low level API. Only use this if you know what you are doing.
///
/// See the documentation for [`create_sender_context`] for more info.
pub fn create_receiver_context<A: Aead, Kdf: KdfTrait, Kem: KemTrait>(
    key: &AeadKey<A>,
    base_nonce: AeadNonce<A>,
    exporter_secret: ExporterSecret<Kdf>,
) -> AeadCtxR<A, Kdf, Kem> {
    AeadCtx::new(key, base_nonce, exporter_secret).into()
}

#[cfg(test)]
mod test {
    use super::{
        create_receiver_context, create_sender_context, AeadKey, AeadNonce, ExporterSecret,
    };
    use crate::{
        aead::{AesGcm128, AesGcm256, ChaCha20Poly1305},
        kdf::HkdfSha256,
    };
    use rand_core::RngCore;

    /// Tests that `open()` can decrypt things properly encrypted with `seal()`
    macro_rules! test_create_ctx_correctness {
        ($test_name:ident, $aead_ty:ty, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type A = $aead_ty;
                type Kdf = HkdfSha256;
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

                let mut sender_ctx = create_sender_context::<_, _, Kem>(&key, base_nonce_copy, exporter_secret_copy);
                let mut receiver_ctx = create_receiver_context::<_, _, Kem>(&key, base_nonce, exporter_secret);

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

                assert_eq!(shared_sender, shared_receiver, "The exported shared secret should be the same between the sender and the receiver");
                assert_ne!(shared_sender, [0u8; 32]);
            }
        };
    }

    #[cfg(all(feature = "x25519", feature = "alloc"))]
    mod x25519_tests {
        use super::*;

        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes128_x25519,
            AesGcm128,
            crate::kem::X25519HkdfSha256
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes256_x25519,
            AesGcm256,
            crate::kem::X25519HkdfSha256
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_x25519,
            ChaCha20Poly1305,
            crate::kem::X25519HkdfSha256
        );
    }

    #[cfg(all(feature = "p256", feature = "alloc"))]
    mod p256_tests {
        use super::*;

        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes128_p256,
            AesGcm128,
            crate::kem::DhP256HkdfSha256
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes256_p256,
            AesGcm256,
            crate::kem::DhP256HkdfSha256
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_p256,
            ChaCha20Poly1305,
            crate::kem::DhP256HkdfSha256
        );
    }

    #[cfg(all(feature = "p384", feature = "alloc"))]
    mod p384_tests {
        use super::*;
        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes128_p384,
            AesGcm128,
            crate::kem::DhP384HkdfSha384
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_aes256_p384,
            AesGcm256,
            crate::kem::DhP384HkdfSha384
        );
        test_create_ctx_correctness!(
            test_create_ctx_correctness_chacha_p384,
            ChaCha20Poly1305,
            crate::kem::DhP384HkdfSha384
        );
    }
}
