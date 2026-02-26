//! Easy low-code-noise interfaces for users of HPKE. For usage, see the example code in the root of
//! this crate.

macro_rules! impl_easy {
    ($kem_dep:literal, $aead_dep:literal, $kem:ident,  $kdf:ident, $aead:ident, $kem_name:literal, $kdf_name:literal, $aead_name:literal, $mod_name:ident) => {
        #[cfg(all(feature = $kem_dep, feature = $aead_dep))]
        #[doc = concat!("Easy HPKE interface for the (", $kem_name, ", ", $kdf_name, ", ", $aead_name, ") ciphersuite.")]
        pub mod $mod_name {
            use crate::{
                aead::{$aead as Aead, AeadCtxR, AeadCtxS},
                kdf::$kdf as Kdf,
                kem::{$kem as Kem, Kem as KemTrait},
                HpkeError, OpModeR, OpModeS, Vec,
            };

            pub use crate::Serializable;
            pub use crate::Deserializable;
            pub use crate::inout::InOutBuf;

            pub type PublicKey = <Kem as KemTrait>::PublicKey;
            pub type PrivateKey = <Kem as KemTrait>::PrivateKey;
            pub type EncappedKey = <Kem as KemTrait>::EncappedKey;
            pub type AeadTag = crate::aead::AeadTag<Aead>;

            #[doc = concat!("Does a [`crate::setup_sender`] with [`OpModeS::Base`], using the (", $kem_name, ", ", $kdf_name, ", ", $aead_name, ") ciphersuite.")]
            pub fn setup_sender(
                pk_recip: &PublicKey,
                info: &[u8],
            ) -> Result<(EncappedKey, AeadCtxS<Aead, Kdf, Kem>), HpkeError> {
                crate::setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, pk_recip, info)
            }

            #[doc = concat!("Does a [`crate::setup_receiver`] with [`OpModeR::Base`], using the (", $kem_name, ", ", $kdf_name, ", ", $aead_name, ") ciphersuite.")]
            pub fn setup_receiver(
                sk_recip: &PrivateKey,
                encapped_key: &EncappedKey,
                info: &[u8],
            ) -> Result<AeadCtxR<Aead, Kdf, Kem>, HpkeError> {
                crate::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, sk_recip, encapped_key, info)
            }

            #[doc = concat!("Generates a new ", $kem_name, " keypair")]
            pub fn gen_keypair() -> (PrivateKey, PublicKey) {
                Kem::gen_keypair()
            }

            #[doc = concat!("Does a [`crate::single_shot_seal`] with [`OpModeS::Base`], using the (", $kem_name, ", ", $kdf_name, ", ", $aead_name, ") ciphersuite.")]
            pub fn single_shot_seal(
                pk_recip: &PublicKey,
                info: &[u8],
                plaintext: &[u8],
                aad: &[u8],
            ) -> Result<(EncappedKey, Vec<u8>), HpkeError> {
                crate::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, pk_recip, info, plaintext, aad)
            }

            #[doc = concat!("Does a [`crate::single_shot_open`] with [`OpModeR::Base`], using the (", $kem_name, ", ", $kdf_name, ", ", $aead_name, ") ciphersuite.")]
            pub fn single_shot_open(
                sk_recip: &PrivateKey,
                encapped_key: &EncappedKey,
                info: &[u8],
                ciphertext: &[u8],
                aad: &[u8],
            ) -> Result<Vec<u8>, HpkeError> {
                crate::single_shot_open::<Aead, Kdf, Kem>(&OpModeR::Base, sk_recip, encapped_key, info, ciphertext, aad)
            }
        }
    };
}

#[cfg(all(feature = "x25519", feature = "chacha"))]
impl_easy!(
    "x25519",                     // KEM feature
    "chacha",                     // AEAD feature
    X25519HkdfSha256,             // KEM type
    HkdfSha256,                   // KDF type
    ChaCha20Poly1305,             // AEAD type
    "DHKEM(X25519, HKDF-SHA256)", // Ciphersuite name
    "HKDF-SHA256",                // KDF name
    "ChaCha20Poly1305",           // AEAD name
    x25519_chacha                 // Module name
);

impl_easy!(
    "p256",                      // KEM feature
    "aes",                       // AEAD feature
    DhP256HkdfSha256,            // KEM type
    HkdfSha256,                  // KDF type
    AesGcm128,                   // AEAD type
    "DHKEM(P-256, HKDF-SHA256)", // Ciphersuite name
    "HKDF-SHA256",               // KDF name
    "AES-128-GCM",               // AEAD name
    p256_aes                     // Module name
);

impl_easy!(
    "xwing",            // KEM feature
    "chacha",           // AEAD feature
    XWing,              // KEM type
    KdfShake256,        // KDF type
    ChaCha20Poly1305,   // AEAD type
    "X-Wing",           // Ciphersuite name
    "SHAKE-256",        // KDF name
    "ChaCha20Poly1305", // AEAD name
    xwing_chacha        // Module name
);
