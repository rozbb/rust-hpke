//! Easy generics-free interfaces for users of HPKE. See example code in the root of this crate for
//! usage.

macro_rules! impl_easy {
    ($kem:ident,  $kdf:ident, $aead:ident, $kem_name:literal, $kdf_name:literal, $aead_name:literal, $mod_name:ident) => {
        #[doc = concat!("Easy interface for users of the (", $kem_name, ", ", $kdf_name, ", ", $aead_name, ") ciphersuite.")]
        pub mod $mod_name {
            use crate::{
                aead::{$aead as Aead, AeadCtxR, AeadCtxS},
                kdf::$kdf as Kdf,
                kem::{$kem as Kem, Kem as KemTrait},
                HpkeError, OpModeR, OpModeS,
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
        }
    };
}

#[cfg(all(feature = "x25519", feature = "chacha"))]
impl_easy!(
    X25519HkdfSha256,
    HkdfSha256,
    ChaCha20Poly1305,
    "DHKEM(X25519, HKDF-SHA256)",
    "HKDF-SHA256",
    "ChaCha20Poly1305",
    x25519_chacha
);

#[cfg(all(feature = "p256", feature = "aes"))]
impl_easy!(
    DhP256HkdfSha256,
    HkdfSha256,
    AesGcm128,
    "DHKEM(P-256, HKDF-SHA256)",
    "HKDF-SHA256",
    "AES-128-GCM",
    p256_aes
);

#[cfg(all(feature = "xwing", feature = "chacha"))]
impl_easy!(
    XWing,
    KdfShake256,
    ChaCha20Poly1305,
    "X-Wing",
    "SHA-256",
    "ChaCha20Poly1305",
    xwing_chacha
);
