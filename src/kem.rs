//! Traits and structs for key encapsulation mechanisms

use crate::{Deserializable, HpkeError, Serializable};

use core::fmt::Debug;

#[cfg(feature = "getrandom")]
use getrandom::SysRng;
use hybrid_array::{Array, ArraySize};
use rand_core::CryptoRng;
#[cfg(feature = "getrandom")]
use rand_core::UnwrapErr;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[cfg(any(feature = "x25519", feature = "nistp"))]
mod dhkem;
#[cfg(any(feature = "x25519", feature = "nistp"))]
pub use dhkem::*;
#[cfg(all(feature = "mlkem", feature = "nistp"))]
mod mlkem_nistp;
#[cfg(all(feature = "mlkem", feature = "nistp"))]
pub use mlkem_nistp::mlkem768p256::MlKem768P256;
#[cfg(all(feature = "mlkem", feature = "nistp"))]
pub use mlkem_nistp::mlkem1024p384::MlKem1024P384;
#[cfg(feature = "mlkem")]
pub(crate) mod mlkem;
#[cfg(feature = "mlkem")]
pub use mlkem::mlkem768::MlKem768;
#[cfg(feature = "mlkem")]
pub use mlkem::mlkem1024::MlKem1024;
#[cfg(all(feature = "mlkem", feature = "x25519"))]
pub(crate) mod xwing;
#[cfg(all(feature = "mlkem", feature = "x25519"))]
pub use xwing::XWing;

/// Represents authenticated encryption functionality
pub trait Kem: Sized {
    /// The key exchange's public key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    type PublicKey: Clone + Debug + PartialEq + Eq + Serializable + Deserializable;

    /// The key exchange's private key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    type PrivateKey: Clone + ConstantTimeEq + Serializable + Deserializable;

    /// Computes the public key of a given private key
    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;
    /// The encapsulated key for this KEM. This is used by the recipient to derive the shared
    /// secret.
    type EncappedKey: Clone + Serializable + Deserializable;

    /// The size of a shared secret in this KEM
    #[doc(hidden)]
    type NSecret: ArraySize;

    /// The algorithm identifier for a KEM implementation
    const KEM_ID: u16;

    /// Deterministically derives a keypair from the given input keying material
    ///
    /// Requirements
    /// ============
    /// This keying material SHOULD have as many bits of entropy as the bit length of a secret key,
    /// i.e., `8 * Self::PrivateKey::size()`. For X25519 and P-256, this is 256 bits of
    /// entropy.
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey);

    /// Generates a random keypair using the system RNG.
    ///
    /// Panics
    /// ======
    /// Panics if `getrandom::SysRng` fails to generate random bytes.
    #[cfg(feature = "getrandom")]
    fn gen_keypair() -> (Self::PrivateKey, Self::PublicKey) {
        Self::gen_keypair_with_rng(&mut UnwrapErr(SysRng))
    }

    /// Generates a random keypair using the given RNG
    // Implementation note: This simply does DeriveKeyPair(random(Nsk)). This does not
    // match the definition of GenerateKeyPair in the PQ and and XWing implementations
    //   <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#section-3-7>
    // and
    //   <https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html#section-5.2-2>
    // In reality, though, we don't care. The goal of this function is to produce a random
    // keypair, and it guarantees no cross-compatiblity. There are no test vectors for it,
    // and the original RFC doesn't even define it (merely uses "can be defined")
    //   <https://datatracker.ietf.org/doc/html/rfc9180#section-4-7>
    // Thus, for us it suffices to just keep this definition in place. More discussion here
    //   <https://mailarchive.ietf.org/arch/msg/hpke/v1Jw382gXveSQxsi8RE4S9ep-bY/>
    fn gen_keypair_with_rng(csprng: &mut impl CryptoRng) -> (Self::PrivateKey, Self::PublicKey) {
        // Make some keying material that's the size of a private key
        let mut ikm: Array<u8, <Self::PrivateKey as Serializable>::OutputSize> = Array::default();
        // Fill it with randomness
        csprng.fill_bytes(&mut ikm);
        // Run derive_keypair using the KEM's KDF
        let keypair = Self::derive_keypair(&ikm);

        // Zeroize the IKM as it contains sensitive material used to derive the private key
        ikm.zeroize();

        keypair
    }

    /// Derives a shared secret given the encapsulated key and the recipients secret key. If
    /// `pk_sender_id` is given, the sender's identity will be tied to the shared secret.
    ///
    /// Return Value
    /// ============
    /// Returns a shared secret on success. If an error happened during key exchange, returns
    /// `Err(HpkeError::DecapError)`.
    #[doc(hidden)]
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError>;

    /// Derives a shared secret and an ephemeral pubkey that the owner of the reciepint's pubkey
    /// can use to derive the same shared secret. If `sk_sender_id` is given, the sender's identity
    /// will be tied to the shared secret. All this does is generate an ephemeral keypair and pass
    /// to `encap_with_eph`.
    ///
    /// Return Value
    /// ============
    /// Returns a shared secret and encapped key on success. If an error happened during key
    /// exchange, returns `Err(HpkeError::EncapError)`.
    ///
    /// Panics
    /// ======
    /// Panics if `getrandom::SysRng` fails to generate random bytes.
    #[cfg(feature = "getrandom")]
    fn encap(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        Self::encap_with_rng(pk_recip, sender_id_keypair, &mut UnwrapErr(SysRng))
    }

    /// Derives a shared secret and an ephemeral pubkey that the owner of the reciepint's pubkey
    /// can use to derive the same shared secret. If `sk_sender_id` is given, the sender's identity
    /// will be tied to the shared secret. All this does is generate an ephemeral keypair and pass
    /// to `encap_with_eph`.
    ///
    /// Return Value
    /// ============
    /// Returns a shared secret and encapped key on success. If an error happened during key
    /// exchange, returns `Err(HpkeError::EncapError)`.
    fn encap_with_rng(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut impl CryptoRng,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError>;
}

// Kem is used as a type parameter everywhere. To avoid confusion, alias it
use Kem as KemTrait;

/// A convenience type for `[u8; NSecret]` for any given KEM
#[doc(hidden)]
pub struct SharedSecret<Kem: KemTrait>(pub Array<u8, Kem::NSecret>);

impl<Kem: KemTrait> Default for SharedSecret<Kem> {
    fn default() -> SharedSecret<Kem> {
        SharedSecret(Array::<u8, Kem::NSecret>::default())
    }
}

// SharedSecrets should zeroize on drop
impl<Kem: KemTrait> Zeroize for SharedSecret<Kem> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}
impl<Kem: KemTrait> Drop for SharedSecret<Kem> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use crate::{Deserializable, Serializable, kem::Kem as KemTrait};

    macro_rules! test_encap_correctness {
        ($test_name:ident, $kem_ty:ty, $use_auth:literal) => {
            /// Tests that encap and decap produce the same shared secret when composed
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let mut csprng = rand::rng();
                let (sk_recip, pk_recip) = Kem::gen_keypair_with_rng(&mut csprng);

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) =
                    Kem::encap_with_rng(&pk_recip, None, &mut csprng).unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    Kem::decap(&sk_recip, None, &encapped_key).unwrap();

                // Ensure that the encapsulated secret is what decap() derives
                assert_eq!(auth_shared_secret.0, decapped_auth_shared_secret.0);

                //
                // Now do it with the auth, i.e., using the sender's identity keys
                //
                if $use_auth {
                    // Make a sender identity keypair
                    let (sk_sender_id, pk_sender_id) = Kem::gen_keypair_with_rng(&mut csprng);

                    // Encapsulate a random shared secret
                    let (auth_shared_secret, encapped_key) = Kem::encap_with_rng(
                        &pk_recip,
                        Some((&sk_sender_id, &pk_sender_id.clone())),
                        &mut csprng,
                    )
                    .unwrap();

                    // Decap it
                    let decapped_auth_shared_secret =
                        Kem::decap(&sk_recip, Some(&pk_sender_id), &encapped_key).unwrap();

                    // Ensure that the encapsulated secret is what decap() derives
                    assert_eq!(auth_shared_secret.0, decapped_auth_shared_secret.0);
                }
            }
        };
    }

    /// Tests that an deserialize-serialize round trip on an encapped key ends up at the same value
    macro_rules! test_encapped_serialize {
        ($test_name:ident, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                // Encapsulate a random shared secret
                let encapped_key = {
                    let mut csprng = rand::rng();
                    let (_, pk_recip) = Kem::gen_keypair_with_rng(&mut csprng);
                    Kem::encap_with_rng(&pk_recip, None, &mut csprng).unwrap().1
                };
                // Serialize it
                let encapped_key_bytes = encapped_key.to_bytes();
                // Deserialize it
                let new_encapped_key =
                    <<Kem as KemTrait>::EncappedKey as Deserializable>::from_bytes(
                        &encapped_key_bytes,
                    )
                    .unwrap();

                // Now serialize again
                assert_eq!(
                    new_encapped_key.to_bytes(),
                    encapped_key_bytes,
                    "encapped key doesn't serialize correctly"
                );
            }
        };
    }

    #[cfg(feature = "x25519")]
    mod x25519_tests {
        use super::*;
        use crate::kem::*;

        test_encap_correctness!(test_encap_correctness_x25519, X25519HkdfSha256, true);
        test_encapped_serialize!(test_encapped_serialize_x25519, X25519HkdfSha256);
    }

    #[cfg(feature = "nistp")]
    mod nistp_test {
        use super::*;
        use crate::kem::*;

        test_encap_correctness!(test_encap_correctness_p256, DhP256HkdfSha256, true);
        test_encapped_serialize!(test_encapped_serialize_p256, DhP256HkdfSha256);

        test_encap_correctness!(test_encap_correctness_p384, DhP384HkdfSha384, true);
        test_encapped_serialize!(test_encapped_serialize_p384, DhP384HkdfSha384);

        test_encap_correctness!(test_encap_correctness_p521, DhP521HkdfSha512, true);
        test_encapped_serialize!(test_encapped_serialize_p521, DhP521HkdfSha512);
    }

    #[cfg(feature = "mlkem")]
    mod mlkem_test {
        use super::*;
        use crate::kem::*;

        test_encap_correctness!(test_encap_correctness_mlkem768, MlKem768, false);
        test_encapped_serialize!(test_encapped_serialize_mlkem768, MlKem768);

        test_encap_correctness!(test_encap_correctness_mlkem1024, MlKem1024, false);
        test_encapped_serialize!(test_encapped_serialize_mlkem1024, MlKem1024);
    }

    #[cfg(all(feature = "mlkem", feature = "nistp"))]
    mod mlkem_nistp_test {
        use super::*;
        use crate::kem::*;

        test_encap_correctness!(test_encap_correctness_mlkem768p256, MlKem768P256, false);
        test_encapped_serialize!(test_encapped_serialize_mlkem768p256, MlKem768P256);

        test_encap_correctness!(test_encap_correctness_mlkem1024p384, MlKem1024P384, false);
        test_encapped_serialize!(test_encapped_serialize_mlkem1024p384, MlKem1024P384);
    }

    #[cfg(all(feature = "mlkem", feature = "x25519"))]
    mod xwing_test {
        use super::*;
        use crate::kem::*;

        test_encap_correctness!(test_encap_correctness_xwing, XWing, false);
        test_encapped_serialize!(test_encapped_serialize_xwing, XWing);
    }
}
