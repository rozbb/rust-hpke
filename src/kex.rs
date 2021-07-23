use crate::{kdf::Kdf as KdfTrait, util::KemSuiteId, HpkeError};

use generic_array::{typenum::marker_traits::Unsigned, ArrayLength, GenericArray};

#[cfg(feature = "serde_impls")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

// This is currently the maximum value of all of Npk, Ndh, and Nenc. It's achieved by P-521
pub(crate) const MAX_PUBKEY_SIZE: usize = 133;

/// Implemented by types that have a fixed-length byte representation
pub trait Serializable {
    type OutputSize: ArrayLength<u8>;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize>;

    /// Returns the size (in bytes) of this type when serialized
    fn size() -> usize {
        Self::OutputSize::to_usize()
    }
}

/// Implemented by types that can be deserialized from byte representation
pub trait Deserializable: Serializable + Sized {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError>;
}

/// This trait captures the requirements of a key exchange mechanism. It must have a way to
/// generate keypairs, perform the KEX computation, and serialize/deserialize KEX pubkeys. Most of
/// this functionality is hidden, though. Use `Kem::derive_keypair` or `Kem::gen_keypair` to make
/// a keypair.
pub trait KeyExchange {
    // Public and private keys need to implement serde::{Serialize, Deserialize} if the serde_impls
    // feature is set. So double up all the definitions: one with serde and one without.

    /// The key exchange's public key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(feature = "serde_impls")]
    type PublicKey: Clone
        + Serializable
        + Deserializable
        + SerdeSerialize
        + for<'a> SerdeDeserialize<'a>;
    /// The key exchange's public key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(not(feature = "serde_impls"))]
    type PublicKey: Clone + Serializable + Deserializable;

    /// The key exchange's private key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(feature = "serde_impls")]
    type PrivateKey: Clone
        + Serializable
        + Deserializable
        + SerdeSerialize
        + for<'a> SerdeDeserialize<'a>;
    /// The key exchange's private key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(not(feature = "serde_impls"))]
    type PrivateKey: Clone + Serializable + Deserializable;

    #[doc(hidden)]
    type KexResult: Serializable;

    #[doc(hidden)]
    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    #[doc(hidden)]
    fn kex(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Self::KexResult, ()>;

    #[doc(hidden)]
    fn derive_keypair<Kdf: KdfTrait>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
    ) -> (Self::PrivateKey, Self::PublicKey);
}

#[cfg(feature = "p256")]
pub(crate) mod ecdh_nistp;
#[cfg(feature = "p256")]
pub use ecdh_nistp::DhP256;

#[cfg(feature = "x25519-dalek")]
pub(crate) mod x25519;
#[cfg(feature = "x25519-dalek")]
pub use x25519::X25519;
