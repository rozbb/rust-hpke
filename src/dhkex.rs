use crate::{kdf::Kdf as KdfTrait, util::KemSuiteId, Deserializable, Serializable};

use core::fmt::Debug;

#[cfg(feature = "serde_impls")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

// This is the maximum value of all of Npk, Ndh, and Nenc. It's achieved by P-521 in RFC 9180 §7.1
// Table 2.
pub(crate) const MAX_PUBKEY_SIZE: usize = 133;

#[doc(hidden)]
/// Internal error type used to represent `DhKeyExchange::dh()` failing
#[derive(Debug)]
pub struct DhError;

/// This trait captures the requirements of a Diffie-Hellman key exchange mechanism. It must have a
/// way to generate keypairs, perform the Diffie-Hellman operation, and serialize/deserialize
/// pubkeys. This is built into a KEM in `kem/dhkem.rs`.
pub trait DhKeyExchange {
    // Public and private keys need to implement serde::{Serialize, Deserialize} if the serde_impls
    // feature is set. So double up all the definitions: one with serde and one without.

    /// The key exchange's public key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(feature = "serde_impls")]
    type PublicKey: Clone
        + Debug
        + PartialEq
        + Eq
        + Serializable
        + Deserializable
        + SerdeSerialize
        + for<'a> SerdeDeserialize<'a>;
    /// The key exchange's public key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(not(feature = "serde_impls"))]
    type PublicKey: Clone + Debug + PartialEq + Eq + Serializable + Deserializable;

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

    /// The result of a DH operation
    #[doc(hidden)]
    type KexResult: Serializable;

    /// Computes the public key of a given private key
    #[doc(hidden)]
    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    /// Does the Diffie-Hellman operation
    #[doc(hidden)]
    fn dh(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Self::KexResult, DhError>;

    /// Computes a keypair given key material `ikm` of sufficient entropy. See
    /// [`crate::kem::Kem::derive_keypair`] for discussion of entropy.
    #[doc(hidden)]
    fn derive_keypair<Kdf: KdfTrait>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
    ) -> (Self::PrivateKey, Self::PublicKey);
}

#[cfg(any(feature = "p256", feature = "p384"))]
pub(crate) mod ecdh_nistp;

#[cfg(feature = "x25519")]
pub(crate) mod x25519;
