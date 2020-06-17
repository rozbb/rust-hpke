use crate::{
    kdf::{HkdfSha512, Kdf as KdfTrait},
    HpkeError,
};

use digest::generic_array::{typenum::marker_traits::Unsigned, ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

/// Implemented by types that have a fixed-length byte representation
pub trait Marshallable {
    type OutputSize: ArrayLength<u8>;

    fn marshal(&self) -> GenericArray<u8, Self::OutputSize>;

    /// Returns the size (in bytes) of this type when marshalled
    fn size() -> usize {
        Self::OutputSize::to_usize()
    }
}

/// Implemented by types that can be deserialized from byte representation
pub trait Unmarshallable: Marshallable + Sized {
    fn unmarshal(encoded: &[u8]) -> Result<Self, HpkeError>;
}

/// This trait captures the requirements of a key exchange mechanism. It must have a way to
/// generate keypairs, perform the KEX computation, and marshal/umarshal KEX pubkeys
pub trait KeyExchange {
    type PublicKey: Clone + Marshallable + Unmarshallable;
    type PrivateKey: Clone + Marshallable + Unmarshallable;
    type KexResult: Marshallable;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    fn kex(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Self::KexResult, HpkeError>;

    fn derive_keypair<Kdf: KdfTrait>(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey);

    /// Generates a random keypair using the given RNG
    fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (Self::PrivateKey, Self::PublicKey) {
        // Make some keying material that's the size of a private key
        let mut ikm: GenericArray<u8, <Self::PrivateKey as Marshallable>::OutputSize> =
            GenericArray::default();
        // Fill it with randomness
        csprng.fill_bytes(&mut ikm);
        // Run derive_keypair. We use SHA-512 to satisfy any security level
        Self::derive_keypair::<HkdfSha512>(&ikm)
    }
}

#[cfg(feature = "p256")]
mod ecdh_nistp;
#[cfg(feature = "p256")]
pub use ecdh_nistp::DhP256;

#[cfg(feature = "x25519-dalek")]
mod x25519;
#[cfg(feature = "x25519-dalek")]
pub use x25519::X25519;
