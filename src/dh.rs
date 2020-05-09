use crate::HpkeError;

use digest::generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

/// Implemented by types that have a fixed-length byte representation
pub trait Marshallable {
    type OutputSize: ArrayLength<u8>;

    fn marshal(&self) -> GenericArray<u8, Self::OutputSize>;
}

/// Implemented by types that can be deserialized from a fixed-length byte representation
pub trait Unmarshallable: Marshallable {
    fn unmarshal(encoded: GenericArray<u8, Self::OutputSize>) -> Self;
}

/// A convenience type representing the fixed-size byte array that a DH pubkey gets serialized
/// to/from.
pub type MarshalledPublicKey<Dh> =
    GenericArray<u8, <<Dh as DiffieHellman>::PublicKey as Marshallable>::OutputSize>;
/// A convenience type representing the fixed-size byte array that a DH privkey gets serialized
/// to/from.
pub type MarshalledPrivateKey<Dh> =
    GenericArray<u8, <<Dh as DiffieHellman>::PrivateKey as Marshallable>::OutputSize>;

/// This trait captures the requirements of a DH-based KEM (draft02 §5.1). It must have a way to
/// generate keypairs, perform the DH computation, and marshall/umarshall DH pubkeys
pub trait DiffieHellman {
    type PublicKey: Clone + Marshallable + Unmarshallable;
    type PrivateKey: Clone + Marshallable + Unmarshallable;
    type DhResult: Marshallable;

    fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (Self::PrivateKey, Self::PublicKey);

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    fn dh(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Self::DhResult, HpkeError>;
}

pub use x25519::X25519;
pub mod x25519 {
    use super::{DiffieHellman, Marshallable, Unmarshallable};
    use crate::HpkeError;

    use digest::generic_array::{typenum, GenericArray};
    use rand::{CryptoRng, RngCore};
    use subtle::ConstantTimeEq;

    // We wrap the types in order to abstract away the dalek dep

    /// An X25519 public key
    #[derive(Clone)]
    pub struct PublicKey(x25519_dalek::PublicKey);
    /// An X25519 private key key
    #[derive(Clone)]
    pub struct PrivateKey(x25519_dalek::StaticSecret);

    // A bare DH computation result
    pub struct DhResult(x25519_dalek::SharedSecret);

    // Oh I love me an excuse to break out type-level integers
    impl Marshallable for PublicKey {
        type OutputSize = typenum::U32;

        // Dalek lets us convert pubkeys to [u8; 32]
        fn marshal(&self) -> GenericArray<u8, typenum::U32> {
            GenericArray::clone_from_slice(self.0.as_bytes())
        }
    }
    impl Unmarshallable for PublicKey {
        // Dalek also lets us convert [u8; 32] to pubkeys
        fn unmarshal(encoded: GenericArray<u8, typenum::U32>) -> Self {
            let arr: [u8; 32] = encoded.into();
            PublicKey(x25519_dalek::PublicKey::from(arr))
        }
    }

    impl Marshallable for PrivateKey {
        type OutputSize = typenum::U32;

        // Dalek lets us convert scalars to [u8; 32]
        fn marshal(&self) -> GenericArray<u8, typenum::U32> {
            GenericArray::clone_from_slice(&self.0.to_bytes())
        }
    }
    impl Unmarshallable for PrivateKey {
        // Dalek also lets us convert [u8; 32] to scalars
        fn unmarshal(encoded: GenericArray<u8, typenum::U32>) -> Self {
            let arr: [u8; 32] = encoded.into();
            PrivateKey(x25519_dalek::StaticSecret::from(arr))
        }
    }

    impl Marshallable for DhResult {
        // §7.1: DHKEM(Curve25519) Nzz = 32
        type OutputSize = typenum::U32;

        // Dalek lets us convert shared secrets to to [u8; 32]
        fn marshal(&self) -> GenericArray<u8, typenum::U32> {
            GenericArray::clone_from_slice(self.0.as_bytes())
        }
    }

    /// Dummy type which implements the `DiffieHellman` trait
    pub struct X25519 {}

    impl DiffieHellman for X25519 {
        type PublicKey = PublicKey;
        type PrivateKey = PrivateKey;
        type DhResult = DhResult;

        /// Generates an X25519 keypair
        fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (PrivateKey, PublicKey) {
            let sk = x25519_dalek::StaticSecret::new(csprng);
            let pk = x25519_dalek::PublicKey::from(&sk);

            (PrivateKey(sk), PublicKey(pk))
        }

        /// Converts an X25519 private key to a public key
        fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
            PublicKey(x25519_dalek::PublicKey::from(&sk.0))
        }

        /// Does the DH operation. Returns `HpkeError::DiffieHellman` if and only if the DH result
        /// was all zeros. This is required by the HPKE spec.
        fn dh(sk: &PrivateKey, pk: &PublicKey) -> Result<DhResult, HpkeError> {
            let res = sk.0.diffie_hellman(&pk.0);
            // "Senders and recipients MUST check whether the shared secret is the all-zero value
            // and abort if so"
            if res.as_bytes().ct_eq(&[0u8; 32]).into() {
                Err(HpkeError::DiffieHellman)
            } else {
                Ok(DhResult(res))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::dh::{
            x25519::{DhResult, PrivateKey, PublicKey, X25519},
            DiffieHellman, Marshallable, MarshalledPublicKey, Unmarshallable,
        };
        use rand::RngCore;

        // We need this in our marshal-unmarshal tests
        impl PartialEq for PrivateKey {
            fn eq(&self, other: &PrivateKey) -> bool {
                self.0.to_bytes() == other.0.to_bytes()
            }
        }

        // We need this in our marshal-unmarshal tests
        impl PartialEq for PublicKey {
            fn eq(&self, other: &PublicKey) -> bool {
                self.0.as_bytes() == other.0.as_bytes()
            }
        }

        // We need to be able to compare shared secrets in order to make sure that encap* and
        // decap* produce the same output
        impl PartialEq for DhResult {
            fn eq(&self, other: &DhResult) -> bool {
                self.marshal() == other.marshal()
            }
        }

        impl Eq for DhResult {}

        // We need Debug in order to be able to assert_eq! shared secrets
        impl core::fmt::Debug for DhResult {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{:0x?}", self.marshal())
            }
        }

        /// Tests that an unmarshal-marshal round-trip ends up at the same pubkey
        #[test]
        fn test_pubkey_marshal_correctness() {
            type Dh = X25519;

            let mut csprng = rand::thread_rng();

            // Fill a buffer with randomness
            let orig_bytes = {
                let mut buf = <MarshalledPublicKey<Dh> as Default>::default();
                csprng.fill_bytes(buf.as_mut_slice());
                buf
            };

            // Make a pubkey with those random bytes. Note, that unmarshal does not clamp the input
            // bytes. This is why this test passes.
            let pk = <Dh as DiffieHellman>::PublicKey::unmarshal(orig_bytes);
            let pk_bytes = pk.marshal();

            // See if the re-marshalled bytes are the same as the input
            assert_eq!(orig_bytes, pk_bytes);
        }

        /// Tests that an unmarshal-marshal round-trip on a DH keypair ends up at the same values
        #[test]
        fn test_dh_marshal_correctness() {
            type Dh = X25519;

            let mut csprng = rand::thread_rng();

            // Make a random keypair and marshal it
            let (sk, pk) = Dh::gen_keypair(&mut csprng);
            let (sk_bytes, pk_bytes) = (sk.marshal(), pk.marshal());

            // Now unmarshal those bytes
            let new_sk = <Dh as DiffieHellman>::PrivateKey::unmarshal(sk_bytes);
            let new_pk = <Dh as DiffieHellman>::PublicKey::unmarshal(pk_bytes);

            // See if the unmarshalled values are the same as the initial ones
            assert!(new_sk == sk, "private key doesn't marshal correctly");
            assert!(new_pk == pk, "public key doesn't marshal correctly");
        }
    }
}
