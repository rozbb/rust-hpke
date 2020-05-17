use crate::HpkeError;

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

/// This trait captures the requirements of a DH-based KEM (draft02 §5.1). It must have a way to
/// generate keypairs, perform the DH computation, and marshall/umarshall DH pubkeys
pub trait KeyExchange {
    type PublicKey: Clone + Marshallable + Unmarshallable;
    type PrivateKey: Clone + Marshallable + Unmarshallable;
    type KexResult: Marshallable;

    fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (Self::PrivateKey, Self::PublicKey);

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    fn kex(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Self::KexResult, HpkeError>;
}

pub use p256kex::DHP256;
pub mod p256kex {
    use super::{KeyExchange, Marshallable, Unmarshallable};
    use crate::HpkeError;
    use rand::{CryptoRng, RngCore};

    use digest::generic_array::{typenum, GenericArray};

    /// A p256 public key
    #[derive(Clone)]
    pub struct PublicKey(p256::PublicKey);
    /// A p256 private key key
    pub struct PrivateKey(p256::SecretKey);

    impl Clone for PrivateKey {
        fn clone(&self) -> Self {
            PrivateKey(p256::SecretKey::new(
                self.0.secret_scalar().as_ref().clone(),
            ))
        }
    }

    // A bare DH computation result
    pub struct KexResult(p256::arithmetic::AffinePoint);

    impl Marshallable for PublicKey {
        type OutputSize = typenum::U65;

        fn marshal(&self) -> GenericArray<u8, typenum::U65> {
            GenericArray::from_slice(self.0.as_bytes()).clone()
        }
    }

    impl Unmarshallable for PublicKey {
        fn unmarshal(encoded: &[u8]) -> Result<Self, HpkeError> {
            if let Some(pk) = p256::PublicKey::from_bytes(encoded) {
                Ok(Self(pk))
            } else {
                Err(HpkeError::InvalidMarshalledLength)
            }
        }
    }

    impl Marshallable for PrivateKey {
        type OutputSize = typenum::U32;

        fn marshal(&self) -> GenericArray<u8, typenum::U32> {
            GenericArray::clone_from_slice(&self.0.secret_scalar().as_ref())
        }
    }
    impl Unmarshallable for PrivateKey {
        fn unmarshal(encoded: &[u8]) -> Result<Self, HpkeError> {
            if let Ok(pk) = p256::SecretKey::from_bytes(encoded) {
                Ok(Self(pk))
            } else {
                Err(HpkeError::InvalidMarshalledLength)
            }
        }
    }

    impl Marshallable for KexResult {
        // §7.1: DHKEM(P256) Ndh = Npk == 65
        // type OutputSize = typenum::U65;
        type OutputSize = typenum::U32;

        fn marshal(&self) -> GenericArray<u8, typenum::U32> {
            // self.0.to_uncompressed_pubkey().into_bytes()
            GenericArray::clone_from_slice(&self.0.to_compressed_pubkey().into_bytes()[1..])
        }
    }

    /// Dummy type which implements the `KeyExchange` trait
    pub struct DHP256 {}

    impl KeyExchange for DHP256 {
        type PublicKey = PublicKey;
        type PrivateKey = PrivateKey;
        type KexResult = KexResult;

        /// Generates an P256 keypair
        fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (PrivateKey, PublicKey) {
            let mut bytes = GenericArray::default();
            csprng.fill_bytes(&mut bytes);

            let sk = PrivateKey(p256::SecretKey::new(bytes));
            let pk = Self::sk_to_pk(&sk);

            (sk, pk)
        }

        /// Converts an P256 private key to a public key
        fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(sk.0.secret_scalar().as_ref());

            let sk_scal = p256::arithmetic::Scalar::from_bytes(bytes).unwrap();
            let pk = p256::arithmetic::ProjectivePoint::generator() * &sk_scal;
            // TODO: destroy sk_scal
            PublicKey(pk.to_affine().unwrap().to_uncompressed_pubkey().into())
        }

        /// Does the DH operation. Returns `HpkeError::InvalidKeyExchange` if and only if the DH
        /// result was all zeros. This is required by the HPKE spec.
        fn kex(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, HpkeError> {
            let g = p256::arithmetic::AffinePoint::generator();
            let pk = p256::arithmetic::AffinePoint::from_pubkey(&pk.0).unwrap_or(g);
            let pka: p256::arithmetic::ProjectivePoint = pk.into();
            if pk != g {
                // FIXME: extra checks + clearing of sk_scal
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(sk.0.secret_scalar().as_ref());

                let sk_scal = p256::arithmetic::Scalar::from_bytes(bytes).unwrap();
                let res = (pka * &sk_scal).to_affine();
                if res.is_none().into() {
                    Err(HpkeError::InvalidKeyExchange)
                } else {
                    Ok(KexResult(res.unwrap()))
                }
            } else {
                Err(HpkeError::InvalidKeyExchange)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::kex::{
            p256kex::{PrivateKey, PublicKey, DHP256},
            KeyExchange, Marshallable, Unmarshallable,
        };
        use rand::RngCore;

        // We need this in our marshal-unmarshal tests
        impl PartialEq for PrivateKey {
            fn eq(&self, other: &PrivateKey) -> bool {
                self.0.secret_scalar().as_ref() == other.0.secret_scalar().as_ref()
            }
        }

        // We need this in our marshal-unmarshal tests
        impl PartialEq for PublicKey {
            fn eq(&self, other: &PublicKey) -> bool {
                self.0.as_bytes() == other.0.as_bytes()
            }
        }

        #[test]
        fn test_vector_ecdh() {
            // https://tools.ietf.org/html/rfc5903
            type Kex = DHP256;
            let secret =
                hex::decode("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
                    .unwrap();
            let pk =  hex::decode("04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF6356FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB").unwrap();
            //let shared = hex::decode("04D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE522BDE0AF0D8585B8DEF9C183B5AE38F50235206A8674ECB5D98EDB20EB153A2").unwrap();
            let shared =
                hex::decode("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")
                    .unwrap();

            let pk = <Kex as KeyExchange>::PublicKey::unmarshal(&pk).unwrap();
            let secret = <Kex as KeyExchange>::PrivateKey::unmarshal(&secret).unwrap();
            let common = <Kex as KeyExchange>::kex(&secret, &pk).unwrap();
            assert_eq!(common.marshal().as_slice(), shared.as_slice());
        }

        #[test]
        fn test_vector_private_public() {
            type Kex = DHP256;

            let secret =
                hex::decode("aa40ae4c159a0b05d999dfb58273798f848660c037e8950cd053f85b4331b114")
                    .unwrap();
            let pk = hex::decode("04a475670b8b2caa8ebd061d60841f0fab440ff3e47ffadb57e12d930defdae54581411dc5ae829252f39c21aa13a90fc1cdf7cf8267aff2d21bf4bc2344ef7c1a").unwrap();

            let pk = <Kex as KeyExchange>::PublicKey::unmarshal(&pk).unwrap();
            let secret = <Kex as KeyExchange>::PrivateKey::unmarshal(&secret).unwrap();
            assert!(
                <Kex as KeyExchange>::sk_to_pk(&secret) == pk,
                "private to public key conversion"
            );
        }

        /// Tests that an unmarshal-marshal round-trip ends up at the same pubkey
        #[test]
        fn test_pubkey_marshal_correctness() {
            type Kex = DHP256;

            let mut csprng = rand::thread_rng();

            // Fill a buffer with randomness
            let orig_bytes = {
                let mut buf = vec![0u8; <Kex as KeyExchange>::PublicKey::size()];
                csprng.fill_bytes(buf.as_mut_slice());
                buf[0] = 0x04;
                buf
            };

            // Make a pubkey with those random bytes. Note, that unmarshal does not clamp the input
            // bytes. This is why this test passes.
            let pk = <Kex as KeyExchange>::PublicKey::unmarshal(&orig_bytes).unwrap();
            let pk_bytes = pk.marshal();

            // See if the re-marshalled bytes are the same as the input
            assert_eq!(orig_bytes.as_slice(), pk_bytes.as_slice());
        }

        /// Tests that an unmarshal-marshal round-trip on a DH keypair ends up at the same values
        #[test]
        fn test_dh_marshal_correctness() {
            type Kex = DHP256;

            let mut csprng = rand::thread_rng();

            // Make a random keypair and marshal it
            let (sk, pk) = Kex::gen_keypair(&mut csprng);
            let (sk_bytes, pk_bytes) = (sk.marshal(), pk.marshal());

            // Now unmarshal those bytes
            let new_sk = <Kex as KeyExchange>::PrivateKey::unmarshal(&sk_bytes).unwrap();
            let new_pk = <Kex as KeyExchange>::PublicKey::unmarshal(&pk_bytes).unwrap();

            // See if the unmarshalled values are the same as the initial ones
            assert!(new_sk == sk, "private key doesn't marshal correctly");
            assert!(new_pk == pk, "public key doesn't marshal correctly");
        }
    }
}

pub use x25519::X25519;
pub mod x25519 {
    use super::{KeyExchange, Marshallable, Unmarshallable};
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
    pub struct KexResult(x25519_dalek::SharedSecret);

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
        fn unmarshal(encoded: &[u8]) -> Result<Self, HpkeError> {
            if encoded.len() != Self::size() {
                // Pubkeys must be 32 bytes
                Err(HpkeError::InvalidMarshalledLength)
            } else {
                // Copy to a fixed-size array
                let mut arr = [0u8; 32];
                arr.copy_from_slice(encoded);
                Ok(PublicKey(x25519_dalek::PublicKey::from(arr)))
            }
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
        fn unmarshal(encoded: &[u8]) -> Result<Self, HpkeError> {
            if encoded.len() != 32 {
                // Privkeys must be 32 bytes
                Err(HpkeError::InvalidMarshalledLength)
            } else {
                // Copy to a fixed-size array
                let mut arr = [0u8; 32];
                arr.copy_from_slice(encoded);
                Ok(PrivateKey(x25519_dalek::StaticSecret::from(arr)))
            }
        }
    }

    impl Marshallable for KexResult {
        // §7.1: DHKEM(Curve25519) Nzz = 32
        type OutputSize = typenum::U32;

        // Dalek lets us convert shared secrets to to [u8; 32]
        fn marshal(&self) -> GenericArray<u8, typenum::U32> {
            GenericArray::clone_from_slice(self.0.as_bytes())
        }
    }

    /// Dummy type which implements the `KeyExchange` trait
    pub struct X25519 {}

    impl KeyExchange for X25519 {
        type PublicKey = PublicKey;
        type PrivateKey = PrivateKey;
        type KexResult = KexResult;

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

        /// Does the DH operation. Returns `HpkeError::InvalidKeyExchange` if and only if the DH
        /// result was all zeros. This is required by the HPKE spec.
        fn kex(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, HpkeError> {
            let res = sk.0.diffie_hellman(&pk.0);
            // "Senders and recipients MUST check whether the shared secret is the all-zero value
            // and abort if so"
            if res.as_bytes().ct_eq(&[0u8; 32]).into() {
                Err(HpkeError::InvalidKeyExchange)
            } else {
                Ok(KexResult(res))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::kex::{
            x25519::{PrivateKey, PublicKey, X25519},
            KeyExchange, Marshallable, Unmarshallable,
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

        /// Tests that an unmarshal-marshal round-trip ends up at the same pubkey
        #[test]
        fn test_pubkey_marshal_correctness() {
            type Kex = X25519;

            let mut csprng = rand::thread_rng();

            // Fill a buffer with randomness
            let orig_bytes = {
                let mut buf = vec![0u8; <Kex as KeyExchange>::PublicKey::size()];
                csprng.fill_bytes(buf.as_mut_slice());
                buf
            };

            // Make a pubkey with those random bytes. Note, that unmarshal does not clamp the input
            // bytes. This is why this test passes.
            let pk = <Kex as KeyExchange>::PublicKey::unmarshal(&orig_bytes).unwrap();
            let pk_bytes = pk.marshal();

            // See if the re-marshalled bytes are the same as the input
            assert_eq!(orig_bytes.as_slice(), pk_bytes.as_slice());
        }

        /// Tests that an unmarshal-marshal round-trip on a DH keypair ends up at the same values
        #[test]
        fn test_dh_marshal_correctness() {
            type Kex = X25519;

            let mut csprng = rand::thread_rng();

            // Make a random keypair and marshal it
            let (sk, pk) = Kex::gen_keypair(&mut csprng);
            let (sk_bytes, pk_bytes) = (sk.marshal(), pk.marshal());

            // Now unmarshal those bytes
            let new_sk = <Kex as KeyExchange>::PrivateKey::unmarshal(&sk_bytes).unwrap();
            let new_pk = <Kex as KeyExchange>::PublicKey::unmarshal(&pk_bytes).unwrap();

            // See if the unmarshalled values are the same as the initial ones
            assert!(new_sk == sk, "private key doesn't marshal correctly");
            assert!(new_pk == pk, "public key doesn't marshal correctly");
        }
    }
}
