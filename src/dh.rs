use digest::generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

/// This trait is used for values with fixed lengths that get sent over the wire. This includes DH
/// public keys and encapsulated KEM outputs.
pub trait Marshallable {
    type OutputSize: ArrayLength<u8>;

    fn marshal(&self) -> GenericArray<u8, Self::OutputSize>;
    fn unmarshal(encoded: GenericArray<u8, Self::OutputSize>) -> Self;
}

/// This trait captures the requirements of a DH-based KEM (draft02 §5.1). It must have a way to
/// generate keypairs, perform the DH computation, and marshall/umarshall DH pubkeys
pub trait DiffieHellman {
    type PublicKey: Clone + Marshallable;
    type PrivateKey: Clone + Marshallable;
    type DhResult: Into<Vec<u8>>;

    const KEM_ID: u16;

    fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (Self::PrivateKey, Self::PublicKey);

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    fn dh(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Self::DhResult;
}

/// A shared secret as a result of a Diffie-Hellman operation
pub(crate) enum SharedSecret<Dh: DiffieHellman> {
    /// Secret is not linked to the sender's identity
    Unauthed(Dh::DhResult),
    /// Secret is linked to the sender's identity
    Authed(Dh::DhResult, Dh::DhResult),
}

// We need to be able to serialize SharedSecrets. Since it's not necessarily contiguous in memory,
// a Vec<u8> is the most logical way.
impl<Dh: DiffieHellman> Into<Vec<u8>> for SharedSecret<Dh> {
    fn into(self) -> Vec<u8> {
        match self {
            SharedSecret::Unauthed(s) => s.into(),
            SharedSecret::Authed(s, t) => [s.into(), t.into()].concat(),
        }
    }
}

pub mod x25519 {
    use super::{DiffieHellman, Marshallable};
    use digest::generic_array::{typenum, GenericArray};
    use rand::{CryptoRng, RngCore};

    // We wrap the types in order to abstract away the dalek dep

    /// An X25519 public key
    #[derive(Clone)]
    pub struct PublicKey(x25519_dalek::PublicKey);
    /// An X25519 private key key
    #[derive(Clone)]
    pub struct PrivateKey(x25519_dalek::StaticSecret);

    // A bare DH computation result. This can be used to make either a SharedSecret::Unauthed (if
    // it's just one DhResult), or a SharedSecret::Authed (if it's two).
    pub struct DhResult(x25519_dalek::SharedSecret);

    // Oh I love me an excuse to break out type-level integers
    impl Marshallable for PublicKey {
        type OutputSize = typenum::U32;

        // Dalek lets us convert pubkeys to [u8; 32]
        fn marshal(&self) -> GenericArray<u8, typenum::U32> {
            GenericArray::clone_from_slice(self.0.as_bytes())
        }

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

        // Dalek also lets us convert [u8; 32] to scalars
        fn unmarshal(encoded: GenericArray<u8, typenum::U32>) -> Self {
            let arr: [u8; 32] = encoded.into();
            PrivateKey(x25519_dalek::StaticSecret::from(arr))
        }
    }

    // Into<Vec<u8>> for SharedSecret relies on this
    impl Into<Vec<u8>> for DhResult {
        fn into(self) -> Vec<u8> {
            self.0.as_bytes().to_vec()
        }
    }

    /// Dummy type which implements the `DiffieHellman` trait
    pub struct X25519Impl {}

    impl DiffieHellman for X25519Impl {
        type PublicKey = PublicKey;
        type PrivateKey = PrivateKey;
        type DhResult = DhResult;

        // Section 8.1: DHKEM(Curve25519)
        const KEM_ID: u16 = 0x0002;

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

        /// Does the DH operation
        fn dh(sk: &PrivateKey, pk: &PublicKey) -> DhResult {
            DhResult(sk.0.diffie_hellman(&pk.0))
        }
    }

    // Some debugging stuff so we can test X25519 functionality

    #[cfg(test)]
    use super::SharedSecret;

    // We need to be able to compare shared secrets in order to make sure that encap* and decap*
    // produce the same output
    #[cfg(test)]
    impl PartialEq for SharedSecret<X25519Impl> {
        fn eq(&self, other: &SharedSecret<X25519Impl>) -> bool {
            match (self, other) {
                (SharedSecret::Authed(x1, y1), SharedSecret::Authed(x2, y2)) => {
                    x1.0.as_bytes() == x2.0.as_bytes() && y1.0.as_bytes() == y2.0.as_bytes()
                }
                (SharedSecret::Unauthed(x1), SharedSecret::Unauthed(x2)) => {
                    x1.0.as_bytes() == x2.0.as_bytes()
                }
                _ => false,
            }
        }
    }

    #[cfg(test)]
    impl Eq for SharedSecret<X25519Impl> {}

    // We need Debug in order to be able to assert_eq! shared secrets
    #[cfg(test)]
    impl std::fmt::Debug for SharedSecret<X25519Impl> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                SharedSecret::Authed(x1, x2) => {
                    write!(f, "{:0x?}\n{:0x?}", x1.0.as_bytes(), x2.0.as_bytes())
                }
                SharedSecret::Unauthed(x) => write!(f, "{:0x?}", x.0.as_bytes()),
            }
        }
    }
}
