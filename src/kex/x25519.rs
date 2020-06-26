use crate::{
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
    kex::{KeyExchange, Marshallable, Unmarshallable},
    HpkeError,
};

use byteorder::{BigEndian, ByteOrder};
use digest::generic_array::{typenum, GenericArray};
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
            Err(HpkeError::InvalidEncoding)
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
            Err(HpkeError::InvalidEncoding)
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

    // def DeriveKeyPair(ikm):
    //   dkp_prk = LabeledExtract(
    //     zero(0),
    //     concat(I2OSP(kem_id, 2), "dkp_prk"),
    //     ikm
    //   )
    //   sk = LabeledExpand(dkp_prk, "sk", zero(0), Nsk)
    //   return (sk, pk(sk))
    /// PRIVATE USE ONLY
    ///
    /// For a function you can actually use, see `kem::Kem::derive_keypair`.
    ///
    /// Deterministically derives a keypair from the given input keying material and KEM ID. This
    /// keying material SHOULD have as many bits of entropy as the bit length of a secret key,
    /// i.e., 256.
    fn derive_keypair<Kdf: KdfTrait>(ikm: &[u8], kem_id: u16) -> (PrivateKey, PublicKey) {
        // Write the label into a byte buffer and extract from the IKM
        let (_, hkdf_ctx) = {
            // The XX is a placeholder for the 16-bit label (which is the KEM ID)
            let mut label_bytes = *b"XXdkp_prk";
            BigEndian::write_u16(&mut label_bytes[..2], kem_id);
            labeled_extract::<Kdf>(&[], &label_bytes, ikm)
        };
        // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
        let mut buf = [0u8; 32];
        hkdf_ctx.labeled_expand(b"sk", &[], &mut buf).unwrap();

        let sk = x25519_dalek::StaticSecret::from(buf);
        let pk = x25519_dalek::PublicKey::from(&sk);

        (PrivateKey(sk), PublicKey(pk))
    }
}

#[cfg(test)]
mod tests {
    use crate::kex::{
        x25519::{PrivateKey, PublicKey, X25519},
        KeyExchange, Marshallable, Unmarshallable,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};

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

        let mut csprng = StdRng::from_entropy();

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

        let mut csprng = StdRng::from_entropy();

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
