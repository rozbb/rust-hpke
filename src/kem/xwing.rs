//! Implemented as per https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/

use alloc::borrow::ToOwned;
use digest::{ExtendableOutput, Update, XofReader};
use rand_core::{CryptoRng, RngCore};

use crate::{kem::{KemTrait}, Deserializable, Serializable};
use x_wing;
use generic_array::typenum::{U32, U1024, U64, Sum, Prod};

// Type-level size constants for X-Wing
type U1216 = Sum<U1024, Prod<U64, generic_array::typenum::U3>>;
type U1120 = Sum<Sum<U1024, U64>, U32>;

/// The private key uses the compressed seed representation, not
/// the full uncompressed version
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateKey([u8; x_wing::DECAPSULATION_KEY_SIZE]);

impl From<&PrivateKey> for x_wing::DecapsulationKey {
    fn from(sk: &PrivateKey) -> x_wing::DecapsulationKey {
        x_wing::DecapsulationKey::from(sk.0)
    }
}

impl Serializable for PrivateKey {
    type OutputSize = generic_array::typenum::U32;

    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::HpkeError> {
        if bytes.len() != x_wing::DECAPSULATION_KEY_SIZE {
            return Err(crate::HpkeError::ValidationError);
        }
        let mut arr = [0u8; x_wing::DECAPSULATION_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(PrivateKey(arr))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey([u8; x_wing::ENCAPSULATION_KEY_SIZE]);

impl Serializable for PublicKey {
    type OutputSize = U1216;
    
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::HpkeError> {
        if bytes.len() != x_wing::ENCAPSULATION_KEY_SIZE {
            return Err(crate::HpkeError::ValidationError);
        }
        let mut arr = [0u8; x_wing::ENCAPSULATION_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(PublicKey(arr))
    }
}

impl From<&PublicKey> for x_wing::EncapsulationKey {
    fn from(pk: &PublicKey) -> x_wing::EncapsulationKey {
        x_wing::EncapsulationKey::from(&pk.0)
    }
}

#[derive(Clone)]
pub struct EncappedKey([u8; x_wing::CIPHERTEXT_SIZE]);

impl Serializable for EncappedKey {
    type OutputSize = U1120;
    
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::HpkeError> {
        if bytes.len() != x_wing::CIPHERTEXT_SIZE {
            return Err(crate::HpkeError::ValidationError);
        }
        let mut arr = [0u8; x_wing::CIPHERTEXT_SIZE];
        arr.copy_from_slice(bytes);
        Ok(EncappedKey(arr))
    }
}

pub struct XWing;

impl KemTrait for XWing {

    // As per Draft-connolly-cfrg-xwing-kem
    const KEM_ID: u16 = 0x647a;

    type NSecret = generic_array::typenum::U32;

    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;


    fn gen_keypair<CsPrng: CryptoRng + RngCore>(
        csprng: &mut CsPrng,
    ) -> (PrivateKey, PublicKey) {
        let (sk, pk) = x_wing::generate_key_pair(csprng);
        (PrivateKey(*sk.as_bytes()), PublicKey(pk.to_bytes()))
    }

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey(x_wing::DecapsulationKey::from(sk).encapsulation_key().to_bytes())
    }
    
    // Draft-connolly-cfrg-xwing-kem Section 5.6
    // 
    // def DeriveKeyPair(ikm):
    //   # Extract 32-byte seed from variable-length ikm using SHAKE.
    //   sk = SHAKE256(ikm, 32*8)
    //   return GenerateKeyPairDerand(sk)
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let mut hasher = sha3::Shake256::default();
        hasher.update(ikm);
        let mut reader = hasher.finalize_xof();
        let mut sk = [0u8; x_wing::DECAPSULATION_KEY_SIZE];
        reader.read(&mut sk);

        let sk = x_wing::DecapsulationKey::from(sk);
        (PrivateKey(*sk.as_bytes()), PublicKey(sk.encapsulation_key().to_bytes()))
    }
    
    // Draft-connolly-cfrg-xwing-kem Section 5.6
    //
    // Encap() is Encapsulate() from Section 5.4, where an ML-KEM
    // encapsulation key check failure causes an HPKE EncapError.
    fn decap(
        sk_recip: &Self::PrivateKey,
        _pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<super::SharedSecret<Self>, crate::HpkeError> {
        use kem::Decapsulate;
        let sk = x_wing::DecapsulationKey::from(sk_recip);
        let ct = x_wing::Ciphertext::from(&encapped_key.0);
        let ss = sk.decapsulate(&ct).expect("infallible");
        Ok(super::SharedSecret(ss.into()))
    }
    
    // Draft-connolly-cfrg-xwing-kem Section 5.6
    // 
    // Decap() is Decapsulate() from Section 5.5.
    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(super::SharedSecret<Self>, Self::EncappedKey), crate::HpkeError> {
        use kem::Encapsulate;
        let pk = x_wing::EncapsulationKey::from(pk_recip);
        let (ct, ss) = pk.encapsulate(csprng).expect("infallible");
        Ok((super::SharedSecret(ss.into()), EncappedKey(ct.to_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn test_roundtrip() {   
        let mut csprng = StdRng::from_os_rng();
        let (sk, pk) = XWing::gen_keypair(&mut csprng);
        let (shared_secret, encapped_key) =
            XWing::encap(&pk, None, &mut csprng).expect("encapsulation failed");
        let shared_secret_recipient =
            XWing::decap(&sk, None, &EncappedKey(encapped_key.0.into())).expect("decapsulation failed");
        assert_eq!(shared_secret.0, shared_secret_recipient.0);
    }
}
