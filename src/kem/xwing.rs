//! Implemented as per https://filippo.io/hpke-pq, which itself derives from
//! https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03

use digest::{ExtendableOutput, Update, XofReader};
use rand_core::{CryptoRng, RngCore};
use sha3::Shake256;
use x_wing::{
    kem::{Decapsulate, Encapsulate},
    DECAPSULATION_KEY_SIZE,
};

use crate::{
    kdf::VERSION_LABEL,
    kem::KemTrait,
    util::{kem_suite_id, write_u16_be, KemSuiteId},
    Deserializable, Serializable,
};
use hybrid_array::typenum::{Prod, Sum, U1024, U3, U32, U64};

// Type-level size constants for X-Wing
type U1216 = Sum<U1024, Prod<U64, U3>>;
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
    type OutputSize = U32;

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

    type NSecret = U32;

    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;

    fn gen_keypair<CsPrng: CryptoRng + RngCore>(csprng: &mut CsPrng) -> (PrivateKey, PublicKey) {
        let (sk, pk) = x_wing::generate_key_pair_from_rng(csprng);
        (PrivateKey(*sk.as_bytes()), PublicKey(pk.to_bytes()))
    }

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey(
            x_wing::DecapsulationKey::from(sk)
                .encapsulation_key()
                .to_bytes(),
        )
    }

    /// DeriveKeyPair from
    /// https://github.com/FiloSottile/hpke/blob/8aa8a04dacd2fb6d7c40e16c3d57037d4eb5e659/hpke-pq.md#kem-functions
    //
    // def DeriveKeyPair(ikm):
    //     seed = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", Nsk)
    //     ek_PQ, ek_T, _, _ = expandKey(seed)
    //     ek = ek_PQ || ek_T
    //     return (seed, ek)
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let suite_id = kem_suite_id::<Self>();
        let mut sk = [0u8; DECAPSULATION_KEY_SIZE];
        shake256_labeled_derive(suite_id, ikm, b"DeriveKeyPair", b"", &mut sk);

        let sk = x_wing::DecapsulationKey::from(sk);
        (
            PrivateKey(*sk.as_bytes()),
            PublicKey(sk.encapsulation_key().to_bytes()),
        )
    }

    /// Decapsulate the encapsulated key using the recipient's private key. This DOES NOT support
    /// authenticated encapsulation, i.e., `pk_sender_id` MUST be `None`.
    ///
    /// # Panics
    /// Panics if `pk_sender_id` is `Some`.
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<super::SharedSecret<Self>, crate::HpkeError> {
        assert!(
            pk_sender_id.is_none(),
            "X-Wing doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        let sk = x_wing::DecapsulationKey::from(sk_recip);
        let ct = x_wing::Ciphertext::from(&encapped_key.0);
        let ss = sk.decapsulate(&ct).expect("infallible");
        Ok(super::SharedSecret(ss.into()))
    }

    /// Decapsulate the encapsulated key using the recipient's private key. This DOES NOT support
    /// authenticated encapsulation, i.e., `sender_id_keypair` MUST be `None`.
    ///
    /// # Panics
    /// Panics if `sender_id_keypair` is `Some`.
    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(super::SharedSecret<Self>, Self::EncappedKey), crate::HpkeError> {
        assert!(
            sender_id_keypair.is_none(),
            "X-Wing doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        let pk = x_wing::EncapsulationKey::from(pk_recip);
        let (ct, ss) = pk.encapsulate_with_rng(csprng).expect("infallible");
        Ok((super::SharedSecret(ss.into()), EncappedKey(ct.to_bytes())))
    }
}

/// SHAKE256.LabeledDerive function from
/// https://github.com/FiloSottile/hpke/blob/8aa8a04dacd2fb6d7c40e16c3d57037d4eb5e659/hpke-pq.md#shake256labeledderive
///
/// Does some domain separation, hashes in all the data, and writes to `out` until `out` is filled
/// with new bytes.
//
// def SHAKE256.LabeledDerive(ikm, label, context, L):
//   suite_id = concat("KEM", I2OSP(kem_id, 2))
//   prefixed_label = I2OSP(len(label), 2) || label
//   labeled_ikm = ikm || "HPKE-v1" || suite_id || prefixed_label || I2OSP(L, 2) || context
//   return SHAKE256(labeled_ikm, L)
fn shake256_labeled_derive(
    suite_id: KemSuiteId,
    ikm: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) {
    // Encode the label and output buffer lengths
    let label_len = {
        let mut buf = [0u8; 2];
        write_u16_be(&mut buf, label.len() as u16);
        buf
    };
    let out_len = {
        let mut buf = [0u8; 2];
        write_u16_be(&mut buf, out.len() as u16);
        buf
    };

    Shake256::default()
        .chain(ikm)
        .chain(VERSION_LABEL)
        .chain(suite_id)
        .chain(label_len)
        .chain(label)
        .chain(out_len)
        .chain(context)
        .finalize_xof()
        .read(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_roundtrip() {
        let mut csprng = rand::rng();
        let (sk, pk) = XWing::gen_keypair(&mut csprng);
        let (shared_secret, encapped_key) =
            XWing::encap(&pk, None, &mut csprng).expect("encapsulation failed");
        let shared_secret_recipient = XWing::decap(&sk, None, &EncappedKey(encapped_key.0.into()))
            .expect("decapsulation failed");
        assert_eq!(shared_secret.0, shared_secret_recipient.0);
    }
}
