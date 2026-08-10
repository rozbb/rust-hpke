//! The X-Wing hybrid PQ KEM, aka MLKEM768-X25519
//!
//! Implemented as per <https://filippo.io/hpke-pq>, which itself derives from
//! <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03>

use crate::{
    Deserializable, HpkeError, Serializable,
    kdf::one_stage_kdf::labeled_derive,
    kem::{KemTrait, SharedSecret},
    util::{enforce_equal_len, enforce_outbuf_len, kem_suite_id},
};

use hybrid_array::typenum::{Prod, Sum, U3, U32, U64, U1024, Unsigned};
use rand_core::CryptoRng;
use shake::Shake256;
use subtle::{Choice, ConstantTimeEq};
use x_wing::{
    Decapsulator, KeyExport, TryKeyInit,
    kem::{Decapsulate, TryDecapsulate},
};
use zeroize::Zeroize;

// Type-level size constants for X-Wing
type U1216 = Sum<U1024, Prod<U64, U3>>;
type U1120 = Sum<Sum<U1024, U64>, U32>;

/// The number of random bytes required to do an X-Wing encapsulation
const XWING_ENCAP_RANDOMNESS_SIZE: usize = 64;

#[derive(Clone)]
pub struct PrivateKey(x_wing::DecapsulationKey);

impl Serializable for PrivateKey {
    // x_wing::DECAPSULATION_KEY_SIZE == 32
    type OutputSize = U32;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        buf.copy_from_slice(self.0.as_bytes());
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Check the input buf length is correct and error if not
        enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = [0u8; Self::OutputSize::USIZE];
        arr.copy_from_slice(encoded);

        let sk = PrivateKey(arr.into());
        arr.zeroize();

        Ok(sk)
    }
}

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_bytes().ct_eq(other.0.as_bytes())
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for PrivateKey {}

#[derive(Clone)]
pub struct PrivateKeyRejectNonContrib(x_wing::DecapsulationKeyRejectNonContrib);

impl Serializable for PrivateKeyRejectNonContrib {
    // x_wing::DECAPSULATION_KEY_SIZE == 32
    type OutputSize = U32;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        buf.copy_from_slice(&self.0.to_bytes());
    }
}

impl Deserializable for PrivateKeyRejectNonContrib {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Check the input buf length is correct and error if not
        enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = [0u8; Self::OutputSize::USIZE];
        arr.copy_from_slice(encoded);

        let sk = PrivateKeyRejectNonContrib(arr.into());
        arr.zeroize();

        Ok(sk)
    }
}

impl ConstantTimeEq for PrivateKeyRejectNonContrib {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.to_bytes().ct_eq(&other.0.to_bytes())
    }
}

impl PartialEq for PrivateKeyRejectNonContrib {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for PrivateKeyRejectNonContrib {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(x_wing::EncapsulationKey);

impl Serializable for PublicKey {
    type OutputSize = U1216;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        buf.copy_from_slice(&self.0.to_bytes());
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Check the input buf length is correct and error if not
        enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;
        // Infallible bc of the check above
        let arr = encoded.try_into().unwrap();

        let pk = x_wing::EncapsulationKey::new(arr).map_err(|_| HpkeError::ValidationError)?;

        Ok(PublicKey(pk))
    }
}

#[derive(Clone)]
pub struct EncappedKey(x_wing::Ciphertext);

impl Serializable for EncappedKey {
    type OutputSize = U1120;

    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        x_wing::Ciphertext::try_from(bytes)
            .map_err(|_| HpkeError::ValidationError)
            .map(EncappedKey)
    }
}

/// X-Wing (a.k.a ML-KEM 768 + X25519) hybrid post-quantum KEM.
///
/// This KEM implementation accepts "non-contributory behaviour" in the X25519 component.
/// To reject instead, use [`XWingRejectNonContrib`].
pub struct XWing;

impl XWing {
    // Encapsulate with the given randomness
    pub(crate) fn encap_deterministic(
        pk_recip: &PublicKey,
        randomness: &[u8; XWING_ENCAP_RANDOMNESS_SIZE],
    ) -> Result<(SharedSecret<Self>, EncappedKey), HpkeError> {
        let (ct, ss) = pk_recip.0.encapsulate_deterministic(randomness.into());
        Ok((SharedSecret(ss), EncappedKey(ct)))
    }
}

impl KemTrait for XWing {
    // Per https://www.ietf.org/archive/id/draft-ietf-hpke-pq-03.html#name-pq-t-hybrid-entries-for-the
    const KEM_ID: u16 = 0x647a;

    // From https://www.ietf.org/archive/id/draft-ietf-hpke-pq-03.html#section-4-6.3.2.1.1
    // NSecret = Nss of X-Wing, which itself is 32 bytes, per
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-02.html#section-4.2-4.5.1
    type NSecret = U32;

    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;

    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        PublicKey(sk.0.encapsulation_key().clone())
    }

    // From https://www.ietf.org/archive/id/draft-ietf-hpke-pq-03.html#section-4-5
    //
    // def DeriveKeyPair(ikm):
    //   seed = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32)
    //   return KEM.DeriveKeyPair(seed)
    fn derive_keypair(ikm: &[u8]) -> (PrivateKey, PublicKey) {
        let suite_id = kem_suite_id::<Self>();
        let mut sk_bytes = [0u8; <PrivateKey as Serializable>::OutputSize::USIZE];
        labeled_derive::<Shake256>(&suite_id, &[ikm], b"DeriveKeyPair", &[b""], &mut sk_bytes);

        // Parse the sk. Can unwrap bc from_bytes only requires that the input len is OutputSize
        let sk = PrivateKey::from_bytes(&sk_bytes).unwrap();
        let pk = Self::sk_to_pk(&sk);
        sk_bytes.zeroize();

        (sk, pk)
    }

    /// Decapsulate the encapsulated key using the recipient's private key. This DOES NOT support
    /// authenticated encapsulation, i.e., `pk_sender_id` MUST be `None`.
    ///
    /// # Panics
    /// Panics if `pk_sender_id` is `Some`.
    fn decap(
        sk_recip: &PrivateKey,
        pk_sender_id: Option<&PublicKey>,
        encapped_key: &EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        assert!(
            pk_sender_id.is_none(),
            "X-Wing doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        let ss = sk_recip.0.decapsulate(&encapped_key.0);
        Ok(SharedSecret(ss))
    }

    /// Decapsulate the encapsulated key using the recipient's private key. This DOES NOT support
    /// authenticated encapsulation, i.e., `sender_id_keypair` MUST be `None`.
    ///
    /// # Panics
    /// Panics if `sender_id_keypair` is `Some`.
    fn encap_with_rng(
        pk_recip: &PublicKey,
        sender_id_keypair: Option<(&PrivateKey, &PublicKey)>,
        csprng: &mut impl CryptoRng,
    ) -> Result<(SharedSecret<Self>, EncappedKey), HpkeError> {
        assert!(
            sender_id_keypair.is_none(),
            "X-Wing doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        // Generate randomness and call encap_deterministic
        let mut randomness = [0u8; XWING_ENCAP_RANDOMNESS_SIZE];
        csprng.fill_bytes(&mut randomness);
        let res = Self::encap_deterministic(pk_recip, &randomness);
        randomness.zeroize();
        res
    }
}

// Impl the trait necessary for known-answer tests
#[cfg(all(test, feature = "kat"))]
impl crate::kat_tests::TestableKem for XWing {
    // There is no encap-with-eph, since that only makes sense for DHKEMs
    type EphemeralKey = core::convert::Infallible;
    fn encap_with_eph(
        _pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        _sk_eph: Self::EphemeralKey,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        unimplemented!()
    }

    fn encap_det(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        randomness: &[u8],
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        assert!(
            sender_id_keypair.is_none(),
            "X-Wing does not support authenticated encapsulation"
        );
        XWing::encap_deterministic(pk_recip, randomness.try_into().unwrap())
    }
}

/// X-Wing (a.k.a ML-KEM 768 + X25519) hybrid post-quantum KEM.
///
/// This KEM implementation rejects "non-contributory behaviour" in the X25519 component.
/// To accept instead, use [`XWing`].
///
/// # Backstory
///
/// [RFC 7748] defines the `X25519` function, and [specifies] that when used for ECDH
/// (as it is inside X-Wing), the implementation **MAY** abort if the all-zero value
/// is produced as a shared secret. X-Wing, as initially specified, used the X25519
/// function without making any mention of this **MAY**, meaning that implementations
/// inherited whatever behaviour their underlying X25519 ECDH implementation provided.
///
/// This crate initially did not check for non-contributory behaviour, which meant it
/// was incompatible with other implementations that did (in that it would accept
/// ciphertexts that other implementations reject).
///
/// [CFRG have decided] that they will pick a single behaviour for the IETF X-Wing
/// standard. Until the corresponding RFC is published, this crate supports both
/// behaviours: [`XWing`] accepts non-contributory behaviour for backwards-compatibility
/// with existing usages, and this struct can be used to instead reject non-contributory
/// behaviour. Once the RFC is published, `XWing` will be altered to match it.
///
/// [RFC 7748]: https://www.rfc-editor.org/info/rfc7748/#section-5
/// [specifies]: https://www.rfc-editor.org/info/rfc7748/#section-6.1
/// [CFRG have decided]: https://mailarchive.ietf.org/arch/msg/cfrg/v9fEHQj3QTUpdu72AzjyyrY4j2g/
pub struct XWingRejectNonContrib;

impl KemTrait for XWingRejectNonContrib {
    const KEM_ID: u16 = XWing::KEM_ID;
    type NSecret = <XWing as KemTrait>::NSecret;
    type PublicKey = <XWing as KemTrait>::PublicKey;
    type PrivateKey = PrivateKeyRejectNonContrib;
    type EncappedKey = <XWing as KemTrait>::EncappedKey;

    fn sk_to_pk(sk: &PrivateKeyRejectNonContrib) -> PublicKey {
        PublicKey(sk.0.encapsulation_key().clone())
    }

    fn derive_keypair(ikm: &[u8]) -> (PrivateKeyRejectNonContrib, PublicKey) {
        let (sk, pk) = XWing::derive_keypair(ikm);

        let sk = PrivateKeyRejectNonContrib::from_bytes(&sk.to_bytes()).expect("valid");

        (sk, pk)
    }

    /// Decapsulate the encapsulated key using the recipient's private key. This DOES NOT support
    /// authenticated encapsulation, i.e., `pk_sender_id` MUST be `None`.
    ///
    /// # Panics
    /// Panics if `pk_sender_id` is `Some`.
    fn decap(
        sk_recip: &PrivateKeyRejectNonContrib,
        pk_sender_id: Option<&PublicKey>,
        encapped_key: &EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        assert!(
            pk_sender_id.is_none(),
            "X-Wing doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        let ss = sk_recip
            .0
            .try_decapsulate(&encapped_key.0)
            .map_err(|_| HpkeError::DecapError)?;
        Ok(SharedSecret(ss))
    }

    /// Decapsulate the encapsulated key using the recipient's private key. This DOES NOT support
    /// authenticated encapsulation, i.e., `sender_id_keypair` MUST be `None`.
    ///
    /// # Panics
    /// Panics if `sender_id_keypair` is `Some`.
    fn encap_with_rng(
        pk_recip: &PublicKey,
        sender_id_keypair: Option<(&PrivateKeyRejectNonContrib, &PublicKey)>,
        csprng: &mut impl CryptoRng,
    ) -> Result<(SharedSecret<Self>, EncappedKey), HpkeError> {
        assert!(
            sender_id_keypair.is_none(),
            "X-Wing doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        XWing::encap_with_rng(pk_recip, None, csprng).map(|(ss, ek)| (SharedSecret(ss.0), ek))
    }
}

// Impl the trait necessary for known-answer tests
#[cfg(all(test, feature = "kat"))]
impl crate::kat_tests::TestableKem for XWingRejectNonContrib {
    // There is no encap-with-eph, since that only makes sense for DHKEMs
    type EphemeralKey = core::convert::Infallible;
    fn encap_with_eph(
        _pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        _sk_eph: Self::EphemeralKey,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        unimplemented!()
    }

    fn encap_det(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        randomness: &[u8],
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        assert!(
            sender_id_keypair.is_none(),
            "X-Wing does not support authenticated encapsulation"
        );
        XWing::encap_deterministic(pk_recip, randomness.try_into().unwrap())
            .map(|(ss, ek)| (SharedSecret(ss.0), ek))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let mut csprng = rand::rng();
        let (sk, pk) = XWing::gen_keypair_with_rng(&mut csprng);
        let (shared_secret, encapped_key) =
            XWing::encap_with_rng(&pk, None, &mut csprng).expect("encapsulation failed");
        let shared_secret_recipient =
            XWing::decap(&sk, None, &EncappedKey(encapped_key.0)).expect("decapsulation failed");
        assert_eq!(shared_secret.0, shared_secret_recipient.0);
    }

    #[test]
    fn test_roundtrip_reject_non_contributory() {
        let mut csprng = rand::rng();
        let (sk, pk) = XWingRejectNonContrib::gen_keypair_with_rng(&mut csprng);
        let (shared_secret, encapped_key) =
            XWingRejectNonContrib::encap_with_rng(&pk, None, &mut csprng)
                .expect("encapsulation failed");
        let shared_secret_recipient =
            XWingRejectNonContrib::decap(&sk, None, &EncappedKey(encapped_key.0))
                .expect("decapsulation failed");
        assert_eq!(shared_secret.0, shared_secret_recipient.0);
    }
}
