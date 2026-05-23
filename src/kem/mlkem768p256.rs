//! The MLKEM768-P256 hybrid PQ KEM. Implemented as per <https://filippo.io/hpke-pq>,
//! which itself derives from <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04>

use crate::{
    kdf::one_stage_kdf,
    kem::{KemTrait, SharedSecret},
    util::{enforce_equal_len, enforce_outbuf_len, kem_suite_id},
    Deserializable, HpkeError, Serializable,
};

use hybrid_array::{
    sizes::{U1153, U1249, U32},
    typenum::Unsigned,
};
use ml_kem::{
    kem::{Decapsulate, Kem as KemCore},
    Ciphertext, Encapsulate, FromSeed, Generate, KeyExport, KeySizeUser, MlKem768,
};
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use rand_core::CryptoRng;
use sha2::digest::XofReader;
use sha3::{
    digest::{self, ExtendableOutput, FixedOutput, Update},
    Digest, Sha3_256, Shake256,
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Label from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
const KEM_LABEL: &[u8] = b"MLKEM768-P256";

/// The bytelength of an MLKEM ciphertext
type KemCtSize = <MlKem768 as KemCore>::CiphertextSize;
/// The bytelength of an MLKEM encapsulation key
type KemPubkeySize = <<MlKem768 as KemCore>::EncapsulationKey as KeySizeUser>::KeySize;

#[derive(Clone)]
pub struct PrivateKey {
    seed: [u8; 32],
    // These are only pub(crate) so they can be checked in kat_tests.rs
    pub(crate) dk_pq: <MlKem768 as KemCore>::DecapsulationKey,
    pub(crate) dk_t: p256::SecretKey,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.seed.zeroize();
        // dk_pq and dk_t both zeroize themselves on drop
    }
}
impl ZeroizeOnDrop for PrivateKey {}

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.seed.ct_eq(&other.seed)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for PrivateKey {}

impl Serializable for PrivateKey {
    // Nseed from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
    type OutputSize = U32;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.5>:
        //   def DeriveKeyPair(seed):
        //       // ...
        //       return (seed, concat(ek_PQ, ek_T))
        buf.copy_from_slice(&self.seed);
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let seed = encoded.try_into().map_err(|_| {
            HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        let (_, _, dk_pq, dk_t) = expand_key(&seed);
        Ok(Self { seed, dk_pq, dk_t })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    ek_pq: <MlKem768 as KemCore>::EncapsulationKey,
    ek_t: p256::PublicKey,
}

impl Serializable for PublicKey {
    // Nek from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
    type OutputSize = U1249;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.5>:
        //   def DeriveKeyPair(seed):
        //       (ek_PQ, ek_T, dk_PQ, dk_T) = expandDecapsKeyG(seed)
        //       return (seed, concat(ek_PQ, ek_T))
        let kem_neq = KemPubkeySize::to_usize();
        buf[..kem_neq].copy_from_slice(&self.ek_pq.to_bytes());
        buf[kem_neq..].copy_from_slice(self.ek_t.to_sec1_point(false).as_bytes());
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Check the input buf length is correct and error if not
        enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;
        // Infallible because of the check above
        let (encoded_pq, encoded_t) = encoded.split_at(KemPubkeySize::to_usize());

        let ek_pq = <MlKem768 as KemCore>::EncapsulationKey::new(
            encoded_pq.try_into().expect("correct length"),
        )
        .map_err(|_| HpkeError::ValidationError)?;

        let ek_t =
            p256::Sec1Point::from_bytes(encoded_t).map_err(|_| HpkeError::ValidationError)?;
        if ek_t.is_compressed() {
            // Should be impossible that the point is both 65 bytes and compressed, but we
            // check anyway
            return Err(HpkeError::ValidationError);
        }
        let ek_t = p256::PublicKey::from_sec1_point(&ek_t)
            .into_option()
            .ok_or(HpkeError::ValidationError)?;

        Ok(Self { ek_pq, ek_t })
    }
}

#[derive(Clone)]
pub struct EncappedKey {
    ct_pq: Ciphertext<MlKem768>,
    ct_t: p256::Sec1Point,
}

impl Serializable for EncappedKey {
    // Nct from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
    type OutputSize = U1153;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.5>:
        //   def Encaps(ek):
        //       // ...
        //       ct_H = concat(ct_PQ, ct_T)
        //       return (ss_H, ct_H)
        let kem_nct = KemCtSize::to_usize();
        buf[..kem_nct].copy_from_slice(&self.ct_pq.0);
        buf[kem_nct..].copy_from_slice(self.ct_t.as_bytes());
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Check the input buf length is correct and error if not
        enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;
        // Infallible because of the check above
        let (encoded_pq, encoded_t) = encoded.split_at(KemCtSize::to_usize());

        let ct_pq = <[u8; KemCtSize::USIZE]>::try_from(encoded_pq)
            .expect("correct length")
            .into();

        let ct_t =
            p256::Sec1Point::from_bytes(encoded_t).map_err(|_| HpkeError::ValidationError)?;
        if ct_t.is_compressed() {
            // Should be impossible that the point is both 65 bytes and compressed, but we
            // check anyway
            return Err(HpkeError::ValidationError);
        }

        Ok(Self { ct_pq, ct_t })
    }
}

/// Represents the MLKEM768-P256 hybrid post-quantum KEM.
pub struct MlKem768P256;

impl KemTrait for MlKem768P256 {
    // Nss from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
    type NSecret = U32;
    // Value from <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#table-3>
    const KEM_ID: u16 = 0x0050;

    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey {
            ek_pq: sk.dk_pq.encapsulation_key().clone(),
            ek_t: sk.dk_t.public_key(),
        }
    }

    // From <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#section-4-5>:
    //   def DeriveKeyPair(ikm):
    //      seed = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32)
    //      return KEM.DeriveKeyPair(seed)
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let seed = {
            let mut buf = [0u8; 32];
            let suite_id = kem_suite_id::<Self>();
            one_stage_kdf::labeled_derive::<Shake256>(
                &suite_id,
                &[ikm],
                b"DeriveKeyPair",
                &[b""],
                &mut buf,
            );
            buf
        };

        // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.5>:
        //   def DeriveKeyPair(seed):
        //       (ek_PQ, ek_T, dk_PQ, dk_T) = expandDecapsKeyG(seed)
        //       return (seed, concat(ek_PQ, ek_T))
        let (ek_pq, ek_t, dk_pq, dk_t) = expand_key(&seed);
        (PrivateKey { seed, dk_pq, dk_t }, PublicKey { ek_pq, ek_t })
    }

    /// Decapsulate the encapsulated key using the recipient's private key. This DOES NOT support
    /// authenticated encapsulation, i.e., `pk_sender_id` MUST be `None`.
    ///
    /// # Panics
    /// Panics if `pk_sender_id` is `Some`.
    // From  <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.5>:
    //   def Decaps(dk, ct):
    //       (ct_PQ, ct_T) = split(KEM_PQ.Nct, Group_T.Nelem, ct)
    //       (ek_PQ, ek_T, dk_PQ, dk_T) = expandDecapsKeyG(dk)
    //       (ss_PQ, ss_T) = prepareDecapsG(ct_PQ, ct_T, dk_PQ, dk_T)
    //       ss_H = C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, Label)
    //       return ss_H
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        assert!(
            pk_sender_id.is_none(),
            "MLKEM768-P256 doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        let ct_t = p256::PublicKey::from_sec1_point(&encapped_key.ct_t)
            .into_option()
            .ok_or(HpkeError::DecapError)?;

        // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.1.1>
        //   def prepareDecapsG(ct_PQ, ct_T, dk_PQ, dk_T):
        //       ss_PQ = KEM_PQ.Decaps(dk_PQ, ct_PQ)
        //       ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ct_T, dk_T))
        //       return (ss_PQ, ss_T)
        let ss_pq = sk_recip.dk_pq.decapsulate(&encapped_key.ct_pq);
        let ss_t = p256::ecdh::diffie_hellman(sk_recip.dk_t.to_nonzero_scalar(), ct_t.as_affine());

        let ss = ss(
            &ss_pq,
            ss_t.raw_secret_bytes(),
            encapped_key.ct_t.as_bytes(),
            sk_recip.dk_t.public_key().to_sec1_point(false).as_bytes(),
        );

        Ok(SharedSecret(ss))
    }

    /// Derives a shared secret and an ephemeral pubkey that the owner of the recipient's pubkey
    /// can use to derive the same shared secret.This DOES NOT support authenticated encapsulation,
    /// i.e., `sender_id_keypair` MUST be `None`.
    ///
    /// # Panics
    /// Panics if `sender_id_keypair` is `Some`.
    // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.5>:
    //   def Encaps(ek):
    //       (ek_PQ, ek_T) = split(KEM_PQ.Nek, Group_T.Nelem, ek)
    //       (ss_PQ, ss_T, ct_PQ, ct_T) = prepareEncapsG(ek_PQ, ek_T)
    //       ss_H = C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, Label)
    //       ct_H = concat(ct_PQ, ct_T)
    //       return (ss_H, ct_H)
    fn encap_with_rng(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut impl CryptoRng,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        assert!(
            sender_id_keypair.is_none(),
            "MLKEM768-P256 doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.1.1>:
        //   def prepareEncapsG(ek_PQ, ek_T):
        //       (ss_PQ, ct_PQ) = KEM_PQ.Encaps(ek_PQ)
        //       sk_E = Group_T.RandomScalar(random(Group_T.Nseed))
        //       ct_T = Group_T.Exp(Group_T.g, sk_E)
        //       ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ek_T, sk_E))
        //       return (ss_PQ, ss_T, ct_PQ, ct_T)
        let (ct_pq, ss_pq) = pk_recip.ek_pq.encapsulate_with_rng(csprng);
        let sk_e = p256::ecdh::EphemeralSecret::generate_from_rng(csprng);
        let ct_t = sk_e.public_key().to_sec1_point(false);
        let ss_t = sk_e.diffie_hellman(&pk_recip.ek_t);

        let ss = ss(
            &ss_pq,
            ss_t.raw_secret_bytes(),
            ct_t.as_bytes(),
            pk_recip.ek_t.to_sec1_point(false).as_bytes(),
        );

        Ok((SharedSecret(ss), EncappedKey { ct_pq, ct_t }))
    }
}

// From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.1.2-2>:
//   def expandDecapsKeyG(seed):
//       seed_full = PRG(seed)
//       (seed_PQ, seed_T) = split(KEM_PQ.Nseed, Group_T.Nseed, seed_full)
//
//       (dk_PQ, ek_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
//       dk_T = Group_T.RandomScalar(seed_T)
//       ek_T = Group_T.Exp(Group_T.g, dk_T)
//
//       return (ek_PQ, ek_T, dk_PQ, dk_T)
fn expand_key(
    seed: &[u8; 32],
) -> (
    <MlKem768 as KemCore>::EncapsulationKey,
    p256::PublicKey,
    <MlKem768 as KemCore>::DecapsulationKey,
    p256::SecretKey,
) {
    // NSeed=64 from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-3.2.1>
    let mut seed_pq = [0; 64];
    // NSeed=128 from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-3.1.1>
    let mut seed_t = [0; 128];

    // PRG=SHAKE-256 from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.2>
    let mut xof = Shake256::default().chain(seed).finalize_xof();
    xof.read(&mut seed_pq);
    xof.read(&mut seed_t);

    let (dk_pq, ek_pq) = MlKem768::from_seed(&seed_pq.into());
    let dk_t = p256_random_scalar(&seed_t);
    let ek_t = dk_t.public_key();

    seed_pq.zeroize();
    seed_t.zeroize();

    (ek_pq, ek_t, dk_pq, dk_t)
}

/// Rejection-sample a random P256 scalar
// From <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-3.1.1>
//   def RandomScalar(seed):
//     start = 0
//     end = Nscalar
//     sk = OS2IP(seed[start : end])
//
//     while sk == 0 || sk >= order:
//       start = end
//       end = end + Nscalar
//       if end > len(seed):
//           raise Exception("Rejection sampling failed")
//       sk = OS2IP(seed[start : end])
//     return sk
fn p256_random_scalar(seed: &[u8; 128]) -> p256::SecretKey {
    for sk in seed.chunks_exact(32) {
        // from_bytes() errors when the input exceeds the modulus
        if let Ok(sk) = p256::SecretKey::from_bytes(sk.try_into().expect("correct length")) {
            return sk;
        }
    }

    // This happens with cryptographically negligible probability. The chance of a single
    // rejection is < 2⁻³² for P-256. The chance of reaching this is thus < 2⁻¹²⁸ for
    // P-256.
    panic!("Rejection sampling failed");
}

/// Computes the final shared secret given the PQ shared secret, DH shared secret, DH key
/// share, and PQ encapsulation key.
// From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.1.3>:
//   def C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, label):
//       return KDF(concat(ss_PQ, ss_T, ct_T, ek_T, label))
fn ss(ss_pq: &[u8], ss_t: &[u8], ct_t: &[u8], ek_t: &[u8]) -> digest::Output<Sha3_256> {
    // SHA3-256 KDF from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
    Sha3_256::default()
        .chain_update(ss_pq)
        .chain_update(ss_t)
        .chain_update(ct_t)
        .chain_update(ek_t)
        .chain_update(KEM_LABEL)
        .finalize_fixed()
}

#[cfg(all(test, feature = "kat"))]
impl crate::kat_tests::TestableKem for MlKem768P256 {
    // There is no encap-with-eph, since that only makes sense for DHKEMs
    type EphemeralKey = core::convert::Infallible;
    fn encap_with_eph(
        _pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&PrivateKey, &PublicKey)>,
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
            "MLKEM768-P256 doesn't support authenticated encapsulation. Use Base or Psk operation mode."
        );

        use rand_core::{TryCryptoRng, TryRng};
        struct FakeCsprng<'a> {
            randomness: &'a [u8],
        }
        impl<'a> TryRng for FakeCsprng<'a> {
            type Error = core::convert::Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                rand_core::utils::next_word_via_fill(self)
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                rand_core::utils::next_word_via_fill(self)
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                if dest.len() > self.randomness.len() {
                    unreachable!("ran out of randomness")
                } else {
                    let (taken, rest) = self.randomness.split_at(dest.len());
                    dest.copy_from_slice(taken);
                    self.randomness = rest;
                    Ok(())
                }
            }
        }
        impl<'a> TryCryptoRng for FakeCsprng<'a> {}

        MlKem768P256::encap_with_rng(pk_recip, sender_id_keypair, &mut FakeCsprng { randomness })
    }
}

#[cfg(test)]
mod tests {
    use super::MlKem768P256;
    use crate::Kem as KemTrait;

    #[test]
    fn round_trip() {
        let mut csprng = rand::rng();

        let (sk_recip, pk_recip) = MlKem768P256::gen_keypair_with_rng(&mut csprng);

        let (shared_secret, encapped_key) =
            MlKem768P256::encap_with_rng(&pk_recip, None, &mut csprng)
                .expect("encapsulation failed");
        let shared_secret_recipient =
            MlKem768P256::decap(&sk_recip, None, &encapped_key).expect("decapsulation failed");

        assert_eq!(shared_secret.0, shared_secret_recipient.0);
    }
}
