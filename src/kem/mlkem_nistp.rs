//! ML-KEM + NIST-P hybrid PQ KEMs
//!
//! Contains implementations of MLKEM768-P256 and MLKEM1024-P384, implemented as per
//! <https://filippo.io/hpke-pq>, which itself derives from
//! <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04>

macro_rules! impl_mlkem_nistp {
    (
        $(#[$kem_doc:meta])*,
        $mod_name:ident, $kem_struct:ident, $mlkem:ident, $curve:ident,
        $kem_label:expr, $kem_id:expr,
        $pubkey_size:ident, $ct_size:ident,
        $seed_t_len:expr, $scalar_len:expr
    ) => {
        pub mod $mod_name {
            use crate::{
                kdf::one_stage_kdf,
                kem::{KemTrait, SharedSecret},
                util::{enforce_equal_len, enforce_outbuf_len, kem_suite_id},
                Deserializable, HpkeError, Serializable,
            };

            use hybrid_array::{sizes::U32, typenum::Unsigned};
            use ml_kem::{
                kem::{Decapsulate, Kem as KemCore},
                $mlkem, Ciphertext, Encapsulate, FromSeed, Generate, KeyExport, KeySizeUser,
            };
            use rand_core::CryptoRng;
            use sha2::digest::XofReader;
            use sha3::{
                digest::{self, ExtendableOutput, FixedOutput, Update},
                Digest, Sha3_256,
            };
            use shake::Shake256;
            use subtle::{Choice, ConstantTimeEq};
            use $curve::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
            use zeroize::{Zeroize, ZeroizeOnDrop};

            const KEM_LABEL: &[u8] = $kem_label;

            /// The bytelength of an MLKEM ciphertext
            type KemCtSize = <$mlkem as KemCore>::CiphertextSize;
            /// The bytelength of an MLKEM encapsulation key
            type KemPubkeySize = <<$mlkem as KemCore>::EncapsulationKey as KeySizeUser>::KeySize;

            #[derive(Clone)]
            pub struct PrivateKey {
                seed: [u8; 32],
                // These are only pub(crate) so they can be checked in kat_tests.rs
                pub(crate) dk_pq: <$mlkem as KemCore>::DecapsulationKey,
                pub(crate) dk_t: $curve::SecretKey,
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
                // Nseed identical in
                //   <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
                // and
                //   <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.3>
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
                ek_pq: <$mlkem as KemCore>::EncapsulationKey,
                ek_t: $curve::PublicKey,
            }

            impl Serializable for PublicKey {
                type OutputSize = hybrid_array::sizes::$pubkey_size;

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

                    let ek_pq = <$mlkem as KemCore>::EncapsulationKey::new(
                        encoded_pq.try_into().expect("correct length"),
                    )
                    .map_err(|_| HpkeError::ValidationError)?;

                    let ek_t = $curve::Sec1Point::from_bytes(encoded_t)
                        .map_err(|_| HpkeError::ValidationError)?;
                    if ek_t.is_compressed() {
                        return Err(HpkeError::ValidationError);
                    }
                    let ek_t = $curve::PublicKey::from_sec1_point(&ek_t)
                        .into_option()
                        .ok_or(HpkeError::ValidationError)?;

                    Ok(Self { ek_pq, ek_t })
                }
            }

            #[derive(Clone)]
            pub struct EncappedKey {
                ct_pq: Ciphertext<$mlkem>,
                ct_t: $curve::Sec1Point,
            }

            impl Serializable for EncappedKey {
                type OutputSize = hybrid_array::sizes::$ct_size;

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

                    let ct_t = $curve::Sec1Point::from_bytes(encoded_t)
                        .map_err(|_| HpkeError::ValidationError)?;
                    if ct_t.is_compressed() {
                        return Err(HpkeError::ValidationError);
                    }

                    Ok(Self { ct_pq, ct_t })
                }
            }

            $(#[$kem_doc])*
            pub struct $kem_struct;

            impl KemTrait for $kem_struct {
                // Nss identical in
                //   <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
                // and
                //   <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
                type NSecret = U32;
                const KEM_ID: u16 = $kem_id;

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

                /// Decapsulate the encapsulated key using the recipient's private key.
                /// This DOES NOT support authenticated encapsulation, i.e.,
                /// `pk_sender_id` MUST be `None`.
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
                        concat!(
                            stringify!($kem_struct),
                            " doesn't support authenticated encapsulation. \
                             Use Base or Psk operation mode."
                        )
                    );

                    let ct_t = $curve::PublicKey::from_sec1_point(&encapped_key.ct_t)
                        .into_option()
                        .ok_or(HpkeError::DecapError)?;

                    // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.1.1>
                    //   def prepareDecapsG(ct_PQ, ct_T, dk_PQ, dk_T):
                    //       ss_PQ = KEM_PQ.Decaps(dk_PQ, ct_PQ)
                    //       ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ct_T, dk_T))
                    //       return (ss_PQ, ss_T)
                    let ss_pq = sk_recip.dk_pq.decapsulate(&encapped_key.ct_pq);
                    let ss_t = $curve::ecdh::diffie_hellman(
                        sk_recip.dk_t.to_nonzero_scalar(),
                        ct_t.as_affine(),
                    );

                    let shared_secret = combine_ss(
                        &ss_pq,
                        ss_t.raw_secret_bytes(),
                        encapped_key.ct_t.as_bytes(),
                        sk_recip.dk_t.public_key().to_sec1_point(false).as_bytes(),
                    );

                    Ok(SharedSecret(shared_secret))
                }

                /// Derives a shared secret and an ephemeral pubkey that the owner of
                /// the recipient's pubkey can use to derive the same shared secret.
                /// This DOES NOT support authenticated encapsulation, i.e.,
                /// `sender_id_keypair` MUST be `None`.
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
                        concat!(
                            stringify!($kem_struct),
                            " doesn't support authenticated encapsulation. \
                             Use Base or Psk operation mode."
                        )
                    );

                    // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.1.1>:
                    //   def prepareEncapsG(ek_PQ, ek_T):
                    //       (ss_PQ, ct_PQ) = KEM_PQ.Encaps(ek_PQ)
                    //       sk_E = Group_T.RandomScalar(random(Group_T.Nseed))
                    //       ct_T = Group_T.Exp(Group_T.g, sk_E)
                    //       ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ek_T, sk_E))
                    //       return (ss_PQ, ss_T, ct_PQ, ct_T)
                    let (ct_pq, ss_pq) = pk_recip.ek_pq.encapsulate_with_rng(csprng);
                    let sk_e = $curve::ecdh::EphemeralSecret::generate_from_rng(csprng);
                    let ct_t = sk_e.public_key().to_sec1_point(false);
                    let ss_t = sk_e.diffie_hellman(&pk_recip.ek_t);

                    let shared_secret = combine_ss(
                        &ss_pq,
                        ss_t.raw_secret_bytes(),
                        ct_t.as_bytes(),
                        pk_recip.ek_t.to_sec1_point(false).as_bytes(),
                    );

                    Ok((SharedSecret(shared_secret), EncappedKey { ct_pq, ct_t }))
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
                <$mlkem as KemCore>::EncapsulationKey,
                $curve::PublicKey,
                <$mlkem as KemCore>::DecapsulationKey,
                $curve::SecretKey,
            ) {
                // NSeed=64 from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-3.2.1>
                let mut seed_pq = [0; 64];
                let mut seed_t = [0; $seed_t_len];

                // PRG=SHAKE-256 from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
                // and <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.3>
                let mut xof = Shake256::default().chain(seed).finalize_xof();
                xof.read(&mut seed_pq);
                xof.read(&mut seed_t);

                let mut seed_pq_arr = seed_pq.into();
                let (dk_pq, ek_pq) = $mlkem::from_seed(&seed_pq_arr);
                seed_pq_arr[..].zeroize();
                let dk_t = random_scalar(&seed_t);
                let ek_t = dk_t.public_key();

                seed_pq.zeroize();
                seed_t.zeroize();

                (ek_pq, ek_t, dk_pq, dk_t)
            }

            /// Rejection-sample a random scalar
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
            fn random_scalar(seed: &[u8; $seed_t_len]) -> $curve::SecretKey {
                for sk in seed.chunks_exact($scalar_len) {
                    // from_bytes() errors when the input exceeds the modulus
                    if let Ok(sk) =
                        $curve::SecretKey::from_bytes(sk.try_into().expect("correct length"))
                    {
                        return sk;
                    }
                }

                // As noted in the spec, this happens with neglibile probability
                panic!("Rejection sampling failed");
            }

            /// Computes the final shared secret given the PQ shared secret, DH shared
            /// secret, DH key share, and PQ encapsulation key.
            // From <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-11.html#section-5.1.3>:
            //   def C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, label):
            //       return KDF(concat(ss_PQ, ss_T, ct_T, ek_T, label))
            fn combine_ss(
                ss_pq: &[u8],
                ss_t: &[u8],
                ct_t: &[u8],
                ek_t: &[u8],
            ) -> digest::Output<Sha3_256> {
                // SHA3-256 KDF from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
                // and <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.3>
                Sha3_256::default()
                    .chain_update(ss_pq)
                    .chain_update(ss_t)
                    .chain_update(ct_t)
                    .chain_update(ek_t)
                    .chain_update(KEM_LABEL)
                    .finalize_fixed()
            }

            #[cfg(all(test, feature = "kat"))]
            impl crate::kat_tests::TestableKem for $kem_struct {
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
                        concat!(
                            stringify!($kem_struct),
                            " doesn't support authenticated encapsulation. \
                             Use Base or Psk operation mode."
                        )
                    );

                    $kem_struct::encap_with_rng(
                        pk_recip,
                        sender_id_keypair,
                        &mut crate::test_util::FakeCsprng::new(randomness),
                    )
                }
            }

            #[cfg(test)]
            mod tests {
                use super::$kem_struct;
                use crate::Kem as KemTrait;

                /// Tests that encap and decap produce the same shared secret
                #[test]
                fn round_trip() {
                    let mut csprng = rand::rng();

                    let (sk_recip, pk_recip) = $kem_struct::gen_keypair_with_rng(&mut csprng);

                    let (shared_secret, encapped_key) =
                        $kem_struct::encap_with_rng(&pk_recip, None, &mut csprng)
                            .expect("encapsulation failed");
                    let shared_secret_recipient =
                        $kem_struct::decap(&sk_recip, None, &encapped_key)
                            .expect("decapsulation failed");

                    assert_eq!(shared_secret.0, shared_secret_recipient.0);
                }

                /// Tests that a serialize-deserialize round trip on an encapped key
                /// is the identity
                #[test]
                fn encapped_serialize() {
                    use crate::{Deserializable, Serializable};

                    let mut csprng = rand::rng();
                    let (_, pk_recip) = $kem_struct::gen_keypair_with_rng(&mut csprng);
                    let encapped_key = $kem_struct::encap_with_rng(&pk_recip, None, &mut csprng)
                        .unwrap()
                        .1;

                    let encapped_key_bytes = encapped_key.to_bytes();
                    let new_encapped_key =
                        <<$kem_struct as KemTrait>::EncappedKey as Deserializable>::from_bytes(
                            &encapped_key_bytes,
                        )
                        .unwrap();

                    assert_eq!(
                        new_encapped_key.to_bytes(),
                        encapped_key.to_bytes(),
                        "encapped key doesn't serialize correctly"
                    );
                }
            }
        }
    };
}

// Implement the hybrid KEMs
//
// kem_label, pubkey_size, and ct_size are from
//   <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1>
// and
//   <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.3>
// kem_id from <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#table-3>
// seed_t_len from <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-3.1.1>

// The cfgs here are redundant. We keep them bc it makes the docs show the feature gates properly

#[cfg(all(feature = "mlkem", feature = "nistp"))]
impl_mlkem_nistp!(
    #[doc = "ML-KEM 768 + P256 hybrid post-quantum KEM"],
    mlkem768p256, // mod_name
    MlKem768P256,     // kem_struct
    MlKem768,         // mlkem
    p256,             // curve
    b"MLKEM768-P256", // kem_label
    0x0050,           // kem_id
    U1249,            // pubkey_size
    U1153,            // ct_size
    128,              // seed_t_len
    32                // scalar_len
);

#[cfg(all(feature = "mlkem", feature = "nistp"))]
impl_mlkem_nistp!(
    #[doc = "ML-KEM 1024 + P384 hybrid post-quantum KEM"],
    mlkem1024p384,     // mod_name
    MlKem1024P384,     // kem_struct
    MlKem1024,         // mlkem
    p384,              // curve
    b"MLKEM1024-P384", // kem_label
    0x0051,            // kem_id
    U1665,             // pubkey_size
    U1665,             // ct_size
    48,                // seed_t_len
    48                 // scalar_len
);
