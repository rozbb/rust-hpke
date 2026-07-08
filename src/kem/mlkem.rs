//! Pure ML-KEM-768 and ML-KEM-1024 KEMs
//!
//! Implemented as per
//! <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04> §3.

/// Parameters:
/// - `$mod_name` - the name of the module we will put this KEM implementation in
/// - `$kem` - the name of the KEM struct to define (e.g. `MlKem768`)
/// - `$param` - the `ml_kem` parameter set type (e.g. `MlKem768Params`)
/// - `$kem_id` - the HPKE KEM identifier from draft-ietf-hpke-pq-04 §3
/// - `$name` - a string literal used in assertion messages (e.g. `"ML-KEM-768"`)
///
/// Wire sizes (`Nenc`, `Npk`, `Nsk`) are derived automatically from the `ml_kem` type-level
/// constants (`CiphertextSize`, `KeySize`, etc.) rather than being supplied as macro arguments.
macro_rules! define_mlkem {
    (
        $(#[$kem_doc:meta])*,
        $mod_name:ident,
        $kem:ident,
        $param:ty,
        $kem_id:expr,
    ) => {
        pub mod $mod_name {
            use crate::{
                kdf::one_stage_kdf::labeled_derive,
                kem::{KemTrait, SharedSecret},
                util::{enforce_equal_len, enforce_outbuf_len, kem_suite_id},
                Deserializable, HpkeError, Serializable,
            };

            use hybrid_array::typenum::{Unsigned, U32, U64};
            use ml_kem::{
                kem::{Decapsulate, Encapsulate, Kem as KemCore},
                Ciphertext, DecapsulationKey, EncapsulationKey, FromSeed, KeyExport, KeySizeUser,
            };
            use rand_core::CryptoRng;
            use shake::Shake256;
            use subtle::{Choice, ConstantTimeEq};
            use zeroize::{Zeroize, ZeroizeOnDrop};


            /// An ML-KEM private key
            #[derive(Clone)]
            pub struct PrivateKey(DecapsulationKey<$param>);

            // DecapsulationKey handles zeroize-on-drop internally
            impl ZeroizeOnDrop for PrivateKey {}

            impl ConstantTimeEq for PrivateKey {
                fn ct_eq(&self, other: &Self) -> Choice {
                    // We can unwrap because every PrivateKey is initialized with `from_seed`
                    let self_seed: [u8; 64] = self.0.to_seed().unwrap().into();
                    let other_seed: [u8; 64] = other.0.to_seed().unwrap().into();
                    self_seed.ct_eq(&other_seed)
                }
            }

            impl PartialEq for PrivateKey {
                fn eq(&self, other: &Self) -> bool {
                    self.ct_eq(other).into()
                }
            }
            impl Eq for PrivateKey {}

            impl Serializable for PrivateKey {
                // Nsk = 64 per <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#table-2>
                type OutputSize = U64;

                fn write_exact(&self, buf: &mut [u8]) {
                    // Check the length is correct and panic if not
                    enforce_outbuf_len::<Self>(buf);
                    // We can unwrap because every PrivateKey is initialized with `from_seed`
                    buf.copy_from_slice(&self.0.to_seed().unwrap());
                }
            }

            impl Deserializable for PrivateKey {
                fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                    let mut seed: [u8; 64] = encoded.try_into().map_err(|_| {
                        HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
                    })?;
                    let mut seed_arr = seed.into();
                    let (dk, _) = <$param as FromSeed>::from_seed(&seed_arr);
                    seed_arr[..].zeroize();
                    seed.zeroize();
                    Ok(Self(dk))
                }
            }

            /// An ML-KEM public key, i.e., an ML-KEM encapsulation key.
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct PublicKey(EncapsulationKey<$param>);

            impl Serializable for PublicKey {
                // Npk per <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#table-2>
                type OutputSize = <EncapsulationKey<$param> as KeySizeUser>::KeySize;

                fn write_exact(&self, buf: &mut [u8]) {
                    // Check the length is correct and panic if not
                    enforce_outbuf_len::<Self>(buf);
                    // Serialize is identity over the fixed-length encapsulation key
                    buf.copy_from_slice(&self.0.to_bytes());
                }
            }

            impl Deserializable for PublicKey {
                fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                    // Check the input buf length is correct and error if not
                    enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;
                    // Infallible because of the check above
                    let ek = EncapsulationKey::<$param>::new(encoded.try_into().unwrap())
                        .map_err(|_| HpkeError::ValidationError)?;
                    Ok(PublicKey(ek))
                }
            }

            /// An ML-KEM encapsulated key (a.k.a. ciphertext)
            #[derive(Clone)]
            pub struct EncappedKey(Ciphertext<$param>);

            impl Serializable for EncappedKey {
                // Nenc per <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#table-2>
                type OutputSize = <$param as KemCore>::CiphertextSize;

                fn write_exact(&self, buf: &mut [u8]) {
                    // Check the length is correct and panic if not
                    enforce_outbuf_len::<Self>(buf);
                    // Serialize is identity over the fixed-length ciphertext
                    buf.copy_from_slice(&self.0);
                }
            }

            impl Deserializable for EncappedKey {
                fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                    // Check the input buf length is correct and error if not
                    enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;
                    // Infallible because of the check above
                    let ct = Ciphertext::<$param>::try_from(encoded).expect("correct length");
                    Ok(EncappedKey(ct))
                }
            }

            $(#[$kem_doc])*
            pub struct $kem;

            impl KemTrait for $kem {
                // Nsecret = 32 per
                // <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#table-2>. The HPKE
                // shared secret is just the ML-KEM shared secret
                type NSecret = U32;
                const KEM_ID: u16 = $kem_id;

                type PublicKey = PublicKey;
                type PrivateKey = PrivateKey;
                type EncappedKey = EncappedKey;

                fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
                    PublicKey(sk.0.encapsulation_key().clone())
                }

                // From <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#section-3-3>
                //   def DeriveKeyPair(ikm):
                //     dk = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 64)
                //     (_expanded_dk, ek) = expandDecapsKey(dk)
                //     return (dk, ek)
                fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
                    let mut seed = [0u8; 64];
                    let suite_id = kem_suite_id::<Self>();
                    labeled_derive::<Shake256>(
                        &suite_id,
                        &[ikm],
                        b"DeriveKeyPair",
                        &[b""],
                        &mut seed,
                    );

                    let mut seed_arr = seed.into();
                    let (dk, ek) = <$param as FromSeed>::from_seed(&seed_arr);
                    seed_arr[..].zeroize();
                    seed.zeroize();

                    (PrivateKey(dk), PublicKey(ek))
                }

                /// Decapsulate the encapsulated key using the recipient's private key. This DOES
                /// NOT support authenticated encapsulation, i.e., `pk_sender_id` MUST be `None`.
                ///
                /// # Panics
                /// Panics if `pk_sender_id` is `Some`.
                // From <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#section-3-11>:
                //   def Decap(enc, skR):
                //     (expanded_dk, _ek) = expandDecapsKey(skR)
                //     return ML-KEM.Decaps(expanded_dk, enc)
                fn decap(
                    sk_recip: &Self::PrivateKey,
                    pk_sender_id: Option<&Self::PublicKey>,
                    encapped_key: &Self::EncappedKey,
                ) -> Result<SharedSecret<Self>, HpkeError> {
                    assert!(
                        pk_sender_id.is_none(),
                        concat!(
                            stringify!($kem),
                            " doesn't support authenticated encapsulation. \
                            Use Base or Psk operation mode."
                        )
                    );

                    let ss = sk_recip.0.decapsulate(&encapped_key.0);
                    Ok(SharedSecret(ss))
                }

                /// Derives a shared secret and an ephemeral pubkey that the owner of the
                /// recipient's pubkey can use to derive the same shared secret. This DOES NOT
                /// support authenticated encapsulation, i.e., `sender_id_keypair` MUST be `None`.
                ///
                /// # Panics
                /// Panics if `sender_id_keypair` is `Some`.
                // From <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#section-3-9>:
                //   The Encap function corresponds to the function ML-KEM.Encaps in [FIPS203],
                //   where an ML-KEM encapsulation key check failure causes an HPKE EncapError.
                fn encap_with_rng(
                    pk_recip: &Self::PublicKey,
                    sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
                    csprng: &mut impl CryptoRng,
                ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
                    assert!(
                        sender_id_keypair.is_none(),
                        concat!(
                            stringify!($kem),
                            " doesn't support authenticated encapsulation. \
                            Use Base or Psk operation mode."
                        )
                    );

                    let (ct, ss) = pk_recip.0.encapsulate_with_rng(csprng);
                    Ok((SharedSecret(ss), EncappedKey(ct)))
                }
            }

            // Impl the trait necessary for known-answer tests
            #[cfg(all(test, feature = "kat"))]
            impl crate::kat_tests::TestableKem for $kem {
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
                        concat!(stringify!(kem), " doesn't support authenticated encapsulation")
                    );

                    $kem::encap_with_rng(
                        pk_recip,
                        sender_id_keypair,
                        &mut crate::test_util::FakeCsprng::new(randomness),
                    )
                }
            }
        }
    };
}

// kem_id is from <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#table-2>

define_mlkem!(
    #[doc = "ML-KEM 768 post-quantum KEM"],
    mlkem768,         // mod_name
    MlKem768,         // kem
    ml_kem::MlKem768, // param
    0x0041,           // kem_id
);

define_mlkem!(
    #[doc = "ML-KEM 1024 post-quantum KEM"],
    mlkem1024,         // mod_name
    MlKem1024,         // kem
    ml_kem::MlKem1024, // param
    0x0042,            // kem_id
);

#[cfg(test)]
mod tests {
    use super::mlkem768::MlKem768;
    use super::mlkem1024::MlKem1024;
    use crate::{Deserializable, Kem as KemTrait, Serializable};

    macro_rules! test_encap_correctness {
        ($test_name:ident, $kem_ty:ty) => {
            /// Tests that encap and decap produce the same shared secret when composed
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let mut csprng = rand::rng();
                let (sk_recip, pk_recip) = Kem::gen_keypair_with_rng(&mut csprng);

                let (shared_secret, encapped_key) =
                    Kem::encap_with_rng(&pk_recip, None, &mut csprng)
                        .expect("encapsulation failed");
                let decapped_shared_secret =
                    Kem::decap(&sk_recip, None, &encapped_key).expect("decapsulation failed");

                assert_eq!(shared_secret.0, decapped_shared_secret.0);
            }
        };
    }

    macro_rules! test_encapped_serialize {
        ($test_name:ident, $kem_ty:ty) => {
            /// Tests that a serialize-deserialize round trip on an encapped key is the identity
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let mut csprng = rand::rng();
                let (_, pk_recip) = Kem::gen_keypair_with_rng(&mut csprng);
                let encapped_key = Kem::encap_with_rng(&pk_recip, None, &mut csprng).unwrap().1;

                let encapped_key_bytes = encapped_key.to_bytes();
                let new_encapped_key =
                    <<Kem as KemTrait>::EncappedKey as Deserializable>::from_bytes(
                        &encapped_key_bytes,
                    )
                    .unwrap();

                assert_eq!(
                    new_encapped_key.to_bytes(),
                    encapped_key.to_bytes(),
                    "encapped key doesn't serialize correctly"
                );
            }
        };
    }

    test_encap_correctness!(test_encap_correctness_mlkem768, MlKem768);
    test_encap_correctness!(test_encap_correctness_mlkem1024, MlKem1024);
    test_encapped_serialize!(test_encapped_serialize_mlkem768, MlKem768);
    test_encapped_serialize!(test_encapped_serialize_mlkem1024, MlKem1024);

    /// Tests that the wire sizes match the constants in <https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html#table-2>
    #[test]
    fn sizes_match_spec_mlkem768() {
        // ML-KEM-768: KEM_ID=0x0041, Nsecret=32, Nenc=1088, Npk=1184, Nsk=64
        assert_eq!(MlKem768::KEM_ID, 0x0041);
        assert_eq!(<MlKem768 as KemTrait>::PrivateKey::size(), 64);
        assert_eq!(<MlKem768 as KemTrait>::PublicKey::size(), 1184);
        assert_eq!(<MlKem768 as KemTrait>::EncappedKey::size(), 1088);
    }

    /// Tests that the wire sizes match the constants in draft-ietf-hpke-pq-04 §3
    #[test]
    fn sizes_match_spec_mlkem1024() {
        // ML-KEM-1024: KEM_ID=0x0042, Nsecret=32, Nenc=1568, Npk=1568, Nsk=64
        assert_eq!(MlKem1024::KEM_ID, 0x0042);
        assert_eq!(<MlKem1024 as KemTrait>::PrivateKey::size(), 64);
        assert_eq!(<MlKem1024 as KemTrait>::PublicKey::size(), 1568);
        assert_eq!(<MlKem1024 as KemTrait>::EncappedKey::size(), 1568);
    }

    /// Tests that DeriveKeyPair is deterministic and that derived keypairs round-trip
    #[test]
    fn derive_keypair_roundtrip() {
        let ikm = [7u8; 64];
        let (sk_a, pk_a) = MlKem768::derive_keypair(&ikm);
        let (sk_b, pk_b) = MlKem768::derive_keypair(&ikm);
        assert_eq!(sk_a.to_bytes(), sk_b.to_bytes());
        assert_eq!(pk_a.to_bytes(), pk_b.to_bytes());
        // sk_to_pk agrees with the derived public key
        assert_eq!(MlKem768::sk_to_pk(&sk_a).to_bytes(), pk_a.to_bytes());

        let mut csprng = rand::rng();
        let (ss, enc) = MlKem768::encap_with_rng(&pk_a, None, &mut csprng).unwrap();
        let ss_recip = MlKem768::decap(&sk_a, None, &enc).unwrap();
        assert_eq!(ss.0, ss_recip.0);
    }
}
