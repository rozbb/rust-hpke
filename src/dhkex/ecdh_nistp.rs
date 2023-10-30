// We define all the NIST P- curve ECDH functionalities in one macro
macro_rules! nistp_dhkex {
    (
        $curve_name:expr,
        $dh_name:ident,
        $curve:ident,
        $pubkey_size:ty,
        $privkey_size:ty,
        $ss_size:ty,
        $keygen_bitmask:expr
    ) => {
        pub(crate) mod $curve {
            use super::*;

            use crate::{
                dhkex::{DhError, DhKeyExchange},
                kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
                util::{enforce_equal_len, enforce_outbuf_len, KemSuiteId},
                Deserializable, HpkeError, Serializable,
            };

            use ::$curve as curve_crate;
            use curve_crate::elliptic_curve::{ecdh::diffie_hellman, sec1::ToEncodedPoint};
            use generic_array::{typenum::Unsigned, GenericArray};
            use subtle::{Choice, ConstantTimeEq};

            #[doc = concat!(
                "An ECDH ",
                $curve_name,
                " public key. This is never the point at infinity."
            )]
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct PublicKey(curve_crate::PublicKey);

            // This is only ever constructed via its Deserializable::from_bytes, which checks for
            // the 0 value. Also, the underlying type is zeroize-on-drop.
            #[doc = concat!(
                "An ECDH ",
                $curve_name,
                " private key. This is a scalar in the range `[1,p)` where `p` is the group order."
            )]
            #[derive(Clone, Eq, PartialEq)]
            pub struct PrivateKey(curve_crate::SecretKey);

            impl ConstantTimeEq for PrivateKey {
                fn ct_eq(&self, other: &Self) -> Choice {
                    self.0.ct_eq(&other.0)
                }
            }

            // The underlying type is zeroize-on-drop
            /// A bare DH computation result
            pub struct KexResult(curve_crate::ecdh::SharedSecret);

            // Everything is serialized and deserialized in uncompressed form
            impl Serializable for PublicKey {
                type OutputSize = $pubkey_size;

                fn write_exact(&self, buf: &mut [u8]) {
                    // Check the length is correct and panic if not
                    enforce_outbuf_len::<Self>(buf);

                    // Get the uncompressed pubkey encoding
                    let encoded = self.0.as_affine().to_encoded_point(false);
                    // Serialize it
                    buf.copy_from_slice(encoded.as_bytes());
                }

            }

            // Everything is serialized and deserialized in uncompressed form
            impl Deserializable for PublicKey {
                fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                    // In order to parse as an uncompressed curve point, we first make sure the
                    // input length is correct. This ensures we're receiving the uncompressed
                    // representation.
                    enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

                    // Now just deserialize. The non-identity invariant is preserved because
                    // PublicKey::from_sec1_bytes() will error if it receives the point at
                    // infinity. This is because its submethod, PublicKey::from_encoded_point(),
                    // does this check explicitly.
                    let parsed = curve_crate::PublicKey::from_sec1_bytes(encoded)
                        .map_err(|_| HpkeError::ValidationError)?;
                    Ok(PublicKey(parsed))
                }
            }

            impl Serializable for PrivateKey {
                type OutputSize = $privkey_size;

                fn write_exact(&self, buf: &mut [u8]) {
                    // Check the length is correct and panic if not
                    enforce_outbuf_len::<Self>(buf);

                    // SecretKeys already know how to convert to bytes
                    buf.copy_from_slice(&self.0.to_bytes());
                }
            }

            impl Deserializable for PrivateKey {
                fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                    // Check the length
                    enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

                    // * Invariant: PrivateKey is in [1,p). This is preserved here.
                    // * SecretKey::from_be_bytes() directly checks that the value isn't zero. And
                    //   its submethod,
                    // * ScalarCore::from_be_bytes() checks that the value doesn't exceed the
                    //   modulus.
                    let sk = curve_crate::SecretKey::from_bytes(encoded.into())
                        .map_err(|_| HpkeError::ValidationError)?;

                    Ok(PrivateKey(sk))
                }
            }

            // DH results are serialized in the same way as public keys
            impl Serializable for KexResult {
                // RFC 9180 §4.1
                // For P-256, P-384, and P-521, the size Ndh of the Diffie-Hellman shared secret is
                // equal to 32, 48, and 66, respectively, corresponding to the x-coordinate of the
                // resulting elliptic curve point.
                type OutputSize = $ss_size;

                fn write_exact(&self, buf: &mut [u8]) {
                    // Check the length is correct and panic if not
                    enforce_outbuf_len::<Self>(buf);

                    // elliptic_curve::ecdh::SharedSecret::raw_secret_bytes returns the serialized
                    // x-coordinate
                    buf.copy_from_slice(self.0.raw_secret_bytes())
                }
            }

            #[doc = concat!("Represents ECDH functionality over NIST curve ", $curve_name, ".")]
            pub struct $dh_name {}

            impl DhKeyExchange for $dh_name {
                #[doc(hidden)]
                type PublicKey = PublicKey;
                #[doc(hidden)]
                type PrivateKey = PrivateKey;
                #[doc(hidden)]
                type KexResult = KexResult;

                /// Converts a private key to a public key
                #[doc(hidden)]
                fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
                    // pk = sk·G where G is the generator. This maintains the invariant of the
                    // public key not being the point at infinity, since ord(G) = p, and sk is not
                    // 0 mod p (by the invariant we keep on PrivateKeys)
                    PublicKey(sk.0.public_key())
                }

                /// Does the DH operation. This function is infallible, thanks to invariants on its
                /// inputs.
                #[doc(hidden)]
                fn dh(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, DhError> {
                    // Do the DH operation
                    let dh_res = diffie_hellman(sk.0.to_nonzero_scalar(), pk.0.as_affine());

                    // RFC 9180 §7.1.4: Senders and recipients MUST ensure that dh_res is not the
                    // point at infinity
                    //
                    // This is already true, since:
                    // 1. pk is not the point at infinity (due to the invariant we keep on
                    //    PublicKeys)
                    // 2. sk is not 0 mod p (due to the invariant we keep on PrivateKeys)
                    // 3. Exponentiating a non-identity element of a prime-order group by something
                    //    less than the order yields a non-identity value
                    // Therefore, dh_res cannot be the point at infinity
                    Ok(KexResult(dh_res))
                }

                // RFC 9180 §7.1.3:
                // def DeriveKeyPair(ikm):
                //   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
                //   sk = 0
                //   counter = 0
                //   while sk == 0 or sk >= order:
                //     if counter > 255:
                //       raise DeriveKeyPairError
                //     bytes = LabeledExpand(dkp_prk, "candidate",
                //                           I2OSP(counter, 1), Nsk)
                //     bytes[0] = bytes[0] & bitmask
                //     sk = OS2IP(bytes)
                //     counter = counter + 1
                //   return (sk, pk(sk))
                // where `bitmask` is defined to be 0xFF for P-256 and P-384, and 0x01 for P-521

                /// Deterministically derives a keypair from the given input keying material and
                /// ciphersuite ID. The keying material SHOULD have as many bits of entropy as the
                /// bit length of a secret key
                #[doc(hidden)]
                fn derive_keypair<Kdf: KdfTrait>(
                    suite_id: &KemSuiteId,
                    ikm: &[u8],
                ) -> (PrivateKey, PublicKey) {
                    // Write the label into a byte buffer and extract from the IKM
                    let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"dkp_prk", ikm);

                    // The buffer we hold the candidate scalar bytes in. This is the size of a
                    // private key.
                    let mut buf =
                        GenericArray::<u8, <PrivateKey as Serializable>::OutputSize>::default();

                    // Try to generate a key 256 times. Practically, this will succeed and return
                    // early on the first iteration.
                    for counter in 0u8..=255 {
                        // This unwrap is fine. It only triggers if buf is way too big. It's only
                        // 32 bytes.
                        hkdf_ctx
                            .labeled_expand(suite_id, b"candidate", &[counter], &mut buf)
                            .unwrap();

                        // Apply the bitmask
                        buf[0] &= $keygen_bitmask;

                        // Try to convert to a valid secret key. If the conversion succeeded,
                        // return the keypair. Recall the invariant of PrivateKey: it is a value in
                        // the range [1,p).
                        if let Ok(sk) = PrivateKey::from_bytes(&buf) {
                            let pk = Self::sk_to_pk(&sk);
                            return (sk, pk);
                        }
                    }

                    // The code should never ever get here. The likelihood that we get 256 bad
                    // samples in a row for P-256 is 2^-8192. For P-384 it's (2^-256)^256.
                    panic!("DeriveKeyPair failed all attempts");
                }
            }
        }
    };
}

use generic_array::typenum;

#[cfg(feature = "p256")]
nistp_dhkex!(
    "P-256",
    DhP256,
    p256,
    typenum::U65, // RFC 9180 §7.1: Npk of DHKEM(P-256, HKDF-SHA256) is 65
    typenum::U32, // RFC 9180 §7.1: Nsk of DHKEM(P-256, HKDF-SHA256) is 32
    typenum::U32, // RFC 9180 §4.1: Ndh of P-256 is equal to 32
    0xFF          // RFC 9180 §7.1.3: The `bitmask` in DeriveKeyPair to be 0xFF for P-256
);

#[cfg(feature = "p384")]
nistp_dhkex!(
    "P-384",
    DhP384,
    p384,
    typenum::U97, // RFC 9180 §7.1: Npk of DHKEM(P-384, HKDF-SHA384) is 97
    typenum::U48, // RFC 9180 §7.1: Nsk of DHKEM(P-384, HKDF-SHA384) is 48
    typenum::U48, // RFC 9180 §4.1: Ndh of P-384 is equal to 48
    0xFF          // RFC 9180 §7.1.3: The `bitmask` in DeriveKeyPair to be 0xFF for P-384
);

#[cfg(feature = "k256")]
nistp_dhkex!(
    "K-256",
    DhK256,
    k256,
    typenum::U65,
    typenum::U32,
    typenum::U32,
    0xFF
);

#[cfg(test)]
mod tests {
    use crate::{dhkex::DhKeyExchange, test_util::dhkex_gen_keypair, Deserializable, Serializable};

    #[cfg(feature = "p256")]
    use super::p256::DhP256;
    #[cfg(feature = "p384")]
    use super::p384::DhP384;

    use hex_literal::hex;
    use rand::{rngs::StdRng, SeedableRng};

    //
    // Test vectors come from RFC 5903 §8.1 and §8.2
    // https://tools.ietf.org/html/rfc5903
    //

    #[cfg(feature = "p256")]
    const P256_PRIVKEYS: &[&[u8]] = &[
        &hex!("C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433"),
        &hex!("C6EF9C5D 78AE012A 011164AC B397CE20 88685D8F 06BF9BE0 B283AB46 476BEE53"),
    ];

    // The public keys corresponding to the above private keys, in order
    #[cfg(feature = "p256")]
    const P256_PUBKEYS: &[&[u8]] = &[
        &hex!(
            "04"                                                                      // Uncompressed
            "DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180" // x-coordinate
            "5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3" // y-coordinate
        ),
        &hex!(
            "04"                                                                      // Uncompressed
            "D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63" // x-coordinate
            "56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB" // y-coordinate
        ),
    ];

    // The result of DH(privkey0, pubkey1) or equivalently, DH(privkey1, pubkey0)
    #[cfg(feature = "p256")]
    const P256_DH_RES_XCOORD: &[u8] =
        &hex!("D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE");

    #[cfg(feature = "p384")]
    const P384_PRIVKEYS: &[&[u8]] = &[
        &hex!(
            "099F3C70 34D4A2C6 99884D73 A375A67F 7624EF7C 6B3C0F16 0647B674 14DCE655 E35B5380"
            "41E649EE 3FAEF896 783AB194"
        ),
        &hex!(
            "41CB0779 B4BDB85D 47846725 FBEC3C94 30FAB46C C8DC5060 855CC9BD A0AA2942 E0308312"
            "916B8ED2 960E4BD5 5A7448FC"
        ),
    ];

    // The public keys corresponding to the above private keys, in order
    #[cfg(feature = "p384")]
    const P384_PUBKEYS: &[&[u8]] = &[
        &hex!(
            "04"                                                             // Uncompressed
            "667842D7 D180AC2C DE6F74F3 7551F557 55C7645C 20EF73E3 1634FE72" // x-coordinate
            "B4C55EE6 DE3AC808 ACB4BDB4 C88732AE E95F41AA"                   //   ...cont
            "9482ED1F C0EEB9CA FC498462 5CCFC23F 65032149 E0E144AD A0241815" // y-coordinate
            "35A0F38E EB9FCFF3 C2C947DA E69B4C63 4573A81C"                   //   ...cont
        ),
        &hex!(
            "04"                                                             // Uncompressed
            "E558DBEF 53EECDE3 D3FCCFC1 AEA08A89 A987475D 12FD950D 83CFA417" // x-coordinate
            "32BC509D 0D1AC43A 0336DEF9 6FDA41D0 774A3571"                   //   ...cont
            "DCFBEC7A ACF31964 72169E83 8430367F 66EEBE3C 6E70C416 DD5F0C68" // y-coordinate
            "759DD1FF F83FA401 42209DFF 5EAAD96D B9E6386C"                   //   ...cont
        ),
    ];

    // The result of DH(privkey0, pubkey1) or equivalently, DH(privkey1, pubkey0)
    #[cfg(feature = "p384")]
    const P384_DH_RES_XCOORD: &[u8] = &hex!(
        "11187331 C279962D 93D60424 3FD592CB 9D0A926F 422E4718 7521287E 7156C5C4 D6031355"
        "69B9E9D0 9CF5D4A2 70F59746"
    );

    //
    // Some helper functions for tests
    //

    /// Tests the ECDH op against a known answer
    #[allow(dead_code)]
    fn test_vector_ecdh<Kex: DhKeyExchange>(
        sk_recip_bytes: &[u8],
        pk_sender_bytes: &[u8],
        dh_res_xcoord_bytes: &[u8],
    ) {
        // Deserialize the pubkey and privkey and do a DH operation
        let sk_recip = Kex::PrivateKey::from_bytes(&sk_recip_bytes).unwrap();
        let pk_sender = Kex::PublicKey::from_bytes(&pk_sender_bytes).unwrap();
        let derived_dh = Kex::dh(&sk_recip, &pk_sender).unwrap();

        // Assert that the derived DH result matches the test vector. Recall that the HPKE DH
        // result is just the x-coordinate, so that's all we can compare
        assert_eq!(derived_dh.to_bytes().as_slice(), dh_res_xcoord_bytes,);
    }

    /// Tests that an deserialize-serialize round-trip ends up at the same pubkey
    #[allow(dead_code)]
    fn test_pubkey_serialize_correctness<Kex: DhKeyExchange>() {
        let mut csprng = StdRng::from_entropy();

        // We can't do the same thing as in the X25519 tests, since a completely random point
        // is not likely to lie on the curve. Instead, we just generate a random point,
        // serialize it, deserialize it, and test whether it's the same using impl Eq for
        // AffinePoint

        let (_, pubkey) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let pubkey_bytes = pubkey.to_bytes();
        let rederived_pubkey =
            <Kex as DhKeyExchange>::PublicKey::from_bytes(&pubkey_bytes).unwrap();

        // See if the re-serialized bytes are the same as the input
        assert_eq!(pubkey, rederived_pubkey);
    }

    /// Tests the `sk_to_pk` function against known answers
    #[allow(dead_code)]
    fn test_vector_corresponding_pubkey<Kex: DhKeyExchange>(sks: &[&[u8]], pks: &[&[u8]]) {
        for (sk_bytes, pk_bytes) in sks.iter().zip(pks.iter()) {
            // Deserialize the hex values
            let sk = Kex::PrivateKey::from_bytes(sk_bytes).unwrap();
            let pk = Kex::PublicKey::from_bytes(pk_bytes).unwrap();

            // Derive the secret key's corresponding pubkey and check that it matches the given
            // pubkey
            let derived_pk = Kex::sk_to_pk(&sk);
            assert_eq!(derived_pk, pk);
        }
    }

    /// Tests that an deserialize-serialize round-trip on a DH keypair ends up at the same values
    #[allow(dead_code)]
    fn test_dh_serialize_correctness<Kex: DhKeyExchange>()
    where
        Kex::PrivateKey: PartialEq,
    {
        let mut csprng = StdRng::from_entropy();

        // Make a random keypair and serialize it
        let (sk, pk) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let (sk_bytes, pk_bytes) = (sk.to_bytes(), pk.to_bytes());

        // Now deserialize those bytes
        let new_sk = Kex::PrivateKey::from_bytes(&sk_bytes).unwrap();
        let new_pk = Kex::PublicKey::from_bytes(&pk_bytes).unwrap();

        // See if the deserialized values are the same as the initial ones
        assert!(new_sk == sk, "private key doesn't serialize correctly");
        assert!(new_pk == pk, "public key doesn't serialize correctly");
    }

    #[cfg(feature = "p256")]
    #[test]
    fn test_vector_ecdh_p256() {
        test_vector_ecdh::<DhP256>(&P256_PRIVKEYS[0], &P256_PUBKEYS[1], &P256_DH_RES_XCOORD);
    }
    #[cfg(feature = "p384")]
    #[test]
    fn test_vector_ecdh_p384() {
        test_vector_ecdh::<DhP384>(&P384_PRIVKEYS[0], &P384_PUBKEYS[1], &P384_DH_RES_XCOORD);
    }

    #[cfg(feature = "p256")]
    #[test]
    fn test_vector_corresponding_pubkey_p256() {
        test_vector_corresponding_pubkey::<DhP256>(P256_PRIVKEYS, P256_PUBKEYS);
    }
    #[cfg(feature = "p384")]
    #[test]
    fn test_vector_corresponding_pubkey_p384() {
        test_vector_corresponding_pubkey::<DhP384>(P384_PRIVKEYS, P384_PUBKEYS);
    }

    #[cfg(feature = "p256")]
    #[test]
    fn test_pubkey_serialize_correctness_p256() {
        test_pubkey_serialize_correctness::<DhP256>();
    }
    #[cfg(feature = "p384")]
    #[test]
    fn test_pubkey_serialize_correctness_p384() {
        test_pubkey_serialize_correctness::<DhP384>();
    }

    #[cfg(feature = "256")]
    #[test]
    fn test_dh_serialize_correctness_p256() {
        test_dh_serialize_correctness::<DhP256>();
    }

    #[cfg(feature = "384")]
    #[test]
    fn test_dh_serialize_correctness_p384() {
        test_dh_serialize_correctness::<DhP384>();
    }
}
