use crate::{
    dhkex::{DhError, DhKeyExchange},
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
    util::{enforce_equal_len, KemSuiteId},
    Deserializable, HpkeError, Serializable,
};

use generic_array::{
    typenum::{Unsigned, U32, U65},
    GenericArray,
};
use p256::elliptic_curve::{ecdh::diffie_hellman, sec1::ToEncodedPoint};

/// An ECDH-P256 public key. This is never the point at infinity.
#[derive(Clone)]
pub struct PublicKey(p256::PublicKey);

// This is only ever constructed via its Deserializable::from_bytes, which checks for the 0 value.
// Also, the underlying type is zeroize-on-drop.
/// An ECDH-P256 private key. This is a scalar in the range `[1,p)` where `p` is the group order.
#[derive(Clone)]
pub struct PrivateKey(p256::SecretKey);

// The underlying type is zeroize-on-drop
/// A bare DH computation result
pub struct KexResult(p256::ecdh::SharedSecret);

// Everything is serialized and deserialized in uncompressed form
impl Serializable for PublicKey {
    // RFC 9180 §7.1: Npk of DHKEM(P-256, HKDF-SHA256) is 65
    type OutputSize = U65;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Get the uncompressed pubkey encoding
        let encoded = self.0.as_affine().to_encoded_point(false);
        // Serialize it
        GenericArray::clone_from_slice(encoded.as_bytes())
    }
}

// Everything is serialized and deserialized in uncompressed form
impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // In order to parse as an uncompressed curve point, we first make sure the input length is
        // correct. This ensures we're receiving the uncompressed representation.
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Now just deserialize. The non-identity invariant is preserved because
        // PublicKey::from_sec1_bytes() will error if it receives the point at infinity. This is
        // because its submethod, PublicKey::from_encoded_point(), does this check explicitly.
        let parsed =
            p256::PublicKey::from_sec1_bytes(encoded).map_err(|_| HpkeError::ValidationError)?;
        Ok(PublicKey(parsed))
    }
}

impl Serializable for PrivateKey {
    // RFC 9180 §7.1: Nsk of DHKEM(P-256, HKDF-SHA256) is 32
    type OutputSize = U32;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // SecretKeys already know how to convert to bytes
        self.0.to_be_bytes()
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Check the length
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Invariant: PrivateKey is in [1,p). This is preserved here.
        // SecretKey::from_be_bytes() directly checks that the value isn't zero. And its submethod,
        // ScalarCore::from_be_bytes() checks that the value doesn't exceed the modulus.
        let sk = p256::SecretKey::from_be_bytes(encoded).map_err(|_| HpkeError::ValidationError)?;

        Ok(PrivateKey(sk))
    }
}

// DH results are serialized in the same way as public keys
impl Serializable for KexResult {
    // RFC 9180 §4.1
    // For P-256, P-384, and P-521, the size Ndh of the Diffie-Hellman shared secret is equal to
    // 32, 48, and 66, respectively, corresponding to the x-coordinate of the resulting elliptic
    // curve point.
    type OutputSize = U32;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // ecdh::SharedSecret::as_bytes returns the serialized x-coordinate
        *self.0.as_bytes()
    }
}

/// Represents ECDH functionality over NIST curve P-256
pub struct DhP256 {}

impl DhKeyExchange for DhP256 {
    #[doc(hidden)]
    type PublicKey = PublicKey;
    #[doc(hidden)]
    type PrivateKey = PrivateKey;
    #[doc(hidden)]
    type KexResult = KexResult;

    /// Converts an P256 private key to a public key
    #[doc(hidden)]
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        // pk = sk·G where G is the generator. This maintains the invariant of the public key not
        // being the point at infinity, since ord(G) = p, and sk is not 0 mod p (by the invariant
        // we keep on PrivateKeys)
        PublicKey(sk.0.public_key())
    }

    /// Does the DH operation. This function is infallible, thanks to invariants on its inputs.
    #[doc(hidden)]
    fn dh(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, DhError> {
        // Do the DH operation
        let dh_res = diffie_hellman(sk.0.to_nonzero_scalar(), pk.0.as_affine());

        // RFC 9180 §7.1.4: Senders and recipients MUST ensure that dh_res is not the point at
        // infinity
        //
        // This is already true, since:
        // 1. pk is not the point at infinity (due to the invariant we keep on PublicKeys)
        // 2. sk is not 0 mod p (due to the invariant we keep on PrivateKeys)
        // 3. Exponentiating a non-identity element of a prime-order group by something less than
        //    the order yields a non-identity value
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
    //  where bitmask = 0xFF for P-256, i.e., the masking line is a no-op

    /// Deterministically derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material SHOULD have as many bits of entropy as the bit length of a secret
    /// key, i.e., 256.
    #[doc(hidden)]
    fn derive_keypair<Kdf: KdfTrait>(
        suite_id: &KemSuiteId,
        ikm: &[u8],
    ) -> Result<(PrivateKey, PublicKey), HpkeError> {
        // Write the label into a byte buffer and extract from the IKM
        let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"dkp_prk", ikm);

        // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
        let mut buf = GenericArray::<u8, <PrivateKey as Serializable>::OutputSize>::default();

        // Try to generate a key 256 times. Practically, this will succeed and return early on the
        // first iteration.
        for counter in 0u8..=255 {
            // This unwrap is fine. It only triggers if buf is way too big. It's only 32 bytes.
            hkdf_ctx
                .labeled_expand(suite_id, b"candidate", &[counter], &mut buf)
                .map_err(|_| HpkeError::KdfOutputTooLong)?;

            // Try to convert to a valid secret key. If the conversion succeeded, return the
            // keypair. Recall the invariant of PrivateKey: it is a value in the range [1,p).
            if let Ok(sk) = PrivateKey::from_bytes(&buf) {
                let pk = Self::sk_to_pk(&sk);
                return Ok((sk, pk));
            }
        }

        // The code should never ever get here. The likelihood that we get 256 bad samples
        // in a row for p256 is 2^-8192.
        Err(HpkeError::DerivationLimitReached)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dhkex::{
            ecdh_nistp::{DhP256, PrivateKey, PublicKey},
            DhKeyExchange,
        },
        test_util::dhkex_gen_keypair,
        Deserializable, Serializable,
    };

    use rand::{rngs::StdRng, SeedableRng};

    // We need this in our serialize-deserialize tests
    impl PartialEq for PrivateKey {
        fn eq(&self, other: &PrivateKey) -> bool {
            self.to_bytes() == other.to_bytes()
        }
    }

    // We need this in our serialize-deserialize tests
    impl PartialEq for PublicKey {
        fn eq(&self, other: &PublicKey) -> bool {
            self.0 == other.0
        }
    }

    impl core::fmt::Debug for PublicKey {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
            write!(f, "PublicKey({:?})", self.0)
        }
    }

    // Test vector comes from RFC 5903 §8.1
    // https://tools.ietf.org/html/rfc5903
    /// Tests the ECDH op against a known answer
    #[test]
    fn test_vector_ecdh() {
        type Kex = DhP256;

        let sk_recip_bytes =
            hex::decode("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
                .unwrap();
        let pk_sender_bytes = hex::decode(concat!(
            "04",                                                               // Uncompressed
            "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63", // x-coordinate
            "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB", // y-coordinate
        ))
        .unwrap();
        let dh_res_xcoord_bytes = hex::decode(
            "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE", // x-coordinate
        )
        .unwrap();

        // Deserialize the pubkey and privkey and do a DH operation
        let sk_recip = <Kex as DhKeyExchange>::PrivateKey::from_bytes(&sk_recip_bytes).unwrap();
        let pk_sender = <Kex as DhKeyExchange>::PublicKey::from_bytes(&pk_sender_bytes).unwrap();
        let derived_dh = <Kex as DhKeyExchange>::dh(&sk_recip, &pk_sender).unwrap();

        // Assert that the derived DH result matches the test vector. Recall that the HPKE DH
        // result is just the x-coordinate, so that's all we can compare
        assert_eq!(
            derived_dh.to_bytes().as_slice(),
            dh_res_xcoord_bytes.as_slice()
        );
    }

    // Test vector comes from RFC 5903 §8.1
    // https://tools.ietf.org/html/rfc5903
    /// Tests the `sk_to_pk` function against known answers
    #[test]
    fn test_vector_corresponding_pubkey() {
        type Kex = DhP256;

        let sks = [
            "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433",
            "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53",
        ];
        let pks = [
            concat!(
                "04",                                                               // Uncompressed
                "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180", // x-coordinate
                "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3"  // y-coordinate
            ),
            concat!(
                "04",                                                               // Uncompressed
                "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63", // x-coordinate
                "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB", // y-coordinate
            ),
        ];

        for (sk_hex, pk_hex) in sks.iter().zip(pks.iter()) {
            // Deserialize the hex values
            let sk = <Kex as DhKeyExchange>::PrivateKey::from_bytes(&hex::decode(sk_hex).unwrap())
                .unwrap();
            let pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(&hex::decode(pk_hex).unwrap())
                .unwrap();

            // Derive the secret key's corresponding pubkey and check that it matches the given
            // pubkey
            let derived_pk = <Kex as DhKeyExchange>::sk_to_pk(&sk);
            assert_eq!(derived_pk, pk);
        }
    }

    /// Tests that an deserialize-serialize round-trip ends up at the same pubkey
    #[test]
    fn test_pubkey_serialize_correctness() {
        type Kex = DhP256;

        let mut csprng = StdRng::from_entropy();

        // We can't do the same thing as in the X25519 tests, since a completely random point is
        // not likely to lie on the curve. Instead, we just generate a random point, serialize it,
        // deserialize it, and test whether it's the same using impl Eq for AffinePoint

        let (_, pubkey) = dhkex_gen_keypair::<Kex, _>(&mut csprng).unwrap();
        let pubkey_bytes = pubkey.to_bytes();
        let rederived_pubkey =
            <Kex as DhKeyExchange>::PublicKey::from_bytes(&pubkey_bytes).unwrap();

        // See if the re-serialized bytes are the same as the input
        assert_eq!(pubkey, rederived_pubkey);
    }

    /// Tests that an deserialize-serialize round-trip on a DH keypair ends up at the same values
    #[test]
    fn test_dh_serialize_correctness() {
        type Kex = DhP256;

        let mut csprng = StdRng::from_entropy();

        // Make a random keypair and serialize it
        let (sk, pk) = dhkex_gen_keypair::<Kex, _>(&mut csprng).unwrap();
        let (sk_bytes, pk_bytes) = (sk.to_bytes(), pk.to_bytes());

        // Now deserialize those bytes
        let new_sk = <Kex as DhKeyExchange>::PrivateKey::from_bytes(&sk_bytes).unwrap();
        let new_pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(&pk_bytes).unwrap();

        // See if the deserialized values are the same as the initial ones
        assert!(new_sk == sk, "private key doesn't serialize correctly");
        assert!(new_pk == pk, "public key doesn't serialize correctly");
    }
}
