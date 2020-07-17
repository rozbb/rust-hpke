use crate::{
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
    kex::{KeyExchange, Marshallable, Unmarshallable},
    util::KemSuiteId,
    HpkeError,
};

use digest::generic_array::GenericArray;
use p256::{
    arithmetic::{AffinePoint, ProjectivePoint, Scalar},
    elliptic_curve::weierstrass::{
        curve::Curve,
        point::{UncompressedCurvePoint, UncompressedPointSize},
    },
    NistP256,
};
use subtle::ConstantTimeEq;

/// An ECDH-P256 public key
#[derive(Clone)]
pub struct PublicKey(AffinePoint);

// The range invariant below is maintained so that sk_to_pk is a well-defined operation. If you
// disagree with this decision, fight me.
/// A ECDH-P256 private key. This is a scalar in the range `[1,p)`.
#[derive(Clone)]
pub struct PrivateKey(Scalar);

// A bare DH computation result
pub struct KexResult(AffinePoint);

// Everything is marshalled and unmarshalled uncompressed
impl Marshallable for PublicKey {
    // A fancy way of saying "65 bytes"
    type OutputSize = UncompressedPointSize<<NistP256 as Curve>::ScalarSize>;

    fn marshal(&self) -> GenericArray<u8, Self::OutputSize> {
        GenericArray::clone_from_slice(&self.0.to_uncompressed_pubkey().into_bytes())
    }
}

// A helper method for the unmarshall method. The real unmarshall method just runs this and
// interprets any `None` as an InvalidEncoding error.
impl PublicKey {
    fn unmarshal_helper(encoded: &[u8]) -> Option<PublicKey> {
        // In order to parse as an uncompressed curve point, we first make sure the input length is
        // correct
        if encoded.len() != Self::size() {
            return None;
        }

        // Parse as uncompressed curve point. This checks that the encoded point is well-formed,
        // but does not check that the point is on the curve.
        let uncompressed = {
            let byte_arr = GenericArray::clone_from_slice(encoded);
            UncompressedCurvePoint::from_bytes(byte_arr)?
        };

        // Convert to an affine point. This will fail if the point is not on the curve or if the
        // point is the point at infinity. Both of these are invalid DH pubkeys.
        let aff = {
            let pubkey = p256::PublicKey::from(uncompressed);
            AffinePoint::from_pubkey(&pubkey)
        };

        if aff.is_some().into() {
            Some(PublicKey(aff.unwrap()))
        } else {
            None
        }
    }
}

// Everything is marshalled and unmarshalled uncompressed
impl Unmarshallable for PublicKey {
    fn unmarshal(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Run the real unmarshal method and treat `None` as an encoding error
        Self::unmarshal_helper(encoded).ok_or(HpkeError::InvalidEncoding)
    }
}

impl Marshallable for PrivateKey {
    // A fancy way of saying "32 bytes"
    type OutputSize = <NistP256 as Curve>::ScalarSize;

    fn marshal(&self) -> GenericArray<u8, Self::OutputSize> {
        GenericArray::clone_from_slice(&self.0.to_bytes())
    }
}

impl Unmarshallable for PrivateKey {
    fn unmarshal(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Check the length
        if encoded.len() != 32 {
            return Err(HpkeError::InvalidEncoding);
        }

        // All private keys must be in the range [1,p). It suffices to check that the given array
        // is not all zeros, since Scalar::from_bytes requires its input to be in reduced form
        // anyways. This means that if arr ends up being np for some integer n, then it'll get
        // rejected later.
        if encoded.ct_eq(&[0u8; 32]).into() {
            return Err(HpkeError::InvalidEncoding);
        }

        // Copy the bytes into a fixed-size array
        let mut arr = [0u8; 32];
        arr.copy_from_slice(encoded);

        // This will fail iff the bytes don't represent a number in the range [0,p)
        let scalar = Scalar::from_bytes(arr);
        if scalar.is_none().into() {
            return Err(HpkeError::InvalidEncoding);
        }

        Ok(PrivateKey(scalar.unwrap()))
    }
}

// DH results are marshalled in the same way as public keys
impl Marshallable for KexResult {
    // §4.1: Ndh equals Npk
    type OutputSize = <PublicKey as Marshallable>::OutputSize;

    fn marshal(&self) -> GenericArray<u8, Self::OutputSize> {
        // Rewrap and marshal
        PublicKey(self.0).marshal()
    }
}

/// Represents ECDH functionality over NIST curve P-256
pub struct DhP256 {}

impl KeyExchange for DhP256 {
    #[doc(hidden)]
    type PublicKey = PublicKey;
    #[doc(hidden)]
    type PrivateKey = PrivateKey;
    #[doc(hidden)]
    type KexResult = KexResult;

    /// Converts an P256 private key to a public key
    #[doc(hidden)]
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        let pk = p256::arithmetic::ProjectivePoint::generator() * &sk.0;
        // It's safe to unwrap() here, because PrivateKeys are guaranteed to never be 0 (see the
        // unmarshal() implementation for details)
        PublicKey(pk.to_affine().unwrap())
    }

    /// Does the DH operation. Returns `HpkeError::InvalidKeyExchange` if and only if the DH
    /// result was all zeros. This is required by the HPKE spec.
    #[doc(hidden)]
    fn kex(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, HpkeError> {
        // Convert to a projective point so we can do arithmetic
        let pk_proj: ProjectivePoint = pk.0.into();
        // Do the DH operation
        let dh_res_proj = pk_proj * &sk.0;

        // We can unwrap here because we know pk is not the point at infinity (since this has no
        // affine representation), and sk is not 0 mod p (due to the invariant we keep on
        // PrivateKeys)
        Ok(KexResult(dh_res_proj.to_affine().unwrap()))
    }

    // From the DeriveKeyPair section
    //   def DeriveKeyPair(ikm):
    //     dkp_prk = LabeledExtract(
    //       zero(0),
    //       concat(I2OSP(kem_id, 2), "dkp_prk"),
    //       ikm
    //     )
    //     sk = 0
    //     counter = 0
    //     while sk == 0 or sk >= order:
    //       if counter > 255:
    //         raise DeriveKeyPairError
    //       bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)
    //       bytes[0] = bytes[0] & bitmask
    //       sk = OS2IP(bytes)
    //       counter = counter + 1
    //     return (sk, pk(sk))
    //
    /// Deterministically derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material SHOULD have as many bits of entropy as the bit length of a secret
    /// key, i.e., 256.
    #[doc(hidden)]
    fn derive_keypair<Kdf: KdfTrait>(suite_id: &KemSuiteId, ikm: &[u8]) -> (PrivateKey, PublicKey) {
        // Write the label into a byte buffer and extract from the IKM
        let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"dkp_prk", ikm);

        // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
        let mut buf = [0u8; 32];

        // Try to generate a key 256 times. Practically, this will succeed and return early on the
        // first iteration.
        for counter in 0u8..=255 {
            // This unwrap is fine. It only triggers if buf is way too big. It's only 32 bytes.
            hkdf_ctx
                .labeled_expand(suite_id, b"candidate", &[counter], &mut buf)
                .unwrap();

            // Try to convert to a scalar
            let sk = Scalar::from_bytes(buf);

            // If the conversion succeeded, return the keypair
            if sk.is_some().into() {
                let sk = PrivateKey(sk.unwrap());
                let pk = Self::sk_to_pk(&sk);
                return (sk, pk);
            }
        }

        // The code should never ever get here. The likelihood that we get 256 bad samples
        // in a row for p256 is 2^-8192.
        panic!("DeriveKeyPair failed all attempts");
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        kex::{
            ecdh_nistp::{DhP256, PrivateKey, PublicKey},
            KeyExchange, Marshallable, Unmarshallable,
        },
        test_util::kex_gen_keypair,
    };

    use rand::{rngs::StdRng, SeedableRng};

    // We need this in our marshal-unmarshal tests
    impl PartialEq for PrivateKey {
        fn eq(&self, other: &PrivateKey) -> bool {
            self.0.to_bytes() == other.0.to_bytes()
        }
    }

    // We need this in our marshal-unmarshal tests
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

    // Test vector comes from §8.1 of RFC5903
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
        let dh_res_bytes = hex::decode(concat!(
            "04",                                                               // Uncompressed
            "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE", // x-coordinate
            "522BDE0AF0D8585B8DEF9C183B5AE38F50235206A8674ECB5D98EDB20EB153A2", // y-coordinate
        ))
        .unwrap();

        // Unmarshal the pubkey and privkey and do a DH operation
        let sk_recip = <Kex as KeyExchange>::PrivateKey::unmarshal(&sk_recip_bytes).unwrap();
        let pk_sender = <Kex as KeyExchange>::PublicKey::unmarshal(&pk_sender_bytes).unwrap();
        let derived_dh = <Kex as KeyExchange>::kex(&sk_recip, &pk_sender).unwrap();

        // Assert that the derived DH result matches the test vector
        assert_eq!(derived_dh.marshal().as_slice(), dh_res_bytes.as_slice());
    }

    // Test vector comes from §8.1 of RFC5903
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
            // Unmarshal the hex values
            let sk =
                <Kex as KeyExchange>::PrivateKey::unmarshal(&hex::decode(sk_hex).unwrap()).unwrap();
            let pk =
                <Kex as KeyExchange>::PublicKey::unmarshal(&hex::decode(pk_hex).unwrap()).unwrap();

            // Derive the secret key's corresponding pubkey and check that it matches the given
            // pubkey
            let derived_pk = <Kex as KeyExchange>::sk_to_pk(&sk);
            assert_eq!(derived_pk, pk);
        }
    }

    /// Tests that an unmarshal-marshal round-trip ends up at the same pubkey
    #[test]
    fn test_pubkey_marshal_correctness() {
        type Kex = DhP256;

        let mut csprng = StdRng::from_entropy();

        // We can't do the same thing as in the X25519 tests, since a completely random point is
        // not likely to lie on the curve. Instead, we just generate a random point, marshal it,
        // unmarshal it, and test whether it's the same using impl Eq for AffinePoint

        let (_, pubkey) = kex_gen_keypair::<Kex, _>(&mut csprng);
        let pubkey_bytes = pubkey.marshal();
        let rederived_pubkey = <Kex as KeyExchange>::PublicKey::unmarshal(&pubkey_bytes).unwrap();

        // See if the re-marshalled bytes are the same as the input
        assert_eq!(pubkey, rederived_pubkey);
    }

    /// Tests that an unmarshal-marshal round-trip on a DH keypair ends up at the same values
    #[test]
    fn test_dh_marshal_correctness() {
        type Kex = DhP256;

        let mut csprng = StdRng::from_entropy();

        // Make a random keypair and marshal it
        let (sk, pk) = kex_gen_keypair::<Kex, _>(&mut csprng);
        let (sk_bytes, pk_bytes) = (sk.marshal(), pk.marshal());

        // Now unmarshal those bytes
        let new_sk = <Kex as KeyExchange>::PrivateKey::unmarshal(&sk_bytes).unwrap();
        let new_pk = <Kex as KeyExchange>::PublicKey::unmarshal(&pk_bytes).unwrap();

        // See if the unmarshalled values are the same as the initial ones
        assert!(new_sk == sk, "private key doesn't marshal correctly");
        assert!(new_pk == pk, "public key doesn't marshal correctly");
    }
}
