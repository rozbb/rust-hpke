use crate::{
    kex::{KeyExchange, Marshallable, Unmarshallable},
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
use rand::{CryptoRng, RngCore};
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

/// Dummy type which implements the `KeyExchange` trait
pub struct DhP256 {}

impl KeyExchange for DhP256 {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type KexResult = KexResult;

    /// Generates an P256 keypair
    fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (PrivateKey, PublicKey) {
        // Generate a random scalar. Since some choices might be out of range, just keep generating
        // until we get a valid one.
        let mut scalar;
        loop {
            let mut bytes = [0u8; 32];
            csprng.fill_bytes(&mut bytes);
            scalar = Scalar::from_bytes(bytes);
            if scalar.is_some().into() {
                break;
            }
        }

        // Wrap the scalar and derive its pubkey
        let sk = PrivateKey(scalar.unwrap());
        let pk = Self::sk_to_pk(&sk);

        (sk, pk)
    }

    /// Converts an P256 private key to a public key
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        let pk = p256::arithmetic::ProjectivePoint::generator() * &sk.0;
        // It's safe to unwrap() here, because PrivateKeys are guaranteed to never be 0 (see the
        // unmarshal() implementation for details)
        PublicKey(pk.to_affine().unwrap())
    }

    /// Does the DH operation. Returns `HpkeError::InvalidKeyExchange` if and only if the DH
    /// result was all zeros. This is required by the HPKE spec.
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
}

#[cfg(test)]
mod tests {
    use crate::kex::{
        ecdh_nistp::{DhP256, PrivateKey, PublicKey},
        KeyExchange, Marshallable, Unmarshallable,
    };

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

        let mut csprng = rand::thread_rng();

        // We can't do the same thing as in the X25519 tests, since a completely random point is
        // not likely to lie on the curve. Instead, we just generate a random point, marshal it,
        // unmarshal it, and test whether it's the same using impl Eq for AffinePoint

        let (_, pubkey) = <Kex as KeyExchange>::gen_keypair(&mut csprng);
        let pubkey_bytes = pubkey.marshal();
        let rederived_pubkey = <Kex as KeyExchange>::PublicKey::unmarshal(&pubkey_bytes).unwrap();

        // See if the re-marshalled bytes are the same as the input
        assert_eq!(pubkey, rederived_pubkey);
    }

    /// Tests that an unmarshal-marshal round-trip on a DH keypair ends up at the same values
    #[test]
    fn test_dh_marshal_correctness() {
        type Kex = DhP256;

        let mut csprng = rand::thread_rng();

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
