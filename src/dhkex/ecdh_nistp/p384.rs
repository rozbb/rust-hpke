use crate::{
    dhkex::{DhError, DhKeyExchange},
    kdf::Kdf as KdfTrait,
    util::{enforce_equal_len, KemSuiteId},
    Deserializable, HpkeError, Serializable,
};
use subtle::{Choice, ConstantTimeEq};

use generic_array::{
    typenum::{Unsigned, U48, U97},
    GenericArray,
};
use p384::elliptic_curve::{ecdh::diffie_hellman, sec1::ToEncodedPoint};

/// An ECDH-P384 public key. This is never the point at infinity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(p384::PublicKey);

// This is only ever constructed via its Deserializable::from_bytes, which checks for the 0 value.
// Also, the underlying type is zeroize-on-drop.
/// An ECDH-P384 private key. This is a scalar in the range `[1,p)` where `p` is the group order.
#[derive(Clone, Eq, PartialEq)]
pub struct PrivateKey(p384::SecretKey);

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

// The underlying type is zeroize-on-drop
/// A bare DH computation result
pub struct KexResult(p384::ecdh::SharedSecret);

// Everything is serialized and deserialized in uncompressed form
impl Serializable for PublicKey {
    // RFC 9180 §7.1: Npk of DHKEM(P-384, HKDF-SHA384) is 97
    type OutputSize = U97;

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
            p384::PublicKey::from_sec1_bytes(encoded).map_err(|_| HpkeError::ValidationError)?;
        Ok(PublicKey(parsed))
    }
}

impl Serializable for PrivateKey {
    // RFC 9180 §7.1: Nsk of DHKEM(P-384, HKDF-SHA384) is 48
    type OutputSize = U48;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // SecretKeys already know how to convert to bytes
        self.0.to_bytes()
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Check the length
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Invariant: PrivateKey is in [1,p). This is preserved here.
        // SecretKey::from_be_bytes() directly checks that the value isn't zero. And its submethod,
        // ScalarCore::from_be_bytes() checks that the value doesn't exceed the modulus.
        let sk =
            p384::SecretKey::from_bytes(encoded.into()).map_err(|_| HpkeError::ValidationError)?;

        Ok(PrivateKey(sk))
    }
}

// DH results are serialized in the same way as public keys
impl Serializable for KexResult {
    // RFC 9180 §4.1
    // For P-256, P-384, and P-521, the size Ndh of the Diffie-Hellman shared secret is equal to
    // 32, 48, and 66, respectively, corresponding to the x-coordinate of the resulting elliptic
    // curve point.
    type OutputSize = U48;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // ecdh::SharedSecret::as_bytes returns the serialized x-coordinate
        *self.0.raw_secret_bytes()
    }
}

/// Represents ECDH functionality over NIST curve P-256
pub struct DhP384 {}

impl DhKeyExchange for DhP384 {
    #[doc(hidden)]
    type PublicKey = PublicKey;
    #[doc(hidden)]
    type PrivateKey = PrivateKey;
    #[doc(hidden)]
    type KexResult = KexResult;

    /// Converts an P384 private key to a public key
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
    fn derive_keypair<Kdf: KdfTrait>(suite_id: &KemSuiteId, ikm: &[u8]) -> (PrivateKey, PublicKey) {
        super::nist_pxxx_derive::<48, Kdf, Self>(suite_id, ikm)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dhkex::{ecdh_nistp::p384::DhP384, DhKeyExchange},
        test_util::dhkex_gen_keypair,
        Deserializable, Serializable,
    };

    use rand::{rngs::StdRng, SeedableRng};

    // Test vector comes from RFC 5903 §8.1
    // https://tools.ietf.org/html/rfc5903
    /// Tests the ECDH op against a known answer
    #[test]
    fn test_vector_ecdh() {
        type Kex = DhP384;

        let sk_recip_bytes =
            hex::decode("099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194") // i
                .unwrap();
        let pk_sender_bytes = hex::decode(concat!( // r
            "04",                                                               // Uncompressed
            "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571", // x-coordinate - grx
            "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C", // y-coordinate - gry
        ))
        .unwrap();
        let dh_res_xcoord_bytes = hex::decode(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746", // x-coordinate - girx
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

    // Test vector comes from RFC 5903 §8.2
    // https://tools.ietf.org/html/rfc5903
    /// Tests the `sk_to_pk` function against known answers
    #[test]
    fn test_vector_corresponding_pubkey() {
        type Kex = DhP384;

        let sks = [
            "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194",
            "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC",
        ];
        let pks = [
            concat!(
                "04",                                                               // Uncompressed
                "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA", // x-coordinate
                "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C"  // y-coordinate
            ),
            concat!(
                "04",                                                               // Uncompressed
                "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571", // x-coordinate
                "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C", // y-coordinate
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
        type Kex = DhP384;

        let mut csprng = StdRng::from_entropy();

        // We can't do the same thing as in the X25519 tests, since a completely random point is
        // not likely to lie on the curve. Instead, we just generate a random point, serialize it,
        // deserialize it, and test whether it's the same using impl Eq for AffinePoint

        let (_, pubkey) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let pubkey_bytes = pubkey.to_bytes();
        let rederived_pubkey =
            <Kex as DhKeyExchange>::PublicKey::from_bytes(&pubkey_bytes).unwrap();

        // See if the re-serialized bytes are the same as the input
        assert_eq!(pubkey, rederived_pubkey);
    }

    /// Tests that an deserialize-serialize round-trip on a DH keypair ends up at the same values
    #[test]
    fn test_dh_serialize_correctness() {
        type Kex = DhP384;

        let mut csprng = StdRng::from_entropy();

        // Make a random keypair and serialize it
        let (sk, pk) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let (sk_bytes, pk_bytes) = (sk.to_bytes(), pk.to_bytes());

        // Now deserialize those bytes
        let new_sk = <Kex as DhKeyExchange>::PrivateKey::from_bytes(&sk_bytes).unwrap();
        let new_pk = <Kex as DhKeyExchange>::PublicKey::from_bytes(&pk_bytes).unwrap();

        // See if the deserialized values are the same as the initial ones
        assert!(new_sk == sk, "private key doesn't serialize correctly");
        assert!(new_pk == pk, "public key doesn't serialize correctly");
    }
}
