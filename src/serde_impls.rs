//! This module defines serde::Serialize and serde::Deserialize for all Serializable and
//! Deserializable types defined in this crate. This is gated under the `serde_impls` feature.

use crate::{
    aead::{Aead, AeadTag},
    dhkex, kem, Deserializable, Serializable,
};

use digest::generic_array::GenericArray;
use serde::{de::Error, Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

// Implement Serialize for AeadTag<P: Aead>
impl<A: Aead> SerdeSerialize for AeadTag<A> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Convert to a GenericArray and serialize that
        let bytes = self.to_bytes();
        bytes.serialize(serializer)
    }
}

// Implement Deserialize for AeadTag<P: Aead>
impl<'de, A: Aead> SerdeDeserialize<'de> for AeadTag<A> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Use the GenericArray deserializer to get the appropriate number of bytes
        let bytes = GenericArray::<u8, <Self as crate::Serializable>::OutputSize>::deserialize(
            deserializer,
        )?;
        // Try to build this object from the given bytes. If it doesn't work, wrap and
        // return the resulting HpkeError
        Self::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

// Implements serde::{Serialize, Deserialize} over type t. This is almost identical to above.
macro_rules! impl_serde_noparam {
    ($t:ty) => {
        /// Implements `serde::Serialize`
        impl SerdeSerialize for $t {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                // Convert to a GenericArray and serialize that
                let bytes = self.to_bytes();
                bytes.serialize(serializer)
            }
        }

        /// Implements `serde::Deserialize`
        impl<'de> SerdeDeserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                // Use the GenericArray deserializer to get the appropriate number of bytes
                let bytes =
                    GenericArray::<u8, <Self as crate::Serializable>::OutputSize>::deserialize(
                        deserializer,
                    )?;
                // Try to build this object from the given bytes. If it doesn't work, wrap and
                // return the resulting HpkeError
                Self::from_bytes(&bytes).map_err(D::Error::custom)
            }
        }
    };
}

// Implement Serialize/Deserialize for all PrivateKey, PublicKey, and EncappedKey types, as
// features permit

#[cfg(feature = "x25519")]
impl_serde_noparam!(dhkex::x25519::PrivateKey);
#[cfg(feature = "x25519")]
impl_serde_noparam!(dhkex::x25519::PublicKey);
#[cfg(feature = "x25519")]
impl_serde_noparam!(kem::X25519HkdfSha256EncappedKey);

#[cfg(feature = "p256")]
impl_serde_noparam!(dhkex::ecdh_nistp::PrivateKey);
#[cfg(feature = "p256")]
impl_serde_noparam!(dhkex::ecdh_nistp::PublicKey);
#[cfg(feature = "p256")]
impl_serde_noparam!(kem::DhP256HkdfSha256EncappedKey);

#[cfg(test)]
mod test {
    use crate::{
        aead::AesGcm128,
        kdf::HkdfSha256,
        kem::Kem as KemTrait,
        setup_sender,
        test_util::{gen_rand_buf, new_op_mode_pair, OpModeKind},
        Serializable,
    };

    use rand::{rngs::StdRng, SeedableRng};
    use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

    // Checks that serializing and deserializing the given data preserves its identity
    fn assert_serde_roundtrip<T>(data: &T)
    where
        T: Serializable + SerdeSerialize + for<'a> SerdeDeserialize<'a>,
    {
        // Write to JSON then try to read back from it
        let json = serde_json::to_vec(data).expect("couldn't serialize data");
        let json_ref: &[u8] = json.as_ref();
        let reconstructed_data: T =
            serde_json::from_reader(json_ref).expect("couldn't deserialize data");

        // We actually have no way of telling these are equal besides just using our built-in
        // Serialize functions and comparing the bytes. Maybe this is tautological. Maybe it's shut
        // up.
        assert_eq!(data.to_bytes(), reconstructed_data.to_bytes());
    }

    /// Tests that the serde's deserialize function undoes whatever serde's serialize function does
    macro_rules! test_serde_roundtrip {
        ($test_name:ident, $kem:ty) => {
            #[test]
            fn $test_name() {
                type A = AesGcm128;
                type Kdf = HkdfSha256;
                type Kem = $kem;

                let mut csprng = StdRng::from_entropy();

                let info = b"my wallet";
                let mut plaintext = *b"DJ turn it up, that's my track right there";

                // Do a whole bunch of stuff to generate a valid session. All we care about is that
                // this gives us a pubkey, secret key, and encapped key to test serde on
                let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);
                let (psk, psk_id) = (gen_rand_buf(), gen_rand_buf());
                let (sender_mode, _) =
                    new_op_mode_pair::<Kdf, Kem>(OpModeKind::Base, &psk, &psk_id);
                let (encapped_key, mut aead_ctx) =
                    setup_sender::<A, Kdf, Kem, _>(&sender_mode, &pk_recip, &info[..], &mut csprng)
                        .unwrap();
                let aead_tag = aead_ctx
                    .seal_in_place_detached(&mut plaintext, b"")
                    .unwrap();

                // Now see if serde behaves properly on everything that can be serialized
                assert_serde_roundtrip(&sk_recip);
                assert_serde_roundtrip(&pk_recip);
                assert_serde_roundtrip(&encapped_key);
                assert_serde_roundtrip(&aead_tag);
            }
        };
    }

    #[cfg(feature = "x25519-dalek")]
    test_serde_roundtrip!(test_serde_roundtrip_x25519, crate::kem::X25519HkdfSha256);

    #[cfg(feature = "p256")]
    test_serde_roundtrip!(test_serde_roundtrip_p256, crate::kem::DhP256HkdfSha256);
}
