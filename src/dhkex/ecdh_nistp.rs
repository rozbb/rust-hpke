use crate::{
    dhkex::{DhKeyExchange, KemSuiteId},
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
};
use generic_array::{
    typenum::{U32, U48, U65, U97},
    GenericArray,
};

macro_rules! nistp_dhkex {
    ($dhname:ident, $mod:ident, $curve:ident, $pubkey_size:ty, $privkey_size:ty, $ss_size:ty, $keygen_bitmask:expr) => {
        pub(crate) mod $mod {
            use super::*;

            use crate::{
                dhkex::{DhError, DhKeyExchange},
                kdf::Kdf as KdfTrait,
                util::{enforce_equal_len, KemSuiteId},
                Deserializable, HpkeError, Serializable,
            };

            use ::$curve as curve_crate;

            use curve_crate::elliptic_curve::{ecdh::diffie_hellman, sec1::ToEncodedPoint};
            use generic_array::{typenum::Unsigned, GenericArray};
            use subtle::{Choice, ConstantTimeEq};

            /// An ECDH-P256 public key. This is never the point at infinity.
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct PublicKey(curve_crate::PublicKey);

            // This is only ever constructed via its Deserializable::from_bytes, which checks for
            // the 0 value. Also, the underlying type is zeroize-on-drop.
            /// An ECDH-P256 private key. This is a scalar in the range `[1,p)` where `p` is the
            /// group order.
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

                fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
                    // SecretKeys already know how to convert to bytes
                    self.0.to_bytes()
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

                fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
                    // ecdh::SharedSecret::as_bytes returns the serialized x-coordinate
                    *self.0.raw_secret_bytes()
                }
            }

            /// Represents ECDH functionality over NIST curve P-256
            pub struct $dhname {}

            impl DhKeyExchange for $dhname {
                #[doc(hidden)]
                type PublicKey = PublicKey;
                #[doc(hidden)]
                type PrivateKey = PrivateKey;
                #[doc(hidden)]
                type KexResult = KexResult;

                /// Converts an P256 private key to a public key
                #[doc(hidden)]
                fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
                    // pk = sk·G where G is the generator. This maintains the invariant of the
                    // public key not being the point at infinity, since ord(G) = p, and sk is not
                    // 0 mod p (by the invariant we keep on PrivateKeys)
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
                    // samples in a row for p256 is 2^-8192.
                    panic!("DeriveKeyPair failed all attempts");
                }
            }
        }
    };
}

// RFC 9180 §7.1: Npk of DHKEM(P-256, HKDF-SHA256) is 65
type P256PubkeySize = U65;
// RFC 9180 §7.1: Nsk of DHKEM(P-256, HKDF-SHA256) is 32
type P256PrivkeySize = U32;
// RFC 9180 §4.1
// P-256, P-384, and P-521, the size Ndh of the Diffie-Hellman shared secret is equal to
// 32, 48, and 66, respectively, corresponding to the x-coordinate of the resulting elliptic
// curve point.
type P256SsSize = U32;
// RFC 9180 §7.1.3:
// The `bitmask` in DeriveKeyPair to be 0xFF for P-256, i.e., the mask doesn't do anything
const P256BITMASK: u8 = 0xFF;

#[cfg(feature = "p256")]
nistp_dhkex!(
    DhP256,
    p256,
    p256,
    P256PubkeySize,
    P256PrivkeySize,
    P256SsSize,
    P256BITMASK
);

// RFC 9180 §7.1: Npk of DHKEM(P-384, HKDF-SHA256) is 97
type P384PubkeySize = U97;
// RFC 9180 §7.1: Nsk of DHKEM(P-384, HKDF-SHA256) is 48
type P384PrivkeySize = U48;
// RFC 9180 §4.1
// For P-384, the size Ndh of the Diffie-Hellman shared secret is equal to 48, corresponding to the
// x-coordinate of the resulting elliptic curve point.
type P384SsSize = U48;
// RFC 9180 §7.1.3:
// The `bitmask` in DeriveKeyPair to be 0xFF for P-384, i.e., the mask doesn't do anything
const P384BITMASK: u8 = 0xFF;

#[cfg(feature = "p384")]
nistp_dhkex!(
    DhP384,
    p384,
    p384,
    P384PubkeySize,
    P384PrivkeySize,
    P384SsSize,
    P384BITMASK
);
