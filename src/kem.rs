use crate::{
    kdf::{extract_and_expand, Kdf as KdfTrait},
    kex::{KeyExchange, MAX_PUBKEY_SIZE},
    util::kem_suite_id,
    Deserializable, HpkeError, Serializable,
};

use digest::FixedOutput;
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde_impls")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// Defines a combination of key exchange mechanism and a KDF, which together form a KEM
pub trait Kem: Sized {
    /// The key exchange's public key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(feature = "serde_impls")]
    type PublicKey: Clone
        + Serializable
        + Deserializable
        + SerdeSerialize
        + for<'a> SerdeDeserialize<'a>;
    /// The key exchange's public key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(not(feature = "serde_impls"))]
    type PublicKey: Clone + Serializable + Deserializable;

    /// The key exchange's private key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(feature = "serde_impls")]
    type PrivateKey: Clone
        + Serializable
        + Deserializable
        + SerdeSerialize
        + for<'a> SerdeDeserialize<'a>;

    /// The key exchange's private key type. If you want to generate a keypair, see
    /// `Kem::gen_keypair` or `Kem::derive_keypair`
    #[cfg(not(feature = "serde_impls"))]
    type PrivateKey: Clone + Serializable + Deserializable;

    #[cfg(feature = "serde_impls")]
    type EncappedKey: Clone
        + Serializable
        + Deserializable
        + SerdeSerialize
        + for<'a> SerdeDeserialize<'a>;
    #[cfg(not(feature = "serde_impls"))]
    type EncappedKey: Clone + Serializable + Deserializable;

    type Kdf: KdfTrait;

    const KEM_ID: u16;

    /// Deterministically derives a keypair from the given input keying material
    ///
    /// Requirements
    /// ============
    /// This keying material SHOULD have as many bits of entropy as the bit length of a secret key,
    /// i.e., `8 * Self::Kex::PrivateKey::size()`. For X25519 and P-256, this is 256 bits of
    /// entropy.
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey);

    /// Generates a random keypair using the given RNG
    fn gen_keypair<R: CryptoRng + RngCore>(csprng: &mut R) -> (Self::PrivateKey, Self::PublicKey);

    #[doc(hidden)]
    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    /// Derives a shared secret that the owner of the recipient's pubkey can use to derive the same
    /// shared secret. If `sk_sender_id` is given, the sender's identity will be tied to the shared
    /// secret.
    ///
    /// Return Value
    /// ============
    /// Returns a shared secret and encapped key on success. If an error happened during key exchange,
    /// returns `Err(HpkeError::EncapError)`.
    #[doc(hidden)]
    fn encap_with_eph(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<&(Self::PrivateKey, Self::PublicKey)>,
        sk_eph: Self::PrivateKey,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError>;

    /// Derives a shared secret given the encapsulated key and the recipients secret key. If
    /// `pk_sender_id` is given, the sender's identity will be tied to the shared secret.
    ///
    /// Return Value
    /// ============
    /// Returns a shared secret on success. If an error happened during key exchange, returns
    /// `Err(HpkeError::DecapError)`.
    #[doc(hidden)]
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError>;

    /// Derives a shared secret and an ephemeral pubkey that the owner of the reciepint's pubkey can
    /// use to derive the same shared secret. If `sk_sender_id` is given, the sender's identity will be
    /// tied to the shared secret.
    /// All this does is generate an ephemeral keypair and pass to `encap_with_eph`.
    ///
    /// Return Value
    /// ============
    /// Returns a shared secret and encapped key on success. If an error happened during key exchange,
    /// returns `Err(HpkeError::EncapError)`.
    #[doc(hidden)]
    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<&(Self::PrivateKey, Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        // Generate a new ephemeral keypair
        let (sk_eph, _) = Self::gen_keypair(csprng);
        // Now pass to encap_with_eph
        Self::encap_with_eph(pk_recip, sender_id_keypair, sk_eph)
    }
}

/// Defines a combination of key exchange mechanism and a KDF, which together form a KEM
macro_rules! impl_dhkem {
    ($kem_name:ident, $encapped_key:ident, $dhkex:ty, $dh_pubkey:ty, $dh_privkey:ty, $kdf:ty, $kem_id:literal) => {
        pub struct $kem_name;

        /// Holds the content of an encapsulated secret. This is what the receiver uses to derive
        /// the shared secret.
        // This just wraps a pubkey, because that's all an encapsulated key is in a DH-KEM
        #[doc(hidden)]
        #[derive(Clone)]
        pub struct $encapped_key(<$dhkex as KeyExchange>::PublicKey);

        // EncappedKeys need to be serializable, since they're gonna be sent over the wire. Underlyingly,
        // they're just DH pubkeys, so we just serialize them the same way
        impl Serializable for $encapped_key {
            type OutputSize = <<$dhkex as KeyExchange>::PublicKey as Serializable>::OutputSize;

            // Pass to underlying to_bytes() impl
            fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
                self.0.to_bytes()
            }
        }

        impl Deserializable for $encapped_key {
            // Pass to underlying from_bytes() impl
            fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                let pubkey =
                    <<$dhkex as KeyExchange>::PublicKey as Deserializable>::from_bytes(encoded)?;
                Ok($encapped_key(pubkey))
            }
        }

        impl KemTrait for $kem_name {
            #[doc(hidden)]
            type Kdf = $kdf;

            type PublicKey = $dh_pubkey;
            type PrivateKey = $dh_privkey;
            type EncappedKey = $encapped_key;
            const KEM_ID: u16 = $kem_id;

            /// Deterministically derives a keypair from the given input keying material
            ///
            /// Requirements
            /// ============
            /// This keying material SHOULD have as many bits of entropy as the bit length of a secret key,
            /// i.e., `8 * Self::Kex::PrivateKey::size()`. For X25519 and P-256, this is 256 bits of
            /// entropy.
            fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
                let suite_id = kem_suite_id::<Self>();
                <$dhkex as KeyExchange>::derive_keypair::<Self::Kdf>(&suite_id, ikm)
            }

            /// Generates a random keypair using the given RNG
            fn gen_keypair<R: CryptoRng + RngCore>(
                csprng: &mut R,
            ) -> (Self::PrivateKey, Self::PublicKey) {
                // Make some keying material that's the size of a private key
                let mut ikm: GenericArray<u8, <Self::PrivateKey as Serializable>::OutputSize> =
                    GenericArray::default();
                // Fill it with randomness
                csprng.fill_bytes(&mut ikm);
                // Run derive_keypair using the KEM's KDF
                Self::derive_keypair(&ikm)
            }

            #[doc(hidden)]
            fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
                <$dhkex as KeyExchange>::sk_to_pk(sk)
            }

            // draft11 §4.1
            // def Encap(pkR):
            //   skE, pkE = GenerateKeyPair()
            //   dh = DH(skE, pkR)
            //   enc = SerializePublicKey(pkE)
            //
            //   pkRm = SerializePublicKey(pkR)
            //   kem_context = concat(enc, pkRm)
            //
            //   shared_secret = ExtractAndExpand(dh, kem_context)
            //   return shared_secret, enc
            //
            // def AuthEncap(pkR, skS):
            //   skE, pkE = GenerateKeyPair()
            //   dh = concat(DH(skE, pkR), DH(skS, pkR))
            //   enc = SerializePublicKey(pkE)
            //
            //   pkRm = SerializePublicKey(pkR)
            //   pkSm = SerializePublicKey(pk(skS))
            //   kem_context = concat(enc, pkRm, pkSm)
            //
            //   shared_secret = ExtractAndExpand(dh, kem_context)
            //   return shared_secret, enc

            /// Derives a shared secret that the owner of the recipient's pubkey can use to derive
            /// the same shared secret. If `sk_sender_id` is given, the sender's identity will be
            /// tied to the shared secret.
            ///
            /// Return Value
            /// ============
            /// Returns a shared secret and encapped key on success. If an error happened during
            /// key exchange, returns `Err(HpkeError::EncapError)`.
            #[doc(hidden)]
            fn encap_with_eph(
                pk_recip: &Self::PublicKey,
                sender_id_keypair: Option<&(Self::PrivateKey, Self::PublicKey)>,
                sk_eph: Self::PrivateKey,
            ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
                // Put together the binding context used for all KDF operations
                let suite_id = kem_suite_id::<Self>();

                // Compute the shared secret from the ephemeral inputs
                let kex_res_eph = <$dhkex as KeyExchange>::kex(&sk_eph, pk_recip)
                    .map_err(|_| HpkeError::EncapError)?;

                // The encapped key is the ephemeral pubkey
                let encapped_key = {
                    let pk_eph = <$dhkex as KeyExchange>::sk_to_pk(&sk_eph);
                    $encapped_key(pk_eph)
                };

                // The shared secret is either gonna be kex_res_eph, or that along with another shared secret
                // that's tied to the sender's identity.
                let shared_secret = if let Some((sk_sender_id, pk_sender_id)) = sender_id_keypair {
                    // kem_context = encapped_key || pk_recip || pk_sender_id
                    // We concat without allocation by making a buffer of the maximum possible size, then
                    // taking the appropriately sized slice.
                    let (kem_context_buf, kem_context_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &encapped_key.to_bytes(),
                        &pk_recip.to_bytes(),
                        &pk_sender_id.to_bytes()
                    );
                    let kem_context = &kem_context_buf[..kem_context_size];

                    // We want to do an authed encap. Do KEX between the sender identity secret key and the
                    // recipient's pubkey
                    let kex_res_identity = <$dhkex as KeyExchange>::kex(sk_sender_id, pk_recip)
                        .map_err(|_| HpkeError::EncapError)?;

                    // concatted_secrets = kex_res_eph || kex_res_identity
                    // Same no-alloc concat trick as above
                    let (concatted_secrets_buf, concatted_secret_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &kex_res_eph.to_bytes(),
                        &kex_res_identity.to_bytes()
                    );
                    let concatted_secrets = &concatted_secrets_buf[..concatted_secret_size];

                    // The "authed shared secret" is derived from the KEX of the ephemeral input with the
                    // recipient pubkey, and the KEX of the identity input with the recipient pubkey. The
                    // HKDF-Expand call only errors if the output values are 255x the digest size of the hash
                    // function. Since these values are fixed at compile time, we don't worry about it.
                    let mut buf = <SharedSecret<Self> as Default>::default();
                    extract_and_expand::<Self>(concatted_secrets, &suite_id, kem_context, &mut buf)
                        .expect("shared secret is way too big");
                    buf
                } else {
                    // kem_context = encapped_key || pk_recip
                    // We concat without allocation by making a buffer of the maximum possible size, then
                    // taking the appropriately sized slice.
                    let (kem_context_buf, kem_context_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &encapped_key.to_bytes(),
                        &pk_recip.to_bytes()
                    );
                    let kem_context = &kem_context_buf[..kem_context_size];

                    // The "unauthed shared secret" is derived from just the KEX of the ephemeral input with
                    // the recipient pubkey. The HKDF-Expand call only errors if the output values are 255x the
                    // digest size of the hash function. Since these values are fixed at compile time, we don't
                    // worry about it.
                    let mut buf = <SharedSecret<Self> as Default>::default();
                    extract_and_expand::<Self>(
                        &kex_res_eph.to_bytes(),
                        &suite_id,
                        kem_context,
                        &mut buf,
                    )
                    .expect("shared secret is way too big");
                    buf
                };

                Ok((shared_secret, encapped_key))
            }

            // draft11 §4.1
            // def Decap(enc, skR):
            //   pkE = DeserializePublicKey(enc)
            //   dh = DH(skR, pkE)
            //
            //   pkRm = SerializePublicKey(pk(skR))
            //   kem_context = concat(enc, pkRm)
            //
            //   shared_secret = ExtractAndExpand(dh, kem_context)
            //   return shared_secret
            //
            // def AuthDecap(enc, skR, pkS):
            //   pkE = DeserializePublicKey(enc)
            //   dh = concat(DH(skR, pkE), DH(skR, pkS))
            //
            //   pkRm = SerializePublicKey(pk(skR))
            //   pkSm = SerializePublicKey(pkS)
            //   kem_context = concat(enc, pkRm, pkSm)
            //
            //   shared_secret = ExtractAndExpand(dh, kem_context)
            //   return shared_secret

            /// Derives a shared secret given the encapsulated key and the recipients secret key.
            /// If `pk_sender_id` is given, the sender's identity will be tied to the shared
            /// secret.
            ///
            /// Return Value
            /// ============
            /// Returns a shared secret on success. If an error happened during key exchange,
            /// returns `Err(HpkeError::DecapError)`.
            #[doc(hidden)]
            fn decap(
                sk_recip: &Self::PrivateKey,
                pk_sender_id: Option<&Self::PublicKey>,
                encapped_key: &Self::EncappedKey,
            ) -> Result<SharedSecret<Self>, HpkeError> {
                // Put together the binding context used for all KDF operations
                let suite_id = kem_suite_id::<Self>();

                // Compute the shared secret from the ephemeral inputs
                let kex_res_eph = <$dhkex as KeyExchange>::kex(sk_recip, &encapped_key.0)
                    .map_err(|_| HpkeError::DecapError)?;

                // Compute the sender's pubkey from their privkey
                let pk_recip = <$dhkex as KeyExchange>::sk_to_pk(sk_recip);

                // The shared secret is either gonna be kex_res_eph, or that along with another
                // shared secret that's tied to the sender's identity.
                if let Some(pk_sender_id) = pk_sender_id {
                    // kem_context = encapped_key || pk_recip || pk_sender_id We concat without
                    // allocation by making a buffer of the maximum possible size, then taking the
                    // appropriately sized slice.
                    let (kem_context_buf, kem_context_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &encapped_key.to_bytes(),
                        &pk_recip.to_bytes(),
                        &pk_sender_id.to_bytes()
                    );
                    let kem_context = &kem_context_buf[..kem_context_size];

                    // We want to do an authed encap. Do KEX between the sender identity secret key
                    // and the recipient's pubkey
                    let kex_res_identity = <$dhkex as KeyExchange>::kex(sk_recip, pk_sender_id)
                        .map_err(|_| HpkeError::DecapError)?;

                    // concatted_secrets = kex_res_eph || kex_res_identity
                    // Same no-alloc concat trick as above
                    let (concatted_secrets_buf, concatted_secret_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &kex_res_eph.to_bytes(),
                        &kex_res_identity.to_bytes()
                    );
                    let concatted_secrets = &concatted_secrets_buf[..concatted_secret_size];

                    // The "authed shared secret" is derived from the KEX of the ephemeral input
                    // with the recipient pubkey, and the kex of the identity input with the
                    // recipient pubkey. The HKDF-Expand call only errors if the output values are
                    // 255x the digest size of the hash function. Since these values are fixed at
                    // compile time, we don't worry about it.
                    let mut shared_secret = <SharedSecret<Self> as Default>::default();
                    extract_and_expand::<Self>(
                        concatted_secrets,
                        &suite_id,
                        kem_context,
                        &mut shared_secret,
                    )
                    .expect("shared secret is way too big");
                    Ok(shared_secret)
                } else {
                    // kem_context = encapped_key || pk_recip || pk_sender_id
                    // We concat without allocation by making a buffer of the maximum possible size, then
                    // taking the appropriately sized slice.
                    let (kem_context_buf, kem_context_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &encapped_key.to_bytes(),
                        &pk_recip.to_bytes()
                    );
                    let kem_context = &kem_context_buf[..kem_context_size];

                    // The "unauthed shared secret" is derived from just the KEX of the ephemeral input
                    // with the recipient pubkey. The HKDF-Expand call only errors if the output values
                    // are 255x the digest size of the hash function. Since these values are fixed at
                    // compile time, we don't worry about it.
                    let mut shared_secret = <SharedSecret<Self> as Default>::default();
                    extract_and_expand::<Self>(
                        &kex_res_eph.to_bytes(),
                        &suite_id,
                        kem_context,
                        &mut shared_secret,
                    )
                    .expect("shared secret is way too big");
                    Ok(shared_secret)
                }
            }
        }
    };
}

// Kem is also used as a type parameter everywhere. To avoid confusion, alias it
use Kem as KemTrait;

#[cfg(feature = "x25519-dalek")]
/// Represents DHKEM(X25519, HKDF-SHA256)
impl_dhkem!(
    X25519HkdfSha256,
    X25519HkdfSha256EncappedKey,
    crate::kex::x25519::X25519,
    crate::kex::x25519::PublicKey,
    crate::kex::x25519::PrivateKey,
    crate::kdf::HkdfSha256,
    0x0020
);

#[cfg(feature = "p256")]
/// Represents DHKEM(P-256, HKDF-SHA256)
impl_dhkem!(
    DhP256HkdfSha256,
    DhP256HkdfSha256EncappedKey,
    crate::kex::ecdh_nistp::DhP256,
    crate::kex::ecdh_nistp::PublicKey,
    crate::kex::ecdh_nistp::PrivateKey,
    crate::kdf::HkdfSha256,
    0x0010
);

/// A convenience type representing the fixed-size byte array of the same length as a serialized
/// `KexResult`
pub(crate) type SharedSecret<Kem> =
    GenericArray<u8, <<<Kem as KemTrait>::Kdf as KdfTrait>::HashImpl as FixedOutput>::OutputSize>;

#[cfg(test)]
mod tests {
    use crate::{kem::Kem as KemTrait, Deserializable, Serializable};

    use rand::{rngs::StdRng, SeedableRng};

    macro_rules! test_encap_correctness {
        ($test_name:ident, $kem_ty:ty) => {
            /// Tests that encap and decap produce the same shared secret when composed
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let mut csprng = StdRng::from_entropy();
                let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) =
                    Kem::encap(&pk_recip, None, &mut csprng).unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    Kem::decap(&sk_recip, None, &encapped_key).unwrap();

                // Ensure that the encapsulated secret is what decap() derives
                assert_eq!(auth_shared_secret, decapped_auth_shared_secret);

                //
                // Now do it with the auth, i.e., using the sender's identity keys
                //

                // Make a sender identity keypair
                let (sk_sender_id, pk_sender_id) = Kem::gen_keypair(&mut csprng);

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) = Kem::encap(
                    &pk_recip,
                    Some(&(sk_sender_id, pk_sender_id.clone())),
                    &mut csprng,
                )
                .unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    Kem::decap(&sk_recip, Some(&pk_sender_id), &encapped_key).unwrap();

                // Ensure that the encapsulated secret is what decap() derives
                assert_eq!(auth_shared_secret, decapped_auth_shared_secret);
            }
        };
    }

    /// Tests that an deserialize-serialize round trip on an encapped key ends up at the same value
    macro_rules! test_encapped_serialize {
        ($test_name:ident, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                // Encapsulate a random shared secret
                let encapped_key = {
                    let mut csprng = StdRng::from_entropy();
                    let (_, pk_recip) = Kem::gen_keypair(&mut csprng);
                    Kem::encap(&pk_recip, None, &mut csprng).unwrap().1
                };
                // Serialize it
                let encapped_key_bytes = encapped_key.to_bytes();
                // Deserialize it
                let new_encapped_key =
                    <<Kem as KemTrait>::EncappedKey as Deserializable>::from_bytes(
                        &encapped_key_bytes,
                    )
                    .unwrap();

                assert_eq!(
                    new_encapped_key.0, encapped_key.0,
                    "encapped key doesn't serialize correctly"
                );
            }
        };
    }

    #[cfg(feature = "x25519-dalek")]
    mod x25519_tests {
        use super::*;

        test_encap_correctness!(test_encap_correctness_x25519, crate::kem::X25519HkdfSha256);
        test_encapped_serialize!(test_encapped_serialize_x25519, crate::kem::X25519HkdfSha256);
    }

    #[cfg(feature = "p256")]
    mod p256_tests {
        use super::*;

        test_encap_correctness!(test_encap_correctness_p256, crate::kem::DhP256HkdfSha256);
        test_encapped_serialize!(test_encapped_serialize_p256, crate::kem::DhP256HkdfSha256);
    }
}
