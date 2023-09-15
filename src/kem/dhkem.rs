/// Defines DHKEM(G, K) given a Diffie-Hellman group G and KDF K
macro_rules! impl_dhkem {
    (
        $mod_name:ident,
        $kem_name:ident,
        $dhkex:ty,
        $kdf:ty,
        $kem_id:literal,
        $doc_str:expr
    ) => {
        pub use $mod_name::$kem_name;

        pub(crate) mod $mod_name {
            use crate::{
                dhkex::{DhKeyExchange, MAX_PUBKEY_SIZE},
                kdf::{extract_and_expand, Kdf as KdfTrait},
                kem::{Kem as KemTrait, SharedSecret},
                util::kem_suite_id,
                Deserializable, HpkeError, Serializable,
            };

            use digest::OutputSizeUser;
            use generic_array::GenericArray;
            use rand_core::{CryptoRng, RngCore};

            // Define convenience types
            type PublicKey = <$dhkex as DhKeyExchange>::PublicKey;
            type PrivateKey = <$dhkex as DhKeyExchange>::PrivateKey;

            // RFC 9180 §4.1
            // The function parameters pkR and pkS are deserialized public keys, and enc is a
            // serialized public key. Since encapsulated keys are Diffie-Hellman public keys in
            // this KEM algorithm, we use SerializePublicKey() and DeserializePublicKey() to
            // encode and decode them, respectively. Npk equals Nenc.

            /// Holds the content of an encapsulated secret. This is what the receiver uses to
            /// derive the shared secret. This just wraps a pubkey, because that's all an
            /// encapsulated key is in a DHKEM.
            #[doc(hidden)]
            #[derive(Clone)]
            pub struct EncappedKey(pub(crate) <$dhkex as DhKeyExchange>::PublicKey);

            // EncappedKeys need to be serializable, since they're gonna be sent over the wire.
            // Underlyingly, they're just DH pubkeys, so we just serialize them the same way
            impl Serializable for EncappedKey {
                type OutputSize = <<$dhkex as DhKeyExchange>::PublicKey as Serializable>::OutputSize;

                // Pass to underlying to_bytes() impl
                fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
                    self.0.to_bytes()
                }
            }

            impl Deserializable for EncappedKey {
                // Pass to underlying from_bytes() impl
                fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                    let pubkey =
                        <<$dhkex as DhKeyExchange>::PublicKey as Deserializable>::from_bytes(encoded)?;
                    Ok(EncappedKey(pubkey))
                }
            }

            // Define the KEM struct
            #[doc = $doc_str]
            pub struct $kem_name;

            // RFC 9180 §4.1
            // def Encap(pkR):
            //   skE, pkE = GenerateKeyPair()
            //   dh = DH(skE, pkR)
            //   enc = SerializePublicKey(pkE)
            //
            //   pkRm = SerializePublicKey(pkR)
            //   kem_context = concat(enc, pkRm)
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

            // The reason we define encap_with_eph() rather than just encap() is because we need to
            // use deterministic ephemeral keys in the known-answer tests. So we define a function
            // here, then use it to impl kem::Kem and kat_tests::TestableKem.

            /// Derives a shared secret that the owner of the recipient's pubkey can use to derive
            /// the same shared secret. If `sk_sender_id` is given, the sender's identity will be
            /// tied to the shared secret.
            ///
            /// Return Value
            /// ============
            /// Returns a shared secret and encapped key on success. If an error happened during
            /// key exchange, returns `Err(HpkeError::EncapError)`.
            #[doc(hidden)]
            pub(crate) fn encap_with_eph(
                pk_recip: &PublicKey,
                sender_id_keypair: Option<(&PrivateKey, &PublicKey)>,
                sk_eph: PrivateKey,
            ) -> Result<(SharedSecret<$kem_name>, EncappedKey), HpkeError> {
                // Put together the binding context used for all KDF operations
                let suite_id = kem_suite_id::<$kem_name>();

                // Compute the shared secret from the ephemeral inputs
                let kex_res_eph = <$dhkex as DhKeyExchange>::dh(&sk_eph, pk_recip)
                    .map_err(|_| HpkeError::EncapError)?;

                // The encapped key is the ephemeral pubkey
                let encapped_key = {
                    let pk_eph = <$kem_name as KemTrait>::sk_to_pk(&sk_eph);
                    EncappedKey(pk_eph)
                };

                // The shared secret is either gonna be kex_res_eph, or that along with another
                // shared secret that's tied to the sender's identity.
                let shared_secret = if let Some((sk_sender_id, pk_sender_id)) = sender_id_keypair {
                    // kem_context = encapped_key || pk_recip || pk_sender_id
                    // We concat without allocation by making a buffer of the maximum possible
                    // size, then taking the appropriately sized slice.
                    let (kem_context_buf, kem_context_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &encapped_key.to_bytes(),
                        &pk_recip.to_bytes(),
                        &pk_sender_id.to_bytes()
                    );
                    let kem_context = &kem_context_buf[..kem_context_size];

                    // We want to do an authed encap. Do a DH exchange between the sender identity
                    // secret key and the recipient's pubkey
                    let kex_res_identity = <$dhkex as DhKeyExchange>::dh(sk_sender_id, pk_recip)
                        .map_err(|_| HpkeError::EncapError)?;

                    // concatted_secrets = kex_res_eph || kex_res_identity
                    // Same no-alloc concat trick as above
                    let (concatted_secrets_buf, concatted_secret_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &kex_res_eph.to_bytes(),
                        &kex_res_identity.to_bytes()
                    );
                    let concatted_secrets = &concatted_secrets_buf[..concatted_secret_size];

                    // The "authed shared secret" is derived from the KEX of the ephemeral input
                    // with the recipient pubkey, and the KEX of the identity input with the
                    // recipient pubkey. The HKDF-Expand call only errors if the output values are
                    // 255x the digest size of the hash function. Since these values are fixed at
                    // compile time, we don't worry about it.
                    let mut buf = <SharedSecret<$kem_name> as Default>::default();
                    extract_and_expand::<$kdf>(concatted_secrets, &suite_id, kem_context, &mut buf.0)
                        .expect("shared secret is way too big");
                    buf
                } else {
                    // kem_context = encapped_key || pk_recip
                    // We concat without allocation by making a buffer of the maximum possible
                    // size, then taking the appropriately sized slice.
                    let (kem_context_buf, kem_context_size) = concat_with_known_maxlen!(
                        MAX_PUBKEY_SIZE,
                        &encapped_key.to_bytes(),
                        &pk_recip.to_bytes()
                    );
                    let kem_context = &kem_context_buf[..kem_context_size];

                    // The "unauthed shared secret" is derived from just the KEX of the ephemeral
                    // input with the recipient pubkey. The HKDF-Expand call only errors if the
                    // output values are 255x the digest size of the hash function. Since these
                    // values are fixed at compile time, we don't worry about it.
                    let mut buf = <SharedSecret<$kem_name> as Default>::default();
                    extract_and_expand::<$kdf>(
                        &kex_res_eph.to_bytes(),
                        &suite_id,
                        kem_context,
                        &mut buf.0,
                    )
                    .expect("shared secret is way too big");
                    buf
                };

                Ok((shared_secret, encapped_key))
            }

            impl KemTrait for $kem_name {
                // RFC 9180 §4.1
                // For the variants of DHKEM defined in this document, the size Nsecret of the
                // KEM shared secret is equal to the output length of the hash function underlying
                // the KDF.

                /// The size of the shared secret at the end of the key exchange process
                #[doc(hidden)]
                type NSecret = <<$kdf as KdfTrait>::HashImpl as OutputSizeUser>::OutputSize;

                type PublicKey = PublicKey;
                type PrivateKey = PrivateKey;
                type EncappedKey = EncappedKey;

                const KEM_ID: u16 = $kem_id;

                /// Deterministically derives a keypair from the given input keying material
                ///
                /// Requirements
                /// ============
                /// This keying material SHOULD have as many bits of entropy as the bit length of a
                /// secret key, i.e., `8 * Self::PrivateKey::size()`. For X25519 and P-256, this is
                /// 256 bits of entropy.
                fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
                    let suite_id = kem_suite_id::<Self>();
                    <$dhkex as DhKeyExchange>::derive_keypair::<$kdf>(&suite_id, ikm)
                }

                /// Computes the public key of a given private key
                fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
                    <$dhkex as DhKeyExchange>::sk_to_pk(sk)
                }

                // Runs encap_with_eph using a random ephemeral key
                fn encap<R: CryptoRng + RngCore>(
                    pk_recip: &Self::PublicKey,
                    sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
                    csprng: &mut R,
                ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
                    // Generate a new ephemeral key
                    let (sk_eph, _) = Self::gen_keypair(csprng);
                    // Now pass to encap_with_eph()
                    encap_with_eph(pk_recip, sender_id_keypair, sk_eph)
                }

                // RFC 9180 §4.1
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
                    let kex_res_eph = <$dhkex as DhKeyExchange>::dh(sk_recip, &encapped_key.0)
                        .map_err(|_| HpkeError::DecapError)?;

                    // Compute the sender's pubkey from their privkey
                    let pk_recip = <$dhkex as DhKeyExchange>::sk_to_pk(sk_recip);

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

                        // We want to do an authed encap. Do a DH exchange between the sender identity
                        // secret key and the recipient's pubkey
                        let kex_res_identity = <$dhkex as DhKeyExchange>::dh(sk_recip, pk_sender_id)
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
                        extract_and_expand::<$kdf>(
                            concatted_secrets,
                            &suite_id,
                            kem_context,
                            &mut shared_secret.0,
                        )
                        .expect("shared secret is way too big");
                        Ok(shared_secret)
                    } else {
                        // kem_context = encapped_key || pk_recip || pk_sender_id
                        // We concat without allocation by making a buffer of the maximum possible
                        // size, then taking the appropriately sized slice.
                        let (kem_context_buf, kem_context_size) = concat_with_known_maxlen!(
                            MAX_PUBKEY_SIZE,
                            &encapped_key.to_bytes(),
                            &pk_recip.to_bytes()
                        );
                        let kem_context = &kem_context_buf[..kem_context_size];

                        // The "unauthed shared secret" is derived from just the KEX of the ephemeral
                        // input with the recipient pubkey. The HKDF-Expand call only errors if the
                        // output values are 255x the digest size of the hash function. Since these
                        // values are fixed at compile time, we don't worry about it.
                        let mut shared_secret = <SharedSecret<Self> as Default>::default();
                        extract_and_expand::<$kdf>(
                            &kex_res_eph.to_bytes(),
                            &suite_id,
                            kem_context,
                            &mut shared_secret.0,
                        )
                        .expect("shared secret is way too big");
                        Ok(shared_secret)
                    }
                }
            }
        }
    };
}

// Implement DHKEM(X25519, HKDF-SHA256)
#[cfg(feature = "x25519")]
impl_dhkem!(
    x25519_hkdfsha256,
    X25519HkdfSha256,
    crate::dhkex::x25519::X25519,
    crate::kdf::HkdfSha256,
    0x0020,
    "Represents DHKEM(X25519, HKDF-SHA256)"
);

// Implement DHKEM(P-256, HKDF-SHA256)
#[cfg(feature = "p256")]
impl_dhkem!(
    dhp256_hkdfsha256,
    DhP256HkdfSha256,
    crate::dhkex::ecdh_nistp::p256::DhP256,
    crate::kdf::HkdfSha256,
    0x0010,
    "Represents DHKEM(P-256, HKDF-SHA256)"
);

// Implement DHKEM(P-384, HKDF-SHA384)
#[cfg(feature = "p384")]
impl_dhkem!(
    dhp384_hkdfsha384,
    DhP384HkdfSha384,
    crate::dhkex::ecdh_nistp::p384::DhP384,
    crate::kdf::HkdfSha384,
    0x0011,
    "Represents DHKEM(P-384, HKDF-SHA384)"
);
