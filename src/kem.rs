use crate::{
    kdf::{extract_and_expand, Kdf as KdfTrait},
    kex::{Deserializable, KeyExchange, Serializable, MAX_PUBKEY_SIZE},
    util::kem_suite_id,
    HpkeError,
};

use digest::FixedOutput;
use generic_array::GenericArray;
use getrandom::getrandom;

/// Defines a combination of key exchange mechanism and a KDF, which together form a KEM
pub trait Kem: Sized {
    type Kex: KeyExchange;
    #[doc(hidden)]
    type Kdf: KdfTrait;

    const KEM_ID: u16;

    /// Deterministically derives a keypair from the given input keying material
    ///
    /// Requirements
    /// ============
    /// This keying material SHOULD have as many bits of entropy as the bit length of a secret key,
    /// i.e., `8* Self::Kex::PrivateKey::size()`. For X25519 and P-256, this is 32 bytes of
    /// entropy.
    fn derive_keypair(
        ikm: &[u8],
    ) -> (
        <Self::Kex as KeyExchange>::PrivateKey,
        <Self::Kex as KeyExchange>::PublicKey,
    ) {
        let suite_id = kem_suite_id::<Self>();
        Self::Kex::derive_keypair::<Self::Kdf>(&suite_id, ikm)
    }

    /// Generates a random keypair using the given RNG
    fn gen_keypair() -> (
        <Self::Kex as KeyExchange>::PrivateKey,
        <Self::Kex as KeyExchange>::PublicKey,
    ) {
        // Make some keying material that's the size of a private key
        let mut ikm: GenericArray<
            u8,
            <<Self::Kex as KeyExchange>::PrivateKey as Serializable>::OutputSize,
        > = GenericArray::default();
        // Fill it with randomness
        getrandom(&mut ikm).unwrap();
        // Run derive_keypair using the KEM's KDF
        Self::derive_keypair(&ikm)
    }
}

// Kem is also used as a type parameter everywhere. To avoid confusion, alias it
use Kem as KemTrait;

#[cfg(feature = "x25519-dalek")]
/// Represents DHKEM(Curve25519, HKDF-SHA256)
pub struct X25519HkdfSha256 {}

#[cfg(feature = "x25519-dalek")]
impl Kem for X25519HkdfSha256 {
    type Kex = crate::kex::X25519;
    type Kdf = crate::kdf::HkdfSha256;

    // §7.1: DHKEM(X25519, HKDF-SHA256)
    const KEM_ID: u16 = 0x0020;
}

#[cfg(feature = "p256")]
/// Represents DHKEM(P256, HKDF-SHA256)
pub struct DhP256HkdfSha256 {}

#[cfg(feature = "p256")]
impl Kem for DhP256HkdfSha256 {
    type Kex = crate::kex::DhP256;
    type Kdf = crate::kdf::HkdfSha256;

    // §7.1: DHKEM(P-256, HKDF-SHA256)
    const KEM_ID: u16 = 0x0010;
}

/// Convenience types representing public/private keys corresponding to a KEM's underlying DH alg
type KemPubkey<Kem> = <<Kem as KemTrait>::Kex as KeyExchange>::PublicKey;
type KemPrivkey<Kem> = <<Kem as KemTrait>::Kex as KeyExchange>::PrivateKey;

/// Holds the content of an encapsulated secret. This is what the receiver uses to derive the
/// shared secret.
// This just wraps a pubkey, because that's all an encapsulated key is in a DH-KEM
pub struct EncappedKey<Kex: KeyExchange>(Kex::PublicKey);

// EncappedKeys need to be serializable, since they're gonna be sent over the wire. Underlyingly,
// they're just DH pubkeys, so we just serialize them the same way
impl<Kex: KeyExchange> Serializable for EncappedKey<Kex> {
    type OutputSize = <Kex::PublicKey as Serializable>::OutputSize;

    // Pass to underlying to_bytes() impl
    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        self.0.to_bytes()
    }
}

impl<Kex: KeyExchange> Deserializable for EncappedKey<Kex> {
    // Pass to underlying from_bytes() impl
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let pubkey = <Kex::PublicKey as Deserializable>::from_bytes(encoded)?;
        Ok(EncappedKey(pubkey))
    }
}

/// A convenience type representing the fixed-size byte array of the same length as a serialized
/// `KexResult`
pub(crate) type SharedSecret<Kem> =
    GenericArray<u8, <<<Kem as KemTrait>::Kdf as KdfTrait>::HashImpl as FixedOutput>::OutputSize>;

// def Encap(pkR):
//   skE, pkE = GenerateKeyPair()
//   dh = DH(skE, pkR)
//   enc = Serialize(pkE)
//
//   pkRm = Serialize(pkR)
//   kem_context = concat(enc, pkRm)
//
// def AuthEncap(pkR, skS):
//   skE, pkE = GenerateKeyPair()
//   dh = concat(DH(skE, pkR), DH(skS, pkR))
//   enc = Serialize(pkE)
//
//   pkRm = Serialize(pkR)
//   pkSm = Serialize(pk(skS))
//   kem_context = concat(enc, pkRm, pkSm)
//
//   shared_secret = ExtractAndExpand(dh, kem_context)
//   return shared_secret, enc
/// Derives a shared secret that the owner of the recipient's pubkey can use to derive the same
/// shared secret. If `sk_sender_id` is given, the sender's identity will be tied to the shared
/// secret.
///
/// Return Value
/// ============
/// Returns a shared secret and encapped key on success. If an error happened during key exchange,
/// returns `Err(HpkeError::InvalidKeyExchange)`.
pub(crate) fn encap_with_eph<Kem: KemTrait>(
    pk_recip: &KemPubkey<Kem>,
    sender_id_keypair: Option<&(KemPrivkey<Kem>, KemPubkey<Kem>)>,
    sk_eph: KemPrivkey<Kem>,
) -> Result<(SharedSecret<Kem>, EncappedKey<Kem::Kex>), HpkeError> {
    // Put together the binding context used for all KDF operations
    let suite_id = kem_suite_id::<Kem>();

    // Compute the shared secret from the ephemeral inputs
    let kex_res_eph = Kem::Kex::kex(&sk_eph, pk_recip)?;

    // The encapped key is the ephemeral pubkey
    let encapped_key = {
        let pk_eph = Kem::Kex::sk_to_pk(&sk_eph);
        EncappedKey(pk_eph)
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
        let kex_res_identity = Kem::Kex::kex(sk_sender_id, pk_recip)?;

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
        let mut buf = <SharedSecret<Kem> as Default>::default();
        extract_and_expand::<Kem>(&concatted_secrets, &suite_id, &kem_context, &mut buf)
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
        let mut buf = <SharedSecret<Kem> as Default>::default();
        extract_and_expand::<Kem>(&kex_res_eph.to_bytes(), &suite_id, &kem_context, &mut buf)
            .expect("shared secret is way too big");
        buf
    };

    Ok((shared_secret, encapped_key))
}

/// Derives a shared secret and an ephemeral pubkey that the owner of the reciepint's pubkey can
/// use to derive the same shared secret. If `sk_sender_id` is given, the sender's identity will be
/// tied to the shared secret.
/// All this does is generate an ephemeral keypair and pass to `encap_with_eph`.
///
/// Return Value
/// ============
/// Returns a shared secret and encapped key on success. If an error happened during key exchange,
/// returns `Err(HpkeError::InvalidKeyExchange)`.
pub(crate) fn encap<Kem: KemTrait>(
    pk_recip: &KemPubkey<Kem>,
    sender_id_keypair: Option<&(KemPrivkey<Kem>, KemPubkey<Kem>)>,
) -> Result<(SharedSecret<Kem>, EncappedKey<Kem::Kex>), HpkeError>
where
    Kem: KemTrait,
{
    // Generate a new ephemeral keypair
    let (sk_eph, _) = Kem::gen_keypair();
    // Now pass to encap_with_eph
    encap_with_eph::<Kem>(pk_recip, sender_id_keypair, sk_eph)
}

// def Decap(enc, skR):
//   pkE = Deserialize(enc)
//   dh = DH(skR, pkE)
//
//   pkRm = Serialize(pk(skR))
//   kem_context = concat(enc, pkRm)
//
//   shared_secret = ExtractAndExpand(dh, kem_context)
//   return shared_secret
//
// def AuthDecap(enc, skR, pkS):
//   pkE = Deserialize(enc)
//   dh = concat(DH(skR, pkE), DH(skR, pkS))
//
//   pkRm = Serialize(pk(skR))
//   pkSm = Serialize(pkS)
//   kem_context = concat(enc, pkRm, pkSm)
//
//   shared_secret = ExtractAndExpand(dh, kem_context)
//   return shared_secret
/// Derives a shared secret given the encapsulated key and the recipients secret key. If
/// `pk_sender_id` is given, the sender's identity will be tied to the shared secret.
///
/// Return Value
/// ============
/// Returns a shared secret on success. If an error happened during key exchange, returns
/// `Err(HpkeError::InvalidKeyExchange)`.
pub(crate) fn decap<Kem: KemTrait>(
    sk_recip: &KemPrivkey<Kem>,
    pk_sender_id: Option<&KemPubkey<Kem>>,
    encapped_key: &EncappedKey<Kem::Kex>,
) -> Result<SharedSecret<Kem>, HpkeError> {
    // Put together the binding context used for all KDF operations
    let suite_id = kem_suite_id::<Kem>();

    // Compute the shared secret from the ephemeral inputs
    let kex_res_eph = Kem::Kex::kex(&sk_recip, &encapped_key.0)?;

    // Compute the sender's pubkey from their privkey
    let pk_recip = Kem::Kex::sk_to_pk(sk_recip);

    // The shared secret is either gonna be kex_res_eph, or that along with another shared secret
    // that's tied to the sender's identity.
    if let Some(pk_sender_id) = pk_sender_id {
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
        let kex_res_identity = Kem::Kex::kex(sk_recip, pk_sender_id)?;

        // concatted_secrets = kex_res_eph || kex_res_identity
        // Same no-alloc concat trick as above
        let (concatted_secrets_buf, concatted_secret_size) = concat_with_known_maxlen!(
            MAX_PUBKEY_SIZE,
            &kex_res_eph.to_bytes(),
            &kex_res_identity.to_bytes()
        );
        let concatted_secrets = &concatted_secrets_buf[..concatted_secret_size];

        // The "authed shared secret" is derived from the KEX of the ephemeral input with the
        // recipient pubkey, and the kex of the identity input with the recipient pubkey. The
        // HKDF-Expand call only errors if the output values are 255x the digest size of the hash
        // function. Since these values are fixed at compile time, we don't worry about it.
        let mut shared_secret = <SharedSecret<Kem> as Default>::default();
        extract_and_expand::<Kem>(
            &concatted_secrets,
            &suite_id,
            &kem_context,
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

        // The "unauthed shared secret" is derived from just the KEX of the ephemeral input with the
        // recipient pubkey. The HKDF-Expand call only errors if the output values are 255x the
        // digest size of the hash function. Since these values are fixed at compile time, we don't
        // worry about it.
        let mut shared_secret = <SharedSecret<Kem> as Default>::default();
        extract_and_expand::<Kem>(
            &kex_res_eph.to_bytes(),
            &suite_id,
            &kem_context,
            &mut shared_secret,
        )
        .expect("shared secret is way too big");
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use crate::kem::{decap, encap, Deserializable, EncappedKey, Kem as KemTrait, Serializable};

    macro_rules! test_encap_correctness {
        ($test_name:ident, $kem_ty:ty) => {
            /// Tests that encap and decap produce the same shared secret when composed
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let (sk_recip, pk_recip) = Kem::gen_keypair();

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) = encap::<Kem>(&pk_recip, None).unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    decap::<Kem>(&sk_recip, None, &encapped_key).unwrap();

                // Ensure that the encapsulated secret is what decap() derives
                assert_eq!(auth_shared_secret, decapped_auth_shared_secret);

                //
                // Now do it with the auth, i.e., using the sender's identity keys
                //

                // Make a sender identity keypair
                let (sk_sender_id, pk_sender_id) = Kem::gen_keypair();

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) =
                    encap::<Kem>(&pk_recip, Some(&(sk_sender_id, pk_sender_id.clone()))).unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    decap::<Kem>(&sk_recip, Some(&pk_sender_id), &encapped_key).unwrap();

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
                    let (_, pk_recip) = Kem::gen_keypair();
                    encap::<Kem>(&pk_recip, None).unwrap().1
                };
                // Serialize it
                let encapped_key_bytes = encapped_key.to_bytes();
                // Deserialize it
                let new_encapped_key =
                    EncappedKey::<<Kem as KemTrait>::Kex>::from_bytes(&encapped_key_bytes).unwrap();

                assert!(
                    new_encapped_key.0 == encapped_key.0,
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
