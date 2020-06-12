use crate::{
    kdf::{extract_and_expand, Kdf as KdfTrait},
    kex::{KeyExchange, Marshallable, Unmarshallable},
    HpkeError,
};
use digest::{generic_array::GenericArray, FixedOutput};
use rand::{CryptoRng, RngCore};

/// Defines a combination of key exchange mechanism and a KDF, which together form a KEM
pub trait Kem {
    type Kex: KeyExchange;
    type Kdf: KdfTrait;

    const KEM_ID: u16;
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

    // Section 7.1: DHKEM(Curve25519, HKDF-SHA256)
    const KEM_ID: u16 = 0x0020;
}

#[cfg(feature = "p256")]
/// Represents DHKEM(P256, HKDF-SHA256)
pub struct DhP256HkdfSha256 {}

#[cfg(feature = "p256")]
impl Kem for DhP256HkdfSha256 {
    type Kex = crate::kex::DhP256;
    type Kdf = crate::kdf::HkdfSha256;

    // Section 7.1: DHKEM(P256, HKDF-SHA256)
    const KEM_ID: u16 = 0x0010;
}

/// Convenience types representing public/private keys corresponding to a KEM's underlying DH alg
type KemPubkey<Kem> = <<Kem as KemTrait>::Kex as KeyExchange>::PublicKey;
type KemPrivkey<Kem> = <<Kem as KemTrait>::Kex as KeyExchange>::PrivateKey;

/// This holds the content of an encapsulated secret. It is output by the `encap` and `encap_auth`
/// functions.
// This just wraps a pubkey, because that's all an encapsulated key is in a DH-KEM
pub struct EncappedKey<Kex: KeyExchange>(Kex::PublicKey);

// EncappedKeys need to be serializable, since they're gonna be sent over the wire. Underlyingly,
// they're just DH pubkeys, so we just serialize them the same way
impl<Kex: KeyExchange> Marshallable for EncappedKey<Kex> {
    type OutputSize = <Kex::PublicKey as Marshallable>::OutputSize;

    // Pass to underlying marshal() impl
    fn marshal(&self) -> GenericArray<u8, Self::OutputSize> {
        self.0.marshal()
    }
}

impl<Kex: KeyExchange> Unmarshallable for EncappedKey<Kex> {
    // Pass to underlying unmarshal() impl
    fn unmarshal(encoded: &[u8]) -> Result<Self, HpkeError> {
        let pubkey = <Kex::PublicKey as Unmarshallable>::unmarshal(encoded)?;
        Ok(EncappedKey(pubkey))
    }
}

/// A convenience type representing the fixed-size byte array of the same length as a serialized
/// `KexResult`
pub(crate) type SharedSecret<Kem> =
    GenericArray<u8, <<<Kem as KemTrait>::Kdf as KdfTrait>::HashImpl as FixedOutput>::OutputSize>;

//  def Encap(pkR):
//    skE, pkE = GenerateKeyPair()
//    dh = DH(skE, pkR)
//    enc = Marshal(pkE)
//
//    pkRm = Marshal(pkR)
//    kemContext = concat(enc, pkRm)
//
//    zz = ExtractAndExpand(dh, kemContext)
//    return zz, enc
//
// def AuthEncap(pkR, skS):
//   skE, pkE = GenerateKeyPair()
//   dh = concat(DH(skE, pkR), DH(skS, pkR))
//   enc = Marshal(pkE)
//
//   pkRm = Marshal(pkR)
//   pkSm = Marshal(pk(skS))
//   kemContext = concat(enc, pkRm, pkSm)
//
//   zz = ExtractAndExpand(dh, kemContext)
//   return zz, enc
/// Derives a shared secret that the owner of the reciepint's pubkey can use to derive the same
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
        let kem_context = [
            encapped_key.marshal(),
            pk_recip.marshal(),
            pk_sender_id.marshal(),
        ]
        .concat();
        // We want to do an authed encap. Do KEX between the sender identity secret key and the
        // recipient's pubkey
        let kex_res_identity = Kem::Kex::kex(sk_sender_id, pk_recip)?;
        // kex_res_eph || kex_res_identity
        let concatted_secrets = [kex_res_eph.marshal(), kex_res_identity.marshal()].concat();

        // The "authed shared secret" is derived from the KEX of the ephemeral input with the
        // recipient pubkey, and the KEX of the identity input with the recipient pubkey. The
        // HKDF-Expand call only errors if the output values are 255x the digest size of the hash
        // function. Since these values are fixed at compile time, we don't worry about it.
        let mut buf = <SharedSecret<Kem> as Default>::default();
        extract_and_expand::<Kem::Kdf>(&concatted_secrets, &kem_context, &mut buf)
            .expect("shared secret is way too big");
        buf
    } else {
        let kem_context = [encapped_key.marshal(), pk_recip.marshal()].concat();
        // The "unauthed shared secret" is derived from just the KEX of the ephemeral input with
        // the recipient pubkey. The HKDF-Expand call only errors if the output values are 255x the
        // digest size of the hash function. Since these values are fixed at compile time, we don't
        // worry about it.
        let mut buf = <SharedSecret<Kem> as Default>::default();
        extract_and_expand::<Kem::Kdf>(&kex_res_eph.marshal(), &kem_context, &mut buf)
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
pub(crate) fn encap<Kem: KemTrait, R>(
    pk_recip: &KemPubkey<Kem>,
    sender_id_keypair: Option<&(KemPrivkey<Kem>, KemPubkey<Kem>)>,
    csprng: &mut R,
) -> Result<(SharedSecret<Kem>, EncappedKey<Kem::Kex>), HpkeError>
where
    Kem: KemTrait,
    R: CryptoRng + RngCore,
{
    // Generate a new ephemeral keypair
    let (sk_eph, _) = Kem::Kex::gen_keypair(csprng);
    // Now pass to encap_with_eph
    encap_with_eph::<Kem>(pk_recip, sender_id_keypair, sk_eph)
}

// def Decap(enc, skR):
//   pkE = Unmarshal(enc)
//   dh = DH(skR, pkE)
//
//   pkRm = Marshal(pk(skR))
//   kemContext = concat(enc, pkRm)
//
//   zz = ExtractAndExpand(dh, kemContext)
//   return zz
//
// def AuthDecap(enc, skR, pkS):
//   pkE = Unmarshal(enc)
//   dh = concat(DH(skR, pkE), DH(skR, pkS))
//
//   pkRm = Marshal(pk(skR))
//   pkSm = Marshal(pkS)
//   kemContext = concat(enc, pkRm, pkSm)
//
//   zz = ExtractAndExpand(dh, kemContext)
//   return zz
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
    // Compute the shared secret from the ephemeral inputs
    let kex_res_eph = Kem::Kex::kex(&sk_recip, &encapped_key.0)?;

    // Compute the sender's pubkey from their privkey
    let pk_recip = Kem::Kex::sk_to_pk(sk_recip);

    // The shared secret is either gonna be kex_res_eph, or that along with another shared secret
    // that's tied to the sender's identity.
    if let Some(pk_sender_id) = pk_sender_id {
        let kem_context = [
            encapped_key.marshal(),
            pk_recip.marshal(),
            pk_sender_id.marshal(),
        ]
        .concat();
        // We want to do an authed encap. Do KEX between the sender identity secret key and the
        // recipient's pubkey
        let kex_res_identity = Kem::Kex::kex(sk_recip, pk_sender_id)?;
        // kex_res_eph || kex_res_identity
        let concatted_secrets = [kex_res_eph.marshal(), kex_res_identity.marshal()].concat();

        // The "authed shared secret" is derived from the KEX of the ephemeral input with the
        // recipient pubkey, and the kex of the identity input with the recipient pubkey. The
        // HKDF-Expand call only errors if the output values are 255x the digest size of the hash
        // function. Since these values are fixed at compile time, we don't worry about it.
        let mut shared_secret = <SharedSecret<Kem> as Default>::default();
        extract_and_expand::<Kem::Kdf>(&concatted_secrets, &kem_context, &mut shared_secret)
            .expect("shared secret is way too big");
        Ok(shared_secret)
    } else {
        let kem_context = [encapped_key.marshal(), pk_recip.marshal()].concat();
        // The "unauthed shared secret" is derived from just the KEX of the ephemeral input with the
        // recipient pubkey. The HKDF-Expand call only errors if the output values are 255x the
        // digest size of the hash function. Since these values are fixed at compile time, we don't
        // worry about it.
        let mut shared_secret = <SharedSecret<Kem> as Default>::default();
        extract_and_expand::<Kem::Kdf>(&kex_res_eph.marshal(), &kem_context, &mut shared_secret)
            .expect("shared secret is way too big");
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::{decap, encap, EncappedKey, Marshallable, Unmarshallable};
    use crate::{kem::Kem as KemTrait, kex::KeyExchange};

    use rand::{rngs::StdRng, SeedableRng};

    macro_rules! test_encap_correctness {
        ($test_name:ident, $kem_ty:ty) => {
            /// Tests that encap and decap produce the same shared secret when composed
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let mut csprng = StdRng::from_entropy();
                let (sk_recip, pk_recip) = <Kem as KemTrait>::Kex::gen_keypair(&mut csprng);

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) =
                    encap::<Kem, _>(&pk_recip, None, &mut csprng).unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    decap::<Kem>(&sk_recip, None, &encapped_key).unwrap();

                // Ensure that the encapsulated secret is what decap() derives
                assert_eq!(auth_shared_secret, decapped_auth_shared_secret);

                //
                // Now do it with the auth, i.e., using the sender's identity keys
                //

                // Make a sender identity keypair
                let (sk_sender_id, pk_sender_id) = <Kem as KemTrait>::Kex::gen_keypair(&mut csprng);

                // Encapsulate a random shared secret
                let (auth_shared_secret, encapped_key) = encap::<Kem, _>(
                    &pk_recip,
                    Some(&(sk_sender_id, pk_sender_id.clone())),
                    &mut csprng,
                )
                .unwrap();

                // Decap it
                let decapped_auth_shared_secret =
                    decap::<Kem>(&sk_recip, Some(&pk_sender_id), &encapped_key).unwrap();

                // Ensure that the encapsulated secret is what decap() derives
                assert_eq!(auth_shared_secret, decapped_auth_shared_secret);
            }
        };
    }

    #[cfg(feature = "x25519-dalek")]
    test_encap_correctness!(test_encap_correctness_x25519, crate::kem::X25519HkdfSha256);
    #[cfg(feature = "p256")]
    test_encap_correctness!(test_encap_correctness_p256, crate::kem::DhP256HkdfSha256);

    /// Tests that an unmarshal-marshal round-trip on an encapped key ends up at the same value
    macro_rules! test_encapped_marshal {
        ($test_name:ident, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                // Encapsulate a random shared secret
                let encapped_key = {
                    let mut csprng = StdRng::from_entropy();
                    let (_, pk_recip) = <Kem as KemTrait>::Kex::gen_keypair(&mut csprng);
                    encap::<Kem, _>(&pk_recip, None, &mut csprng).unwrap().1
                };
                // Marshal it
                let encapped_key_bytes = encapped_key.marshal();
                // Unmarshal it
                let new_encapped_key =
                    EncappedKey::<<Kem as KemTrait>::Kex>::unmarshal(&encapped_key_bytes).unwrap();

                assert!(
                    new_encapped_key.0 == encapped_key.0,
                    "encapped key doesn't marshal correctly"
                );
            }
        };
    }

    #[cfg(feature = "x25519-dalek")]
    test_encapped_marshal!(test_encapped_marshal_x25519, crate::kem::X25519HkdfSha256);
    #[cfg(feature = "p256")]
    test_encapped_marshal!(test_encapped_marshal_p256, crate::kem::DhP256HkdfSha256);
}
