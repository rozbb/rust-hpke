use crate::{
    dh::{DiffieHellman, Marshallable, Unmarshallable},
    kdf::{extract_and_expand, Kdf},
};
use digest::generic_array::GenericArray;
use rand::{CryptoRng, RngCore};

/// This holds the content of an encapsulated secret. It is output by the `encap` and `encap_auth`
/// functions.
// This just wraps a pubkey, because that's all an encapsulated key is in a DH-KEM
pub struct EncappedKey<Dh: DiffieHellman>(Dh::PublicKey);

// EncappedKeys need to be serializable, since they're gonna be sent over the wire. Underlyingly,
// they're just DH pubkeys, so we just serialize them the same way
impl<Dh: DiffieHellman> Marshallable for EncappedKey<Dh> {
    type OutputSize = <Dh::PublicKey as Marshallable>::OutputSize;

    // Pass to underlying marshal() impl
    fn marshal(&self) -> GenericArray<u8, Self::OutputSize> {
        self.0.marshal()
    }
}

impl<Dh: DiffieHellman> Unmarshallable for EncappedKey<Dh> {
    // Pass to underlying unmarshal() impl
    fn unmarshal(encoded: GenericArray<u8, Self::OutputSize>) -> Self {
        let pubkey = <Dh::PublicKey as Unmarshallable>::unmarshal(encoded);
        EncappedKey(pubkey)
    }
}

/// A convenience type representing the fixed-size byte array that an encapped key gets serialized
/// to/from.
pub type MarshalledEncappedKey<Dh> =
    GenericArray<u8, <EncappedKey<Dh> as Marshallable>::OutputSize>;

/// A convenience type representing the fixed-size byte array of the same length as a serialized
/// `DhResult`
pub(crate) type SharedSecret<Dh> =
    GenericArray<u8, <<Dh as DiffieHellman>::DhResult as Marshallable>::OutputSize>;

// def Encap(pkR):
//   skE, pkE = GenerateKeyPair()
//   dh = DH(skE, pkR)
//   enc = Marshal(pkE)
//
//   pkRm = Marshal(pkR)
//   kemContext = concat(enc, pkRm)
//
//   zz = ExtractAndExpand(dh, kemContext)
//   return zz, enc
//
// def AuthEncap(pkR, skS, pkS):
//   skE, pkE = GenerateKeyPair()
//   dh = concat(DH(skE, pkR), DH(skS, pkR))
//   enc = Marshal(pkE)
//
//   pkRm = Marshal(pkR)
//   pkSm = Marshal(pkS)
//   kemContext = concat(enc, pkRm, pkSm)
//
//   zz = ExtractAndExpand(dh, kemContext)
//   return zz, enc
/// Derives a shared secret that the owner of the reciepint's pubkey can use to derive the same
/// shared secret. If `sk_sender_id` is given, the sender's identity will be tied to the shared
/// secret.
pub(crate) fn encap_with_eph<Dh, K>(
    pk_recip: &Dh::PublicKey,
    sender_id_keypair: Option<&(Dh::PrivateKey, Dh::PublicKey)>,
    sk_eph: Dh::PrivateKey,
    pk_eph: Dh::PublicKey,
) -> (SharedSecret<Dh>, EncappedKey<Dh>)
where
    Dh: DiffieHellman,
    K: Kdf,
{
    // Compute the shared secret from the ephemeral inputs
    let dh_res_eph = Dh::dh(&sk_eph, pk_recip);

    // The encapped key is the ephemeral pubkey
    let encapped_key = EncappedKey(pk_eph);

    // The shared secret is either gonna be dh_res_eph, or that along with another shared secret
    // that's tied to the sender's identity.
    let shared_secret = if let Some((sk_sender_id, pk_sender_id)) = sender_id_keypair {
        let kem_context = [
            encapped_key.marshal(),
            pk_recip.marshal(),
            pk_sender_id.marshal(),
        ]
        .concat();
        // We want to do an authed encap. Do DH between the sender identity secret key and the
        // recipient's pubkey
        let dh_res_identity = Dh::dh(sk_sender_id, pk_recip);
        // dh_eph || dh_identity
        let concatted_secrets = [dh_res_eph.marshal(), dh_res_identity.marshal()].concat();

        // The "authed shared secret" is derived from the DH of the ephemeral input with the
        // recipient pubkey, and the DH of the identity input with the recipient pubkey. The
        // HKDF-Expand call only errors if the output values are 255x the digest size of the hash
        // function. Since these values are fixed at compile time, we don't worry about it.
        let mut buf = <SharedSecret<Dh> as Default>::default();
        extract_and_expand::<K>(&concatted_secrets, &kem_context, &mut buf)
            .expect("shared secret is way too big");
        buf
    } else {
        let kem_context = [encapped_key.marshal(), pk_recip.marshal()].concat();
        // The "unauthed shared secret" is derived from just the DH of the ephemeral input with the
        // recipient pubkey. The HKDF-Expand call only errors if the output values are 255x the
        // digest size of the hash function. Since these values are fixed at compile time, we don't
        // worry about it.
        let mut buf = <SharedSecret<Dh> as Default>::default();
        extract_and_expand::<K>(&dh_res_eph.marshal(), &kem_context, &mut buf)
            .expect("shared secret is way too big");
        buf
    };

    (shared_secret, encapped_key)
}

/// Derives a shared secret and an ephemeral pubkey that the owner of the reciepint's pubkey can
/// use to derive the same shared secret. If `sk_sender_id` is given, the sender's identity will be
/// tied to the shared secret.
/// All this does is generate an ephemeral keypair and pass to `encap_with_eph`.
pub(crate) fn encap<Dh, K, R>(
    pk_recip: &Dh::PublicKey,
    sender_id_keypair: Option<&(Dh::PrivateKey, Dh::PublicKey)>,
    csprng: &mut R,
) -> (SharedSecret<Dh>, EncappedKey<Dh>)
where
    Dh: DiffieHellman,
    K: Kdf,
    R: CryptoRng + RngCore,
{
    // Generate a new ephemeral keypair
    let (sk_eph, pk_eph) = Dh::gen_keypair(csprng);
    // Now pass to encap_with_eph
    encap_with_eph::<_, K>(pk_recip, sender_id_keypair, sk_eph, pk_eph)
}

// def Decap(enc, skR, pkR):
//   pkE = Unmarshal(enc)
//   dh = DH(skR, pkE)
//
//   pkRm = Marshal(pkR)
//   kemContext = concat(enc, pkRm)
//
// def AuthDecap(enc, skR, pkR, pkS):
//   pkE = Unmarshal(enc)
//   dh = concat(DH(skR, pkE), DH(skR, pkS))
//
//   pkRm = Marshal(pkR)
//   pkSm = Marshal(pkS)
//   kemContext = concat(enc, pkRm, pkSm)
//
//   zz = ExtractAndExpand(dh, kemContext)
//   return zz, enc
/// Derives a shared secret given the encapsulated key and the recipients secret key. If
/// `pk_sender_id` is given, the sender's identity will be tied to the shared secret.
pub(crate) fn decap<Dh, K>(
    sk_recip: &Dh::PrivateKey,
    pk_recip: &Dh::PublicKey,
    pk_sender_id: Option<&Dh::PublicKey>,
    encapped_key: &EncappedKey<Dh>,
) -> SharedSecret<Dh>
where
    Dh: DiffieHellman,
    K: Kdf,
{
    // Compute the shared secret from the ephemeral inputs
    let dh_res_eph = Dh::dh(&sk_recip, &encapped_key.0);

    // The shared secret is either gonna be dh_res_eph, or that along with another shared secret
    // that's tied to the sender's identity.
    if let Some(pk_sender_id) = pk_sender_id {
        let kem_context = [
            encapped_key.marshal(),
            pk_recip.marshal(),
            pk_sender_id.marshal(),
        ]
        .concat();
        // We want to do an authed encap. Do DH between the sender identity secret key and the
        // recipient's pubkey
        let dh_res_identity = Dh::dh(sk_recip, pk_sender_id);
        // dh_eph || dh_identity
        let concatted_secrets = [dh_res_eph.marshal(), dh_res_identity.marshal()].concat();

        // The "authed shared secret" is derived from the DH of the ephemeral input with the
        // recipient pubkey, and the DH of the identity input with the recipient pubkey. The
        // HKDF-Expand call only errors if the output values are 255x the digest size of the hash
        // function. Since these values are fixed at compile time, we don't worry about it.
        let mut shared_secret = <SharedSecret<Dh> as Default>::default();
        extract_and_expand::<K>(&concatted_secrets, &kem_context, &mut shared_secret)
            .expect("shared secret is way too big");
        shared_secret
    } else {
        let kem_context = [encapped_key.marshal(), pk_recip.marshal()].concat();
        // The "unauthed shared secret" is derived from just the DH of the ephemeral input with the
        // recipient pubkey. The HKDF-Expand call only errors if the output values are 255x the
        // digest size of the hash function. Since these values are fixed at compile time, we don't
        // worry about it.
        let mut shared_secret = <SharedSecret<Dh> as Default>::default();
        extract_and_expand::<K>(&dh_res_eph.marshal(), &kem_context, &mut shared_secret)
            .expect("shared secret is way too big");
        shared_secret
    }
}

#[cfg(test)]
mod tests {
    use super::{decap, encap, EncappedKey, Marshallable, Unmarshallable};
    use crate::{
        dh::{x25519::X25519, DiffieHellman},
        kdf::HkdfSha256,
    };

    /// Tests that encap and decap produce the same shared secret when composed
    #[test]
    fn test_encap_correctness() {
        type Dh = X25519;
        type K = HkdfSha256;

        let mut csprng = rand::thread_rng();
        let (sk_recip, pk_recip) = Dh::gen_keypair(&mut csprng);

        // Encapsulate a random shared secret
        let (auth_shared_secret, encapped_key) = encap::<Dh, K, _>(&pk_recip, None, &mut csprng);

        // Decap it
        let decapped_auth_shared_secret = decap::<Dh, K>(&sk_recip, &pk_recip, None, &encapped_key);

        // Ensure that the encapsulated secret is what decap() derives
        assert_eq!(auth_shared_secret, decapped_auth_shared_secret);

        //
        // Now do it with the auth, i.e., using the sender's identity keys
        //

        // Make a sender identity keypair
        let (sk_sender_id, pk_sender_id) = Dh::gen_keypair(&mut csprng);

        // Encapsulate a random shared secret
        let (auth_shared_secret, encapped_key) = encap::<Dh, K, _>(
            &pk_recip,
            Some(&(sk_sender_id, pk_sender_id.clone())),
            &mut csprng,
        );

        // Decap it
        let decapped_auth_shared_secret =
            decap::<Dh, K>(&sk_recip, &pk_recip, Some(&pk_sender_id), &encapped_key);

        // Ensure that the encapsulated secret is what decap() derives
        assert_eq!(auth_shared_secret, decapped_auth_shared_secret);
    }

    /// Tests that an unmarshal-marshal round-trip on an encapped key ends up at the same value
    #[test]
    fn test_encapped_marshal() {
        type Dh = X25519;
        type K = HkdfSha256;

        // Encapsulate a random shared secret
        let encapped_key = {
            let mut csprng = rand::thread_rng();
            let (_, pk_recip) = Dh::gen_keypair(&mut csprng);
            encap::<Dh, K, _>(&pk_recip, None, &mut csprng).1
        };
        // Marshal it
        let encapped_key_bytes = encapped_key.marshal();
        // Unmarshal it
        let new_encapped_key = EncappedKey::<Dh>::unmarshal(encapped_key_bytes);

        assert!(
            new_encapped_key.0 == encapped_key.0,
            "encapped key doesn't marshal correctly"
        );
    }
}
