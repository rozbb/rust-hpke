use crate::dh::{DiffieHellman, Marshallable, SharedSecret};
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

    // Pass to underlying unmarshal() impl
    fn unmarshal(encoded: GenericArray<u8, Self::OutputSize>) -> Self {
        let pubkey = <Dh::PublicKey as Marshallable>::unmarshal(encoded);
        EncappedKey(pubkey)
    }
}

/// A convenience type representing the fixed-size byte array that an encapped key gets serialized
/// to/from.
pub type MarshalledEncappedKey<Dh> =
    GenericArray<u8, <EncappedKey<Dh> as Marshallable>::OutputSize>;

/// Derives a shared secret that the owner of the reciepint's pubkey can use to derive the same
/// shared secret. If `sk_sender_id` is given, the sender's identity will be tied to the shared
/// secret.
pub(crate) fn encap_with_eph<Dh>(
    pk_recip: &Dh::PublicKey,
    sk_sender_id: Option<&Dh::PrivateKey>,
    sk_eph: Dh::PrivateKey,
    pk_eph: Dh::PublicKey,
) -> (SharedSecret<Dh>, EncappedKey<Dh>)
where
    Dh: DiffieHellman,
{
    // Compute the shared secret from the ephemeral inputs
    let dh_res_eph = Dh::dh(&sk_eph, pk_recip);

    // The shared secret is either gonna be dh_res_eph, or that along with another shared secret
    // that's tied to the sender's identity.
    let shared_secret = if let Some(sk_sender_id) = sk_sender_id {
        // We want to do an authed encap. Do DH between the sender identity secret key and the
        // recipient's pubkey
        let dh_res_identity = Dh::dh(sk_sender_id, pk_recip);
        // "authed shared secret" is the concatenation of the two shared secrets
        SharedSecret::Authed(dh_res_eph, dh_res_identity)
    } else {
        // The "unauthed shared secret" is just the DH of the ephemeral inputs
        SharedSecret::Unauthed(dh_res_eph)
    };

    (shared_secret, EncappedKey(pk_eph))
}

/// Derives a shared secret and an ephemeral pubkey that the owner of the reciepint's pubkey can
/// use to derive the same shared secret. If `sk_sender_id` is given, the sender's identity will be
/// tied to the shared secret.
/// All this does is generate an ephemeral keypair and pass to `encap_with_eph`.
pub(crate) fn encap<Dh, R>(
    pk_recip: &Dh::PublicKey,
    sk_sender_id: Option<&Dh::PrivateKey>,
    csprng: &mut R,
) -> (SharedSecret<Dh>, EncappedKey<Dh>)
where
    Dh: DiffieHellman,
    R: CryptoRng + RngCore,
{
    // Generate a new ephemeral keypair
    let (sk_eph, pk_eph) = Dh::gen_keypair(csprng);
    // Now pass to encap_with_eph
    encap_with_eph(pk_recip, sk_sender_id, sk_eph, pk_eph)
}

/// Derives a shared secret given the encapsulated key and the recipients secret key. If
/// `pk_sender_id` is given, the sender's identity will be tied to the shared secret.
pub(crate) fn decap<Dh: DiffieHellman>(
    sk_recip: &Dh::PrivateKey,
    pk_sender_id: Option<&Dh::PublicKey>,
    encapped_key: &EncappedKey<Dh>,
) -> SharedSecret<Dh> {
    // Compute teh shared secret from the ephemeral inputs
    let dh_res_eph = Dh::dh(&sk_recip, &encapped_key.0);

    // The shared secret is either gonna be dh_res_eph, or that along with another shared secret
    // that's tied to the sender's identity.
    if let Some(pk_sender_id) = pk_sender_id {
        // We want to do an authed decap. Do DH between the sender identity pubkey and the
        // recipient's secret key
        let dh_res_identity = Dh::dh(sk_recip, pk_sender_id);
        // "authed shared secret" is the concatenation of the two shared secrets
        SharedSecret::Authed(dh_res_eph, dh_res_identity)
    } else {
        // The "unauthed shared secret" is just the DH of the ephemeral inputs
        SharedSecret::Unauthed(dh_res_eph)
    }
}

#[cfg(test)]
mod tests {
    use super::{decap, encap, EncappedKey, Marshallable};
    use crate::dh::{x25519::X25519, DiffieHellman};

    /// Tests that encap and decap produce the same shared secret when composed
    #[test]
    fn test_encap_correctness() {
        type Dh = X25519;

        let mut csprng = rand::thread_rng();
        let (sk_recip, pk_recip) = Dh::gen_keypair(&mut csprng);

        // Encapsulate a random shared secret
        let (auth_shared_secret, encapped_key) = encap::<Dh, _>(&pk_recip, None, &mut csprng);

        // Decap it
        let decapped_auth_shared_secret = decap::<Dh>(&sk_recip, None, &encapped_key);

        // Ensure that the encapsulated secret is what decap() derives
        assert_eq!(auth_shared_secret, decapped_auth_shared_secret);

        //
        // Now do it with the auth, i.e., using the sender's identity keys
        //

        // Make a sender identity keypair
        let (sk_sender_id, pk_sender_id) = Dh::gen_keypair(&mut csprng);

        // Encapsulate a random shared secret
        let (auth_shared_secret, encapped_key) =
            encap::<Dh, _>(&pk_recip, Some(&sk_sender_id), &mut csprng);

        // Decap it
        let decapped_auth_shared_secret =
            decap::<Dh>(&sk_recip, Some(&pk_sender_id), &encapped_key);

        // Ensure that the encapsulated secret is what decap() derives
        assert_eq!(auth_shared_secret, decapped_auth_shared_secret);
    }

    /// Tests that an unmarshal-marshal round-trip on an encapped key ends up at the same value
    #[test]
    fn test_encapped_marshal() {
        type Dh = X25519;

        // Encapsulate a random shared secret
        let encapped_key = {
            let mut csprng = rand::thread_rng();
            let (_, pk_recip) = Dh::gen_keypair(&mut csprng);
            encap::<Dh, _>(&pk_recip, None, &mut csprng).1
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
