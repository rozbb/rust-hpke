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

/// Takes `SharedSecret::Unauthed(dh_res)` and returns dh_res. This is a helper function for
/// `auth_encap` and `auth_decap`.
///
/// Panics: When its input is a `SharedSecret::Authed`
fn extract_dh_res<Dh: DiffieHellman>(ss: SharedSecret<Dh>) -> Dh::DhResult {
    // Unpack the value into the DH result
    if let SharedSecret::Unauthed(res) = ss {
        res
    } else {
        // decap() is guaranteed to return a SharedSecret::Unauthed variant
        panic!("misused extract_dh_res");
    }
}

/// Derives a shared secret and an ephemeral pubkey that the owner of the reciepint's pubkey can
/// use to derive the same shared secret
pub(crate) fn encap<Dh, R>(
    pk_recip: &Dh::PublicKey,
    csprng: &mut R,
) -> (SharedSecret<Dh>, EncappedKey<Dh>)
where
    Dh: DiffieHellman,
    R: CryptoRng + RngCore,
{
    // Generate a new ephemeral keypair
    let (sk_eph, pk_eph) = Dh::gen_keypair(csprng);
    // Compute the shared secret
    let dh_res = Dh::dh(&sk_eph, pk_recip);

    (SharedSecret::Unauthed(dh_res), EncappedKey(pk_eph))
}

/// Same idea as `encap`, except an extra DH step is done between the sender's identity privkey and
/// the recipients public key. This ties the sender identity to the shared secret.
fn auth_encap<Dh, R>(
    sk_sender_id: &Dh::PrivateKey,
    pk_recip: &Dh::PublicKey,
    csprng: &mut R,
) -> (SharedSecret<Dh>, EncappedKey<Dh>)
where
    Dh: DiffieHellman,
    R: CryptoRng + RngCore,
{
    // Do a normal encap first
    let (single_shared_secret, encapped_key) = encap::<Dh, _>(pk_recip, csprng);
    // Unwrap the enum
    let dh_res_eph = extract_dh_res(single_shared_secret);

    // Now do a DH between the sender identity secret key and the recipient's pubkey
    let dh_res_identity = Dh::dh(sk_sender_id, pk_recip);

    // The "authed shared secret" is the concatenation of the two
    let authed_shared_secret = SharedSecret::Authed(dh_res_eph, dh_res_identity);

    (authed_shared_secret, encapped_key)
}

/// Derives a shared secret given the encapsulated key and the recipients secret key
pub(crate) fn decap<Dh: DiffieHellman>(
    sk_recip: &Dh::PrivateKey,
    encapped_key: &EncappedKey<Dh>,
) -> SharedSecret<Dh> {
    // Do a DH with my secret key
    let dh_res = Dh::dh(&sk_recip, &encapped_key.0);

    SharedSecret::Unauthed(dh_res)
}

/// Same idea as `decap`, except an extra DH step is done between the sender's identity pubkey and
/// the recipient's privkey. This ties the sender identity to the shared secret.
fn auth_decap<Dh: DiffieHellman>(
    sk_recip: &Dh::PrivateKey,
    encapped_key: &EncappedKey<Dh>,
    pk_sender_id: &Dh::PublicKey,
) -> SharedSecret<Dh> {
    // Do a normal decap first
    let single_shared_secret = decap::<Dh>(sk_recip, encapped_key);
    // Unwrap the enum
    let dh_res_eph = extract_dh_res(single_shared_secret);

    // Do a DH between the sender's identity pubkey and my secret key
    let dh_res_identity = Dh::dh(sk_recip, pk_sender_id);

    // The "authed shared secret" is the concatenation of the two
    SharedSecret::Authed(dh_res_eph, dh_res_identity)
}

#[cfg(test)]
mod tests {
    use super::{auth_decap, auth_encap, decap, encap};
    use crate::dh::{x25519::X25519Impl, DiffieHellman};

    #[test]
    /// Tests that encap and decap produce the same shared secret when composed
    fn encap_correctness() {
        let mut csprng = rand::thread_rng();
        let (sk_recip, pk_recip) = X25519Impl::gen_keypair(&mut csprng);

        // Encapsulate a random shared secret
        let (shared_secret, public_share) = encap::<X25519Impl, _>(&pk_recip, &mut csprng);

        // Ensure that the encapsulated secret is what decap() derives
        assert_eq!(shared_secret, decap::<X25519Impl>(&sk_recip, &public_share));
    }

    #[test]
    /// Tests that auth_encap and auth_decap produce the same shared secret when composed
    fn auth_encap_correctness() {
        let mut csprng = rand::thread_rng();
        let (sk_sender_id, pk_sender_id) = X25519Impl::gen_keypair(&mut csprng);
        let (sk_recip, pk_recip) = X25519Impl::gen_keypair(&mut csprng);

        // Encapsulate a random shared secret
        let (auth_shared_secret, pk_sender_eph) =
            auth_encap::<X25519Impl, _>(&sk_sender_id, &pk_recip, &mut csprng);

        // Decap it
        let decapped_auth_shared_secret =
            auth_decap::<X25519Impl>(&sk_recip, &pk_sender_eph, &pk_sender_id);

        // Ensure that the encapsulated secret is what decap() derives
        assert_eq!(auth_shared_secret, decapped_auth_shared_secret);
    }
}
