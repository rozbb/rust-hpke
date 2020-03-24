use crate::prelude::*;
use crate::{
    aead::{Aead, AeadCtx},
    dh::{DiffieHellman, Marshallable, SharedSecret},
    kdf::Kdf,
    kem::{self, EncappedKey},
    op_mode::{OpMode, OpModeR, OpModeS},
};

use byteorder::{BigEndian, WriteBytesExt};
use digest::{generic_array::GenericArray, Digest};
use rand::{CryptoRng, RngCore};

/* From draft02 §6.1
    struct {
        // Mode and algorithms
        uint8 mode;
        uint16 kem_id;
        uint16 kdf_id;
        uint16 aead_id;

        // Public inputs to this key exchange
        opaque enc[Nenc];
        opaque pkR[Npk];
        opaque pkI[Npk];

        // Cryptographic hash of application-supplied pskID
        opaque pskID_hash[Nh];

        // Cryptographic hash of application-supplied info
        opaque info_hash[Nh];
    } HPKEContext;
*/

/// Secret generated in `derive_enc_ctx` and stored in `AeadCtx`
pub(crate) type ExporterSecret<K> = GenericArray<u8, <<K as Kdf>::HashImpl as Digest>::OutputSize>;

// This is the KeySchedule function defined in draft02 §6.1. It runs a KDF over all the parameters,
// inputs, and secrets, and spits out a key-nonce pair to be used for symmetric encryption
fn derive_enc_ctx<A: Aead, Dh: DiffieHellman, K: Kdf, O: OpMode<Dh, K>>(
    mode: &O,
    pk_recip: &Dh::PublicKey,
    shared_secret: SharedSecret<Dh>,
    encapped_key: &EncappedKey<Dh>,
    info: &[u8],
) -> AeadCtx<A, K> {
    // In KeySchedule(),
    //     pkRm = Marshal(pkR)
    //     ciphersuite = concat(encode_big_endian(kem_id, 2),
    //                          encode_big_endian(kdf_id, 2),
    //                          encode_big_endian(aead_id, 2))
    //     pskID_hash = Hash(pskID)
    //     info_hash = Hash(info)
    //     context = concat(mode, ciphersuite, enc, pkRm, pkIm, pskID_hash, info_hash)
    //
    // `context` comes out to `7 + Nenc + 2*Npk + 2*Nh` bytes, where `Npk` is the size of a
    // marshalled pubkey, and `Nh` is the digest size of the KDF
    let context_bytes: Vec<u8> = {
        let mut buf = Vec::new();

        // This relies on <Vec<u8> as Write>, which never errors, so unwrap() is justified
        buf.write_u8(mode.mode_id()).unwrap();
        buf.write_u16::<BigEndian>(Dh::KEM_ID).unwrap();
        buf.write_u16::<BigEndian>(K::KDF_ID).unwrap();
        buf.write_u16::<BigEndian>(A::AEAD_ID).unwrap();

        buf.extend(encapped_key.marshal());
        buf.extend(pk_recip.marshal().as_ref());
        buf.extend(mode.get_marshalled_sender_pk().as_ref());

        let psk_id_hash = K::HashImpl::digest(mode.get_psk_id());
        let info_hash = K::HashImpl::digest(info);

        buf.extend(psk_id_hash.as_slice());
        buf.extend(info_hash.as_slice());

        buf
    };

    // In KeySchedule(),
    //     secret = Extract(psk, zz)
    //     key = Expand(secret, concat("hpke key", context), Nk)
    //     nonce = Expand(secret, concat("hpke nonce", context), Nn)
    //     exporter_secret = Expand(secret, concat("exp", context), Nh)
    //     return Context(key, nonce, exporter_secret)
    //
    // Instead of `secret` we derive an HKDF context which we run .expand() on to derive the
    // key-nonce pair.
    let (_, hkdf_ctx) = {
        let psk = mode.get_psk();
        let shared_secret_bytes: Vec<u8> = shared_secret.into();
        hkdf::Hkdf::<K::HashImpl>::extract(Some(&psk), &shared_secret_bytes)
    };
    // The info strings for HKDF::expand
    let key_info = [&b"hpke key"[..], &context_bytes].concat();
    let nonce_info = [&b"hpke nonce"[..], &context_bytes].concat();
    let exporter_info = [&b"hpke exp"[..], &context_bytes].concat();

    // Empty fixed-size buffers
    let mut key = crate::aead::AeadKey::<A>::default();
    let mut nonce = crate::aead::AeadNonce::<A>::default();
    let mut exporter_secret = <ExporterSecret<K> as Default>::default();

    // Fill the key and nonce. This only errors if the output values are 255x the digest size of
    // the hash function. Since these values are fixed at compile time, we don't worry about it.
    hkdf_ctx
        .expand(&key_info, key.as_mut_slice())
        .expect("aead key len is way too big");
    hkdf_ctx
        .expand(&nonce_info, nonce.as_mut_slice())
        .expect("aead nonce len is way too big");
    hkdf_ctx
        .expand(&exporter_info, exporter_secret.as_mut_slice())
        .expect("exporter secret len is way too big");

    AeadCtx::new(key, nonce, exporter_secret)
}

// From draft02 §6.5:
//     def SetupAuthPSKI(pkR, info, psk, pskID, skI):
//       zz, enc = AuthEncap(pkR, skI)
//       pkIm = Marshal(pk(skI))
//       return enc, KeySchedule(mode_psk_auth, pkR, zz, enc, info,
//                               psk, pskID, pkIm)
/// Initiates an encryption context to the given recipient. Does an "authenticated" encapsulation
/// if `sk_sender_id` is set. This ties the sender identity to the shared secret.
///
/// Return Value
/// ============
/// Returns an encapsulated public key (intended to be sent to the recipient), and an encryption
/// context.
pub fn setup_sender<A, Dh, K, R>(
    mode: &OpModeS<Dh, K>,
    pk_recip: &Dh::PublicKey,
    info: &[u8],
    csprng: &mut R,
) -> (EncappedKey<Dh>, AeadCtx<A, K>)
where
    A: Aead,
    Dh: DiffieHellman,
    K: Kdf,
    R: CryptoRng + RngCore,
{
    // If the identity key is set, use it
    let sk_sender_id: Option<&Dh::PrivateKey> = mode.get_sk_sender_id();
    // Do the encapsulation
    let (shared_secret, encapped_key) = kem::encap(pk_recip, sk_sender_id, csprng);
    // Use everything to derive an encryption context
    let enc_ctx = derive_enc_ctx(mode, pk_recip, shared_secret, &encapped_key, info);

    (encapped_key, enc_ctx)
}

//  From draft02 §6.5:
//     def SetupAuthPSKR(enc, skR, info, psk, pskID, pkI):
//       zz = AuthDecap(enc, skR, pkI)
//       pkIm = Marshal(pkI)
//       return KeySchedule(mode_psk_auth, pk(skR), zz, enc, info,
//                          psk, pskID, pkIm)
/// Initiates an encryption context given a private key sk and a encapsulated key which was
/// encapsulated to `sk`'s corresponding public key
///
/// Return Value
/// ============
/// Returns an encryption context
pub fn setup_receiver<A, Dh, K>(
    mode: &OpModeR<Dh, K>,
    sk_recip: &Dh::PrivateKey,
    encapped_key: &EncappedKey<Dh>,
    info: &[u8],
) -> AeadCtx<A, K>
where
    A: Aead,
    Dh: DiffieHellman,
    K: Kdf,
{
    // If the identity key is set, use it
    let pk_sender_id: Option<&Dh::PublicKey> = mode.get_pk_sender_id();
    // Do the decapsulation
    let shared_secret = kem::decap(sk_recip, pk_sender_id, encapped_key);
    // Get the pubkey corresponding to the recipient's private key
    let pk_recip = Dh::sk_to_pk(sk_recip);

    // Use everything to derive an encryption context
    derive_enc_ctx(mode, &pk_recip, shared_secret, &encapped_key, info)
}

#[cfg(test)]
mod test {
    use crate::test_util::{assert_aead_ctx_eq, gen_ctx_kem_pair};
    use crate::{
        aead::ChaCha20Poly1305,
        dh::x25519::X25519,
        kdf::{HkdfSha256, Kdf},
        op_mode::PskBundle,
    };

    // For testing purposes, we need PskBundle to be copyable. We can't use #[derive(Clone)]
    // because it thinks that K has to be Clone.
    impl<K: Kdf> Clone for PskBundle<K> {
        fn clone(&self) -> Self {
            // Do the obvious thing
            PskBundle {
                psk: self.psk.clone(),
                psk_id: self.psk_id.clone(),
            }
        }
    }

    /// This tests that `setup_sender` and `setup_receiver` derive the same context. We do this by
    /// testing that `gen_ctx_kem_pair` returns identical encryption contexts
    #[test]
    fn test_psk_auth_correctness() {
        // Make two random identical contexts
        let (mut aead_ctx1, mut aead_ctx2) =
            gen_ctx_kem_pair::<ChaCha20Poly1305, X25519, HkdfSha256>();
        assert_aead_ctx_eq(&mut aead_ctx1, &mut aead_ctx2);
    }

    /// Makes sure that using different data gives you different encryption contexts
    #[test]
    #[should_panic]
    fn test_bad_setup() {
        // Make two random contexts which are not identical
        let (mut aead_ctx1, _) = gen_ctx_kem_pair::<ChaCha20Poly1305, X25519, HkdfSha256>();
        let (mut aead_ctx2, _) = gen_ctx_kem_pair::<ChaCha20Poly1305, X25519, HkdfSha256>();

        // Make sure the contexts don't line up
        assert_aead_ctx_eq(&mut aead_ctx1, &mut aead_ctx2);
    }

    // Test overflow by setting seq to something very high
}
