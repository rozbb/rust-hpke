use crate::{
    aead::{Aead, AeadCtx},
    dh::{DiffieHellman, Marshallable, SharedSecret},
    kdf::Kdf,
    kem::{self, EncappedKey},
    op_mode::{OpMode, OpModeR, OpModeS},
};

use byteorder::{BigEndian, WriteBytesExt};
use digest::Digest;
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

// This is the KeySchedule function defined in draft02 §5.1. It runs a KDF over all the parameters,
// inputs, and secrets, and spits out a key-nonce pair to be used for symmetric encryption
fn derive_enc_ctx<'a, A: Aead, Dh: DiffieHellman, K: Kdf, O: OpMode<'a, Dh, K>>(
    mode: &O,
    pk_recip: &Dh::PublicKey,
    shared_secret: SharedSecret<Dh>,
    encapped_key: &EncappedKey<Dh>,
    info: &[u8],
) -> AeadCtx<A> {
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
    //     return Context(key, nonce)
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

    // Empty fixed-size buffers
    let mut key = crate::aead::Key::<A>::default();
    let mut nonce = crate::aead::Nonce::<A>::default();

    // Fill the key and nonce. This only errors if the key and nonce values are 255x the digest
    // size of the hash function. Since these values are fixed at compile time, we don't worry
    // about it.
    hkdf_ctx
        .expand(&key_info, key.as_mut_slice())
        .expect("aead key len is way too big");
    hkdf_ctx
        .expand(&nonce_info, nonce.as_mut_slice())
        .expect("aead nonce len is way too big");

    AeadCtx::new(key, nonce)
}

// From draft02 §5.1.4:
//     def SetupAuthPSKS(pkR, info, psk, pskID, skS):
//       zz, enc = AuthEncap(pkR, skS)
//       pkSm = Marshal(pk(skS))
//       return enc, KeySchedule(mode_auth_psk, pkR, zz, enc, info,
//                               psk, pskID, pkSm)
/// Initiates an encryption context to the given recipient. Does an "authenticated" encapsulation
/// if `sk_sender_id` is set. This ties the sender identity to the shared secret.
///
/// Returns: An encapsulated public key (intended to be sent to the recipient), and an encryption
/// context.
pub fn setup_sender<A, Dh, K, R>(
    mode: &OpModeS<Dh, K>,
    pk_recip: &Dh::PublicKey,
    info: &[u8],
    csprng: &mut R,
) -> (EncappedKey<Dh>, AeadCtx<A>)
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

//  From draft02 §5.1.4:
//     def SetupAuthPSKR(enc, skR, info, psk, pskID, pkS):
//       zz = AuthDecap(enc, skR, pkS)
//       pkSm = Marshal(pkS)
//       return KeySchedule(mode_auth_psk, pk(skR), zz, enc, info,
//                          psk, pskID, pkSm)
/// Initiates an encryption context given a private key sk and a encapsulated key which was
/// encapsulated to `sk`'s corresponding public key
///
/// Returns: An encryption context
pub fn setup_receiver<A, Dh, K, R>(
    mode: &OpModeR<Dh, K>,
    sk_recip: &Dh::PrivateKey,
    encapped_key: &EncappedKey<Dh>,
    info: &[u8],
) -> AeadCtx<A>
where
    A: Aead,
    Dh: DiffieHellman,
    K: Kdf,
    R: CryptoRng + RngCore,
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
    use super::{setup_receiver, setup_sender};
    use crate::{
        aead::{AssociatedData, ChaCha20Poly1305},
        dh::{x25519::X25519Impl, DiffieHellman},
        kdf::HkdfSha256,
        op_mode::{OpModeS, Psk, PskBundle},
    };

    use rand::{rngs::ThreadRng, RngCore};

    /// This tests that `setup_sender` and `setup_receiver` derive the same context
    #[test]
    fn test_psk_auth_correctness() {
        let mut csprng = rand::thread_rng();
        let info = b"why would you think in a million years that that would actually work";
        let psk = {
            let mut buf = <Psk<HkdfSha256> as Default>::default();
            csprng.fill_bytes(buf.as_mut_slice());
            buf
        };
        let psk_id = b"this is the war room";
        let psk_bundle = PskBundle::<HkdfSha256> {
            psk: &psk,
            psk_id: &psk_id[..],
        };

        let (sk_sender_id, pk_sender_id) = X25519Impl::gen_keypair(&mut csprng);
        let (sk_recip, pk_recip) = X25519Impl::gen_keypair(&mut csprng);

        let mode = OpModeS::<X25519Impl, _>::PskAuth(psk_bundle, &sk_sender_id);
        let (encapped_key, mut aead_ctx1) =
            setup_sender::<ChaCha20Poly1305, _, _, _>(&mode, &pk_recip, &info[..], &mut csprng);

        let mode_r = mode.to_op_mode_r();
        let mut aead_ctx2 = setup_receiver::<ChaCha20Poly1305, X25519Impl, HkdfSha256, ThreadRng>(
            &mode_r,
            &sk_recip,
            &encapped_key,
            &info[..],
        );

        //
        // Test the encryption
        //

        let msg = b"I'll have what I'm having";
        let aad = AssociatedData(b"diced onion, red pepper, grilled meat");

        // Do 100 iterations of encryption-decryption. The underlying sequence number increments
        // each time.
        for _ in 0..100 {
            let mut plaintext = *msg;
            // Encrypt the plaintext
            let tag = aead_ctx1
                .seal(&mut plaintext[..], &aad)
                .expect("first seal() failed");
            // Rename for clarity
            let mut ciphertext = plaintext;

            // Now to decrypt on the other side
            aead_ctx2
                .open(&mut ciphertext[..], &aad, &tag)
                .expect("first open() failed");
            // Rename for clarity
            let roundtrip_plaintext = ciphertext;

            // Make sure the output message was the same as the input message
            assert_eq!(msg, &roundtrip_plaintext);
        }
    }

    // Test that making an OpModeR and using to_mode_r do the same thing

    // Test overflow by setting seq to something very high
}
