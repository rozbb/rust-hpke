use crate::{
    aead::{Aead, AeadCtx, AeadCtxR, AeadCtxS, AeadKey, AeadNonce},
    dhkex::DhKeyExchange,
    kdf::Kdf as KdfTrait,
    kem::Kem as KemTrait,
    op_mode::{OpModeR, OpModeS, PskBundle},
    setup::ExporterSecret,
    HpkeError, Serializable,
};

use generic_array::GenericArray;
use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};

/// Returns a random 32-byte buffer
pub(crate) fn gen_rand_buf() -> [u8; 32] {
    let mut csprng = StdRng::from_entropy();
    let mut buf = [0u8; 32];
    csprng.fill_bytes(&mut buf);
    buf
}

/// Generates a keypair without the need of a KEM
pub(crate) fn dhkex_gen_keypair<Kex: DhKeyExchange, R: CryptoRng + RngCore>(
    csprng: &mut R,
) -> Result<(Kex::PrivateKey, Kex::PublicKey), HpkeError> {
    // Make some keying material that's the size of a private key
    let mut ikm: GenericArray<u8, <Kex::PrivateKey as Serializable>::OutputSize> =
        GenericArray::default();
    // Fill it with randomness
    csprng.fill_bytes(&mut ikm);
    // Run derive_keypair with a nonsense ciphersuite. We use SHA-512 to satisfy any security level
    Kex::derive_keypair::<crate::kdf::HkdfSha512>(b"31337", &ikm)
}

/// Creates a pair of `AeadCtx`s without doing a key exchange
pub(crate) fn gen_ctx_simple_pair<A, Kdf, Kem>() -> (AeadCtxS<A, Kdf, Kem>, AeadCtxR<A, Kdf, Kem>)
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    let mut csprng = StdRng::from_entropy();

    // Initialize the key and nonce
    let key = {
        let mut buf = AeadKey::<A>::default();
        csprng.fill_bytes(buf.0.as_mut_slice());
        buf
    };
    let base_nonce = {
        let mut buf = AeadNonce::<A>::default();
        csprng.fill_bytes(buf.0.as_mut_slice());
        buf
    };
    let exporter_secret = {
        let mut buf = ExporterSecret::<Kdf>::default();
        csprng.fill_bytes(buf.0.as_mut_slice());
        buf
    };

    let ctx1 = AeadCtx::new(&key, base_nonce.clone(), exporter_secret.clone());
    let ctx2 = AeadCtx::new(&key, base_nonce, exporter_secret);

    (ctx1.into(), ctx2.into())
}

#[derive(Clone, Copy)]
pub(crate) enum OpModeKind {
    Base,
    Auth,
    Psk,
    AuthPsk,
}

/// Makes an agreeing pair of `OpMode`s of the specified variant
pub(crate) fn new_op_mode_pair<'a, Kdf: KdfTrait, Kem: KemTrait>(
    kind: OpModeKind,
    psk: &'a [u8],
    psk_id: &'a [u8],
) -> Result<(OpModeS<'a, Kem>, OpModeR<'a, Kem>), HpkeError> {
    let mut csprng = StdRng::from_entropy();
    let (sk_sender, pk_sender) = Kem::gen_keypair(&mut csprng)?;
    let psk_bundle = PskBundle { psk, psk_id };

    match kind {
        OpModeKind::Base => {
            let sender_mode = OpModeS::Base;
            let receiver_mode = OpModeR::Base;
            Ok((sender_mode, receiver_mode))
        }
        OpModeKind::Psk => {
            let sender_mode = OpModeS::Psk(psk_bundle);
            let receiver_mode = OpModeR::Psk(psk_bundle);
            Ok((sender_mode, receiver_mode))
        }
        OpModeKind::Auth => {
            let sender_mode = OpModeS::Auth((sk_sender, pk_sender.clone()));
            let receiver_mode = OpModeR::Auth(pk_sender);
            Ok((sender_mode, receiver_mode))
        }
        OpModeKind::AuthPsk => {
            let sender_mode = OpModeS::AuthPsk((sk_sender, pk_sender.clone()), psk_bundle);
            let receiver_mode = OpModeR::AuthPsk(pk_sender, psk_bundle);
            Ok((sender_mode, receiver_mode))
        }
    }
}

/// Evaluates the equivalence of two encryption contexts by doing some encryption-decryption
/// round trips. Returns `true` iff the contexts are equal after 1000 iterations
pub(crate) fn aead_ctx_eq<A: Aead, Kdf: KdfTrait, Kem: KemTrait>(
    sender: &mut AeadCtxS<A, Kdf, Kem>,
    receiver: &mut AeadCtxR<A, Kdf, Kem>,
) -> bool {
    let mut csprng = StdRng::from_entropy();

    // Some random input data
    let msg = {
        let len = csprng.gen::<u8>();
        let mut buf = vec![0u8; len as usize];
        csprng.fill_bytes(&mut buf);
        buf
    };
    let aad = {
        let len = csprng.gen::<u8>();
        let mut buf = vec![0u8; len as usize];
        csprng.fill_bytes(&mut buf);
        buf
    };

    // Do 1000 iterations of encryption-decryption. The underlying sequence number increments
    // each time.
    for i in 0..1000 {
        let mut plaintext = msg.clone();
        // Encrypt the plaintext
        let tag = sender
            .seal_in_place_detached(&mut plaintext[..], &aad)
            .unwrap_or_else(|_| panic!("seal() #{} failed", i));
        // Rename for clarity
        let mut ciphertext = plaintext;

        // Now to decrypt on the other side
        if receiver
            .open_in_place_detached(&mut ciphertext[..], &aad, &tag)
            .is_err()
        {
            // An error occurred in decryption. These encryption contexts are not identical.
            return false;
        }
        // Rename for clarity
        let roundtrip_plaintext = ciphertext;

        // Make sure the output message was the same as the input message. If it doesn't match,
        // early return
        if msg != roundtrip_plaintext {
            return false;
        }
    }

    true
}
