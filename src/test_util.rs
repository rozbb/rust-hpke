use crate::{
    aead::{Aead, AeadCtx, AeadCtxR, AeadCtxS, AeadKey, AeadNonce},
    dhkex::DhKeyExchange,
    kdf::Kdf as KdfTrait,
    kem::Kem as KemTrait,
    op_mode::{OpModeR, OpModeS, PskBundle},
    setup::ExporterSecret,
    Serializable,
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
) -> (Kex::PrivateKey, Kex::PublicKey) {
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

#[derive(Clone, Copy, PartialEq)]
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
) -> (OpModeS<'a, Kem>, OpModeR<'a, Kem>) {
    let mut csprng = StdRng::from_entropy();
    let (sk_sender, pk_sender) = Kem::gen_keypair(&mut csprng);
    let psk_bundle = PskBundle { psk, psk_id };

    match kind {
        OpModeKind::Base => {
            let sender_mode = OpModeS::Base;
            let receiver_mode = OpModeR::Base;
            (sender_mode, receiver_mode)
        }
        OpModeKind::Psk => {
            let sender_mode = OpModeS::Psk(psk_bundle);
            let receiver_mode = OpModeR::Psk(psk_bundle);
            (sender_mode, receiver_mode)
        }
        OpModeKind::Auth => {
            let sender_mode = OpModeS::Auth((sk_sender, pk_sender.clone()));
            let receiver_mode = OpModeR::Auth(pk_sender);
            (sender_mode, receiver_mode)
        }
        OpModeKind::AuthPsk => {
            let sender_mode = OpModeS::AuthPsk((sk_sender, pk_sender.clone()), psk_bundle);
            let receiver_mode = OpModeR::AuthPsk(pk_sender, psk_bundle);
            (sender_mode, receiver_mode)
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
    let msg_len = csprng.gen::<u8>() as usize;
    let msg_buf = {
        let mut buf = [0u8; 255];
        csprng.fill_bytes(&mut buf);
        buf
    };
    let aad_len = csprng.gen::<u8>() as usize;
    let aad_buf = {
        let mut buf = [0u8; 255];
        csprng.fill_bytes(&mut buf);
        buf
    };
    let aad = &aad_buf[..aad_len];

    // Do 1000 iterations of encryption-decryption. The underlying sequence number increments
    // each time.
    for i in 0..1000 {
        let plaintext = &mut msg_buf.clone()[..msg_len];
        // Encrypt the plaintext
        let tag = sender
            .seal_in_place_detached(&mut plaintext[..], &aad)
            .unwrap_or_else(|_| panic!("seal() #{} failed", i));
        // Rename for clarity
        let ciphertext = plaintext;

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
        if &msg_buf[..msg_len] != roundtrip_plaintext {
            return false;
        }
    }

    true
}

/// An RNG whose stream is entirely given by an iterator. This is for known-answer tests whose
/// random coins are given directly.
pub(crate) struct PromptedRng<'a> {
    iter: core::slice::Iter<'a, u8>,
}

impl PromptedRng<'_> {
    pub(crate) fn new(prompt: &[u8]) -> PromptedRng {
        PromptedRng {
            iter: prompt.iter(),
        }
    }

    fn next(&mut self) -> u8 {
        self.iter.next().cloned().unwrap()
    }

    pub(crate) fn assert_done(&mut self) -> () {
        assert!(
            self.iter.next().is_none(),
            "PromptedRng still had {} bytes in the buffer",
            self.iter.len() + 1,
        )
    }
}

impl CryptoRng for PromptedRng<'_> {}

impl RngCore for PromptedRng<'_> {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(self.fill_bytes(dest))
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for d in dst.iter_mut() {
            *d = self.next();
        }
    }
}
