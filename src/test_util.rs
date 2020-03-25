use crate::{
    aead::{Aead, AeadCtx, AeadKey, AeadNonce, AssociatedData},
    dh::DiffieHellman,
    kdf::Kdf,
    op_mode::{OpModeR, OpModeS, Psk, PskBundle},
    setup::{setup_receiver, setup_sender, ExporterSecret},
};

use rand::{Rng, RngCore};

/// Makes an random PSK bundle
pub(crate) fn gen_psk_bundle<K: Kdf>() -> PskBundle<K> {
    let mut csprng = rand::thread_rng();

    let psk = {
        let mut buf = <Psk<K> as Default>::default();
        csprng.fill_bytes(buf.as_mut_slice());
        buf
    };
    let psk_id = {
        let mut buf = [0u8; 32];
        csprng.fill_bytes(&mut buf);
        buf.to_vec()
    };

    PskBundle::<K> { psk, psk_id }
}

pub(crate) fn gen_ctx_simple_pair<A: Aead, K: Kdf>() -> (AeadCtx<A, K>, AeadCtx<A, K>) {
    let mut csprng = rand::thread_rng();

    // Initialize the key and nonce
    let key = {
        let mut buf = AeadKey::<A>::default();
        csprng.fill_bytes(buf.as_mut_slice());
        buf
    };
    let nonce = {
        let mut buf = AeadNonce::<A>::default();
        csprng.fill_bytes(buf.as_mut_slice());
        buf
    };
    let exporter_secret = {
        let mut buf = ExporterSecret::<K>::default();
        csprng.fill_bytes(buf.as_mut_slice());
        buf
    };

    let ctx1 = AeadCtx::new(key.clone(), nonce.clone(), exporter_secret.clone());
    let ctx2 = AeadCtx::new(key.clone(), nonce.clone(), exporter_secret.clone());

    (ctx1, ctx2)
}

/// Makes a pair of identical encryption contexts by simulating a KEM exchange
pub(crate) fn gen_ctx_kem_pair<A: Aead, Dh: DiffieHellman, K: Kdf>(
) -> (AeadCtx<A, K>, AeadCtx<A, K>) {
    let mut csprng = rand::thread_rng();

    // Set up an arbitrary info string, a random PSK, and an arbitrary PSK ID
    let info = b"why would you think in a million years that that would actually work";
    let psk_bundle = gen_psk_bundle::<K>();

    // Generate the sender's and receiver's long-term keypairs
    let (sk_sender_id, pk_sender_id) = Dh::gen_keypair(&mut csprng);
    let (sk_recip, pk_recip) = Dh::gen_keypair(&mut csprng);

    // Construct the sender's encryption context, and get an encapped key
    let sender_mode = OpModeS::<Dh, _>::AuthPsk(sk_sender_id, psk_bundle.clone());
    let (encapped_key, aead_ctx1) = setup_sender(&sender_mode, &pk_recip, &info[..], &mut csprng);

    // Use the encapped key to derive the reciever's encryption context
    let receiver_mode = OpModeR::<Dh, _>::AuthPsk(pk_sender_id, psk_bundle);
    let aead_ctx2 = setup_receiver(&receiver_mode, &sk_recip, &encapped_key, &info[..]);

    (aead_ctx1, aead_ctx2)
}

/// Asserts the equivalence of two encryption contexts by doing some encryption-decryption
/// round trips. Panics if not equal.
pub(crate) fn assert_aead_ctx_eq<A: Aead, K: Kdf>(
    ctx1: &mut AeadCtx<A, K>,
    ctx2: &mut AeadCtx<A, K>,
) {
    let mut csprng = rand::thread_rng();

    // Some random input data
    let msg = {
        let len = csprng.gen::<u8>();
        let mut buf = vec![0u8; len as usize];
        csprng.fill_bytes(&mut buf);
        buf
    };
    let aad_bytes = {
        let len = csprng.gen::<u8>();
        let mut buf = vec![0u8; len as usize];
        csprng.fill_bytes(&mut buf);
        buf
    };
    let aad = AssociatedData(&aad_bytes);

    // Do 1000 iterations of encryption-decryption. The underlying sequence number increments
    // each time.
    for i in 0..1000 {
        let mut plaintext = msg.clone();
        // Encrypt the plaintext
        let tag = ctx1
            .seal(&mut plaintext[..], aad)
            .expect(&format!("seal() #{} failed", i));
        // Rename for clarity
        let mut ciphertext = plaintext;

        // Now to decrypt on the other side
        ctx2.open(&mut ciphertext[..], aad, &tag)
            .expect(&format!("open() #{} failed", i));
        // Rename for clarity
        let roundtrip_plaintext = ciphertext;

        // Make sure the output message was the same as the input message
        assert_eq!(msg, roundtrip_plaintext);
    }
}
