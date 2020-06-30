//! This file describes a simple interaction between a client and a server. Here's the flow:
//!  1. The server initializes itself with a new public-private keypair.
//!  2. The client encapsulates a symmetric key, and then uses it to encrypt a message. It then
//!     sends the server the encapsulated key and the authenticated ciphertext.
//!  3. The server derives the encryption context from the encapsulated key and uses it to decrypt
//!     the ciphertext.
//!
//! Concepts not covered in this example:
//!  * Different operation modes (Auth, Psk, AuthPsk). See the docs on `OpModeR` and `OpModeS`
//!    types for more info
//!  * The single-shot API. See the methods exposed in the `single_shot` module for more info. The
//!    single-shot methods are basically just `setup` followed by `seal/open`.
//!  * Proper error handling. Everything here just panics when an error is encountered. It is up to
//!    the user of this library to do the appropriate thing when a function returns an error.

use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    EncappedKey, Kem as KemTrait, KeyExchange, Marshallable, OpModeR, OpModeS, Unmarshallable,
};

use rand::{rngs::StdRng, SeedableRng};

const INFO_STR: &'static [u8] = b"example session";

// These are the only algorithms we're gonna use for this example
type Kem = hpke::kem::X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

// The KEX is dependent on the choice of KEM
type Kex = <Kem as KemTrait>::Kex;

// Initialize the server with a fresh keypair
fn server_init() -> (
    <Kex as KeyExchange>::PrivateKey,
    <Kex as KeyExchange>::PublicKey,
) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}

// Given a message and associated data, returns an encapsulated key, ciphertext, and tag. The
// ciphertext is encrypted with the shared AEAD context
fn client_encrypt_msg(
    msg: &[u8],
    associated_data: &[u8],
    server_pk: &<Kex as KeyExchange>::PublicKey,
) -> (EncappedKey<Kex>, Vec<u8>, AeadTag<Aead>) {
    let mut csprng = StdRng::from_entropy();

    // Encapsulate a key and use the resulting shared secret to encrypt a message. The AEAD context
    // is what you use to encrypt.
    let (encapped_key, mut sender_ctx) =
        hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, server_pk, INFO_STR, &mut csprng)
            .expect("invalid server pubkey!");

    // On success, seal() will encrypt the plaintext in place
    let mut msg_copy = msg.to_vec();
    let tag = sender_ctx
        .seal(&mut msg_copy, associated_data)
        .expect("encryption failed!");

    // Rename for clarity
    let ciphertext = msg_copy;

    (encapped_key, ciphertext, tag)
}

// Returns the decrypted client message
fn server_decrypt_msg(
    server_sk_bytes: &[u8],
    encapped_key_bytes: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
    tag_bytes: &[u8],
) -> Vec<u8> {
    // We have to unmarshal the secret key, AEAD tag, and encapsulated pubkey. These fail if the
    // bytestrings are the wrong length.
    let server_sk = <Kex as KeyExchange>::PrivateKey::unmarshal(server_sk_bytes)
        .expect("could not deserialize server privkey!");
    let tag = AeadTag::<Aead>::unmarshal(tag_bytes).expect("could not deserialize AEAD tag!");
    let encapped_key = EncappedKey::<Kex>::unmarshal(encapped_key_bytes)
        .expect("could not deserialize the encapsulated pubkey!");

    // Decapsulate and derive the shared secret. This creates a shared AEAD context.
    let mut receiver_ctx =
        hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &server_sk, &encapped_key, INFO_STR)
            .expect("failed to set up receiver!");

    // On success, open() will decrypt the ciphertext in place
    let mut ciphertext_copy = ciphertext.to_vec();
    receiver_ctx
        .open(&mut ciphertext_copy, associated_data, &tag)
        .expect("invalid ciphertext!");

    // Rename for clarity
    let plaintext = ciphertext_copy;

    plaintext
}

fn main() {
    // Set up the server
    let (server_privkey, server_pubkey) = server_init();

    // The message to be encrypted
    let msg = b"Kat Branchman";
    // Associated data that's authenticated but left unencrypted
    let associated_data = b"Mr. Meow";

    // Let the client send a message to the server using the server's pubkey
    let (encapped_key, ciphertext, tag) = client_encrypt_msg(msg, associated_data, &server_pubkey);

    // Now imagine we send everything over the wire, so we have to serialize it
    let encapped_key_bytes = encapped_key.marshal();
    let tag_bytes = tag.marshal();

    // Now imagine the server had to reboot so it saved its private key in byte format
    let server_privkey_bytes = server_privkey.marshal();

    // Now let the server decrypt the message. The marshal() calls returned a GenericArray, so we
    // have to convert them to slices before sending them
    let decrypted_msg = server_decrypt_msg(
        server_privkey_bytes.as_slice(),
        encapped_key_bytes.as_slice(),
        &ciphertext,
        associated_data,
        tag_bytes.as_slice(),
    );

    // Make sure everything decrypted correctly
    assert_eq!(decrypted_msg, msg);

    println!("MESSAGE SUCCESSFULLY SENT AND RECEIVED");
}
