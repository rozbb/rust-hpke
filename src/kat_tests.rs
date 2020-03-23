use std::{fs::File, path::Path};

use hex;
use serde::{de::Error as SError, Deserialize, Deserializer};
use serde_json;

// Tells serde how to deserialize bytes from the hex representation
fn bytes_from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut hex_str = String::deserialize(deserializer)?;
    // Prepend a 0 if it's not even length
    if hex_str.len() % 2 == 1 {
        hex_str.insert(0, '0');
    }
    hex::decode(hex_str).map_err(|e| SError::custom(format!("{:?}", e)))
}

fn bytes_from_hex_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    bytes_from_hex(deserializer).map(|v| Some(v))
}

// Each individual test case looks like this
#[derive(Deserialize)]
struct MainTestVector {
    // Parameters
    mode: u8,
    #[serde(rename = "kemID")]
    kem_id: u16,
    #[serde(rename = "kdfID")]
    kdf_id: u16,
    #[serde(rename = "aeadID")]
    aead_id: u16,
    #[serde(deserialize_with = "bytes_from_hex")]
    info: Vec<u8>,

    // Private keys
    #[serde(rename = "skR", deserialize_with = "bytes_from_hex")]
    sk_recip: Vec<u8>,
    #[serde(rename = "skS", deserialize_with = "bytes_from_hex_opt")]
    sk_sender: Option<Vec<u8>>,
    #[serde(rename = "skE", deserialize_with = "bytes_from_hex")]
    sk_eph: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_hex_opt")]
    psk: Option<Vec<u8>>,
    #[serde(rename = "pskID", deserialize_with = "bytes_from_hex_opt")]
    psk_id: Option<Vec<u8>>,

    // Public Keys
    #[serde(rename = "pkR", deserialize_with = "bytes_from_hex")]
    pk_recip: Vec<u8>,
    #[serde(rename = "pkS", deserialize_with = "bytes_from_hex_opt")]
    pk_sender: Option<Vec<u8>>,
    #[serde(rename = "pkE", deserialize_with = "bytes_from_hex")]
    pk_eph: Vec<u8>,

    // Key schedule inputs and computations
    #[serde(rename = "enc", deserialize_with = "bytes_from_hex")]
    encapped_key: Vec<u8>,
    #[serde(rename = "zz", deserialize_with = "bytes_from_hex")]
    shared_secret: Vec<u8>,
    #[serde(rename = "context", deserialize_with = "bytes_from_hex")]
    hpke_context: Vec<u8>,
    #[serde(rename = "secret", deserialize_with = "bytes_from_hex")]
    key_schedule_secret: Vec<u8>,
    #[serde(rename = "key", deserialize_with = "bytes_from_hex")]
    aead_key: Vec<u8>,
    #[serde(rename = "nonce", deserialize_with = "bytes_from_hex")]
    aead_nonce: Vec<u8>,
    #[serde(rename = "exporterSecret", deserialize_with = "bytes_from_hex")]
    exporter_secret: Vec<u8>,

    encryptions: Vec<EncryptionTestVector>,
    exports: Vec<ExporterTestVector>,
}

#[derive(Deserialize)]
struct EncryptionTestVector {
    #[serde(deserialize_with = "bytes_from_hex")]
    plaintext: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_hex")]
    aad: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_hex")]
    nonce: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_hex")]
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
struct ExporterTestVector {
    #[serde(rename = "context", deserialize_with = "bytes_from_hex")]
    info: Vec<u8>,
    #[serde(rename = "exportLength")]
    export_len: usize,
    #[serde(rename = "exportValue", deserialize_with = "bytes_from_hex")]
    export_val: Vec<u8>,
}

use crate::{
    aead::{Aead, ChaCha20Poly1305},
    dh::{x25519::X25519Impl, DiffieHellman, Marshallable, MarshalledPrivkey, MarshalledPubkey},
    kdf::{HkdfSha256, Kdf},
};

#[test]
fn kat_test() {
    let file = File::open("test-vectors-76e2596.json").unwrap();
    let tvs: Vec<MainTestVector> = serde_json::from_reader(file).unwrap();

    for tv in tvs.into_iter() {
        if tv.aead_id != ChaCha20Poly1305::AEAD_ID
            || tv.kdf_id != HkdfSha256::KDF_ID
            || tv.kem_id != X25519Impl::KEM_ID
            || tv.mode != 0
        {
            continue;
        }

        let sk_recip = {
            let mut buf = <MarshalledPrivkey<X25519Impl> as Default>::default();
            buf.copy_from_slice(&tv.sk_recip);
            <X25519Impl as DiffieHellman>::PrivateKey::unmarshal(buf)
        };
        let pk_recip = {
            let mut buf = <MarshalledPubkey<X25519Impl> as Default>::default();
            buf.copy_from_slice(&tv.pk_recip);
            <X25519Impl as DiffieHellman>::PublicKey::unmarshal(buf)
        };

        // Make sure the derived pubkey matches the given pubkey
        assert_eq!(
            pk_recip.marshal(),
            X25519Impl::sk_to_pk(&sk_recip).marshal()
        );
    }
}
