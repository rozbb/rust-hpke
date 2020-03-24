use crate::{
    aead::{Aead, AeadTag, AesGcm128, AesGcm256, AssociatedData, ChaCha20Poly1305},
    dh::{x25519::X25519, DiffieHellman, Marshallable, MarshalledPrivkey, MarshalledPubkey},
    kdf::{HkdfSha256, Kdf},
    kem::encap_with_eph,
    op_mode::{OpModeR, Psk, PskBundle},
    setup::setup_receiver,
};

use std::fs::File;

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

// Tells serde how to deserialize bytes from an optional field with hex encoding
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
    _shared_secret: Vec<u8>,
    #[serde(rename = "context", deserialize_with = "bytes_from_hex")]
    _hpke_context: Vec<u8>,
    #[serde(rename = "secret", deserialize_with = "bytes_from_hex")]
    _key_schedule_secret: Vec<u8>,
    #[serde(rename = "key", deserialize_with = "bytes_from_hex")]
    _aead_key: Vec<u8>,
    #[serde(rename = "nonce", deserialize_with = "bytes_from_hex")]
    _aead_nonce: Vec<u8>,
    #[serde(rename = "exporterSecret", deserialize_with = "bytes_from_hex")]
    _exporter_secret: Vec<u8>,

    encryptions: Vec<EncryptionTestVector>,
    exports: Vec<ExporterTestVector>,
}

#[derive(Deserialize)]
struct EncryptionTestVector {
    #[serde(deserialize_with = "bytes_from_hex")]
    plaintext: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_hex")]
    aad: Vec<u8>,
    #[serde(rename = "nonce", deserialize_with = "bytes_from_hex")]
    _nonce: Vec<u8>,
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

/// Returns a DH keypair given the secret bytes and pubkey bytes, and ensures that the pubkey does
/// indeed correspond to that secret key
fn get_and_assert_keypair<Dh: DiffieHellman>(
    sk_bytes: &[u8],
    pk_bytes: &[u8],
) -> (Dh::PrivateKey, Dh::PublicKey) {
    // Unmarshall the secret key
    let sk = {
        let mut buf = <MarshalledPrivkey<Dh> as Default>::default();
        buf.copy_from_slice(sk_bytes);
        <Dh as DiffieHellman>::PrivateKey::unmarshal(buf)
    };
    // Unmarshall the pubkey
    let pk = {
        let mut buf = <MarshalledPubkey<Dh> as Default>::default();
        buf.copy_from_slice(pk_bytes);
        <Dh as DiffieHellman>::PublicKey::unmarshal(buf)
    };

    // Make sure the derived pubkey matches the given pubkey
    assert_eq!(pk.marshal(), Dh::sk_to_pk(&sk).marshal());

    (sk, pk)
}

/// Constructs an `OpModeR` from the given components. The variant constructed is determined solely
/// by `mode_id`. This will panic if there is insufficient data to construct the variants specified
/// by `mode_id`.
fn make_op_mode_r<Dh: DiffieHellman, K: Kdf>(
    mode_id: u8,
    pk_sender_bytes: Option<Vec<u8>>,
    psk: Option<Vec<u8>>,
    psk_id: Option<Vec<u8>>,
) -> OpModeR<Dh, K> {
    // Unmarshal the optional pubkey
    let pk = pk_sender_bytes.map(|bytes| {
        let mut buf = <MarshalledPubkey<Dh> as Default>::default();
        buf.copy_from_slice(&bytes);
        <Dh as DiffieHellman>::PublicKey::unmarshal(buf)
    });
    // Unmarshal the optinoal bundle
    let bundle = psk.map(|bytes| {
        let mut buf = <Psk<K> as Default>::default();
        buf.copy_from_slice(&bytes);
        PskBundle::<K> {
            psk: buf,
            psk_id: psk_id.unwrap(),
        }
    });

    // These better be set if the mode ID calls for them
    match mode_id {
        0 => OpModeR::Base,
        1 => OpModeR::Psk(bundle.unwrap()),
        2 => OpModeR::Auth(pk.unwrap()),
        3 => OpModeR::PskAuth(bundle.unwrap(), pk.unwrap()),
        _ => panic!("Invalid mode ID: {}", mode_id),
    }
}

// Implements a test case for a given AEAD implementation
macro_rules! test_case {
    ($tv:ident, $aead_ty:ty) => {{
        type A = $aead_ty;
        type Dh = X25519;
        type K = HkdfSha256;

        // First, unmarshall all the relevant keys so we can reconstruct the encapped key
        let (sk_recip, pk_recip) = get_and_assert_keypair::<Dh>(&$tv.sk_recip, &$tv.pk_recip);
        let (sk_eph, pk_eph) = get_and_assert_keypair::<Dh>(&$tv.sk_eph, &$tv.pk_eph);
        let sk_sender = $tv.sk_sender.map(|bytes| {
            let mut buf = <MarshalledPubkey<Dh> as Default>::default();
            buf.copy_from_slice(&bytes);
            <Dh as DiffieHellman>::PrivateKey::unmarshal(buf)
        });

        // Now derive the encapped key with the deterministic encap function, using all the inputs
        // above
        let (_, encapped_key) = encap_with_eph::<Dh>(
            &pk_recip,
            sk_sender.as_ref(),
            sk_eph.clone(),
            pk_eph.clone(),
        );
        // Now assert that the derived encapped key is identical to the one provided
        assert_eq!(
            encapped_key.marshal().as_slice(),
            $tv.encapped_key.as_slice()
        );

        // We're going to test the encryption contexts. First, construct the appropriate OpMode.
        let mode = make_op_mode_r($tv.mode, $tv.pk_sender, $tv.psk, $tv.psk_id);
        let mut aead_ctx = setup_receiver::<A, Dh, K>(&mode, &sk_recip, &encapped_key, &$tv.info);

        // Go through all the plaintext-ciphertext pairs of this test vector and assert the
        // ciphertext decrypts to the corresponding plaintext
        for enc_packet in $tv.encryptions {
            let aad = enc_packet.aad;

            // The test vector's ciphertext is of the form ciphertext || tag. Break it up into two
            // pieces so we can call open() on it.
            let (mut ciphertext, tag) = {
                let mut ciphertext_and_tag = enc_packet.ciphertext;
                let total_len = ciphertext_and_tag.len();

                let mut tag_buf = <AeadTag<A> as Default>::default();
                let (ciphertext_bytes, tag_bytes) =
                    ciphertext_and_tag.split_at_mut(total_len - tag_buf.len());

                tag_buf.copy_from_slice(tag_bytes);

                (ciphertext_bytes.to_vec(), tag_buf)
            };

            // Open the ciphertext in place and assert that this succeeds
            aead_ctx
                .open(&mut ciphertext, AssociatedData(&aad), &tag)
                .unwrap();
            // Rename for clarity
            let plaintext = ciphertext;

            // Assert the plaintext equals the expected plaintext
            assert_eq!(plaintext, enc_packet.plaintext.as_slice());
        }

        // Now check that AeadCtx::export returns the expected values
        for export in $tv.exports {
            let mut exported_val = vec![0u8; export.export_len];
            aead_ctx.export(&export.info, &mut exported_val).unwrap();
            assert_eq!(exported_val, export.export_val);
        }
    }};
}

#[test]
fn kat_test() {
    //let file = File::open("test-vectors-76e2596.json").unwrap();
    let file = File::open("test-vectors-modified.json").unwrap();
    let tvs: Vec<MainTestVector> = serde_json::from_reader(file).unwrap();

    for tv in tvs.into_iter() {
        // Ignore pretty much all but one test vector for now
        if tv.kdf_id != HkdfSha256::KDF_ID || tv.kem_id != X25519::KEM_ID {
            continue;
        }

        match tv.aead_id {
            AesGcm128::AEAD_ID => test_case!(tv, AesGcm128),
            AesGcm256::AEAD_ID => test_case!(tv, AesGcm256),
            ChaCha20Poly1305::AEAD_ID => test_case!(tv, ChaCha20Poly1305),
            _ => panic!("Invalid AEAD ID: {}", tv.aead_id),
        };
    }
}
