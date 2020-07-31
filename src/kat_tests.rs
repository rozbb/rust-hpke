use crate::{
    aead::{Aead, AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as KdfTrait},
    kem::{encap_with_eph, DhP256HkdfSha256, EncappedKey, Kem as KemTrait, X25519HkdfSha256},
    kex::{Deserializable, KeyExchange, Serializable},
    op_mode::{OpModeR, PskBundle},
    setup::setup_receiver,
};

extern crate std;
use std::{fs::File, string::String, vec::Vec};

use hex;
use serde::{de::Error as SError, Deserialize, Deserializer};
use serde_json;

/// Asserts that the given serializable values are equal
macro_rules! assert_serializable_eq {
    ($a:expr, $b:expr, $args:tt) => {
        assert_eq!($a.to_bytes(), $b.to_bytes(), $args)
    };
}

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
#[derive(Clone, Deserialize, Debug)]
struct MainTestVector {
    // Parameters
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    #[serde(deserialize_with = "bytes_from_hex")]
    info: Vec<u8>,

    // Keying material
    #[serde(rename = "seedR", deserialize_with = "bytes_from_hex")]
    ikm_recip: Vec<u8>,
    #[serde(default, rename = "seedS", deserialize_with = "bytes_from_hex_opt")]
    ikm_sender: Option<Vec<u8>>,
    #[serde(rename = "seedE", deserialize_with = "bytes_from_hex")]
    ikm_eph: Vec<u8>,

    // Private keys
    #[serde(rename = "skRm", deserialize_with = "bytes_from_hex")]
    sk_recip: Vec<u8>,
    #[serde(default, rename = "skSm", deserialize_with = "bytes_from_hex_opt")]
    sk_sender: Option<Vec<u8>>,
    #[serde(rename = "skEm", deserialize_with = "bytes_from_hex")]
    sk_eph: Vec<u8>,

    // Preshared Key Bundle
    #[serde(default, deserialize_with = "bytes_from_hex_opt")]
    psk: Option<Vec<u8>>,
    #[serde(default, rename = "psk_id", deserialize_with = "bytes_from_hex_opt")]
    psk_id: Option<Vec<u8>>,

    // Public Keys
    #[serde(rename = "pkRm", deserialize_with = "bytes_from_hex")]
    pk_recip: Vec<u8>,
    #[serde(default, rename = "pkSm", deserialize_with = "bytes_from_hex_opt")]
    pk_sender: Option<Vec<u8>>,
    #[serde(rename = "pkEm", deserialize_with = "bytes_from_hex")]
    pk_eph: Vec<u8>,

    // Key schedule inputs and computations
    #[serde(rename = "enc", deserialize_with = "bytes_from_hex")]
    encapped_key: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_hex")]
    shared_secret: Vec<u8>,
    #[serde(rename = "key_schedule_context", deserialize_with = "bytes_from_hex")]
    _hpke_context: Vec<u8>,
    #[serde(rename = "secret", deserialize_with = "bytes_from_hex")]
    _key_schedule_secret: Vec<u8>,
    #[serde(rename = "key", deserialize_with = "bytes_from_hex")]
    _aead_key: Vec<u8>,
    #[serde(rename = "nonce", deserialize_with = "bytes_from_hex")]
    _aead_nonce: Vec<u8>,
    #[serde(rename = "exporter_secret", deserialize_with = "bytes_from_hex")]
    _exporter_secret: Vec<u8>,

    encryptions: Vec<EncryptionTestVector>,
    exports: Vec<ExporterTestVector>,
}

#[derive(Clone, Deserialize, Debug)]
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

#[derive(Clone, Deserialize, Debug)]
struct ExporterTestVector {
    #[serde(rename = "exportContext", deserialize_with = "bytes_from_hex")]
    export_ctx: Vec<u8>,
    #[serde(rename = "exportLength")]
    export_len: usize,
    #[serde(rename = "exportValue", deserialize_with = "bytes_from_hex")]
    export_val: Vec<u8>,
}

/// Returns a KEX keypair given the secret bytes and pubkey bytes, and ensures that the pubkey does
/// indeed correspond to that secret key
fn get_and_validate_keypair<Kex: KeyExchange>(
    sk_bytes: &[u8],
    pk_bytes: &[u8],
) -> (Kex::PrivateKey, Kex::PublicKey) {
    // Deserialize the secret key
    let sk = <Kex as KeyExchange>::PrivateKey::from_bytes(sk_bytes).unwrap();
    // Deserialize the pubkey
    let pk = <Kex as KeyExchange>::PublicKey::from_bytes(pk_bytes).unwrap();

    // Make sure the derived pubkey matches the given pubkey
    assert_serializable_eq!(pk, Kex::sk_to_pk(&sk), "derived pubkey doesn't match given");

    (sk, pk)
}

/// Constructs an `OpModeR` from the given components. The variant constructed is determined solely
/// by `mode_id`. This will panic if there is insufficient data to construct the variants specified
/// by `mode_id`.
fn make_op_mode_r<'a, Kex: KeyExchange>(
    mode_id: u8,
    pk: Option<Kex::PublicKey>,
    psk: Option<&'a [u8]>,
    psk_id: Option<&'a [u8]>,
) -> OpModeR<'a, Kex> {
    // Deserialize the optional bundle
    let bundle = psk.map(|bytes| PskBundle {
        psk: bytes,
        psk_id: psk_id.unwrap(),
    });

    // These better be set if the mode ID calls for them
    match mode_id {
        0 => OpModeR::Base,
        1 => OpModeR::Psk(bundle.unwrap()),
        2 => OpModeR::Auth(pk.unwrap()),
        3 => OpModeR::AuthPsk(pk.unwrap(), bundle.unwrap()),
        _ => panic!("Invalid mode ID: {}", mode_id),
    }
}

// This does all the legwork
fn test_case<A: Aead, Kdf: KdfTrait, Kem: KemTrait>(tv: MainTestVector) {
    // First, deserialize all the relevant keys so we can reconstruct the encapped key
    let recip_keypair = get_and_validate_keypair::<Kem::Kex>(&tv.sk_recip, &tv.pk_recip);
    let eph_keypair = get_and_validate_keypair::<Kem::Kex>(&tv.sk_eph, &tv.pk_eph);
    let sender_keypair = {
        let pk_sender = &tv.pk_sender.as_ref();
        tv.sk_sender
            .as_ref()
            .map(|sk| get_and_validate_keypair::<Kem::Kex>(sk, pk_sender.unwrap()))
    };

    // Make sure the keys match what we would've gotten had we used DeriveKeyPair
    {
        let derived_kp = Kem::derive_keypair(&tv.ikm_recip);
        assert_serializable_eq!(recip_keypair.0, derived_kp.0, "sk recip doesn't match");
        assert_serializable_eq!(recip_keypair.1, derived_kp.1, "pk recip doesn't match");
    }
    {
        let derived_kp = Kem::derive_keypair(&tv.ikm_eph);
        assert_serializable_eq!(eph_keypair.0, derived_kp.0, "sk eph doesn't match");
        assert_serializable_eq!(eph_keypair.1, derived_kp.1, "pk eph doesn't match");
    }
    if let Some(sks) = sender_keypair.as_ref() {
        let derived_kp = Kem::derive_keypair(&tv.ikm_sender.unwrap());
        assert_serializable_eq!(sks.0, derived_kp.0, "sk sender doesn't match");
        assert_serializable_eq!(sks.1, derived_kp.1, "pk sender doesn't match");
    }

    let (sk_recip, pk_recip) = recip_keypair;
    let (sk_eph, _) = eph_keypair;

    // Now derive the encapped key with the deterministic encap function, using all the inputs
    // above
    let (shared_secret, encapped_key) =
        encap_with_eph::<Kem>(&pk_recip, sender_keypair.as_ref(), sk_eph.clone())
            .expect("encap failed");

    // Assert that the derived shared secret key is identical to the one provided
    assert_eq!(
        shared_secret.as_slice(),
        tv.shared_secret.as_slice(),
        "shared_secret doesn't match"
    );

    // Assert that the derived encapped key is identical to the one provided
    {
        let provided_encapped_key = EncappedKey::<Kem::Kex>::from_bytes(&tv.encapped_key).unwrap();
        assert_serializable_eq!(
            encapped_key,
            provided_encapped_key,
            "encapped keys don't match"
        );
    }

    // We're going to test the encryption contexts. First, construct the appropriate OpMode.
    let mode = make_op_mode_r(
        tv.mode,
        sender_keypair.map(|(_, pk)| pk),
        tv.psk.as_ref().map(Vec::as_slice),
        tv.psk_id.as_ref().map(Vec::as_slice),
    );
    let mut aead_ctx = setup_receiver::<A, Kdf, Kem>(&mode, &sk_recip, &encapped_key, &tv.info)
        .expect("setup_receiver failed");

    // Go through all the plaintext-ciphertext pairs of this test vector and assert the
    // ciphertext decrypts to the corresponding plaintext
    for enc_packet in tv.encryptions {
        let aad = enc_packet.aad;

        // The test vector's ciphertext is of the form ciphertext || tag. Break it up into two
        // pieces so we can call open() on it.
        let (mut ciphertext, tag) = {
            let mut ciphertext_and_tag = enc_packet.ciphertext;
            let total_len = ciphertext_and_tag.len();

            let tag_size = AeadTag::<A>::size();
            let (ciphertext_bytes, tag_bytes) =
                ciphertext_and_tag.split_at_mut(total_len - tag_size);

            (
                ciphertext_bytes.to_vec(),
                AeadTag::from_bytes(tag_bytes).unwrap(),
            )
        };

        // Open the ciphertext in place and assert that this succeeds
        aead_ctx
            .open(&mut ciphertext, &aad, &tag)
            .expect("open failed");
        // Rename for clarity
        let plaintext = ciphertext;

        // Assert the plaintext equals the expected plaintext
        assert_eq!(
            plaintext,
            enc_packet.plaintext.as_slice(),
            "plaintexts don't match"
        );
    }

    // Now check that AeadCtx::export returns the expected values
    for export in tv.exports {
        let mut exported_val = vec![0u8; export.export_len];
        aead_ctx
            .export(&export.export_ctx, &mut exported_val)
            .unwrap();
        assert_eq!(exported_val, export.export_val, "export values don't match");
    }
}

// This macro takes in all the supported AEADs, KDFs, and KEMs, and dispatches the given test
// vector to the test case with the appropriate types
macro_rules! dispatch_testcase {
    // Step 1: Roll up the AEAD, KDF, and KEM types into tuples. We'll unroll them later
    ($tv:ident, ($( $aead_ty:ty ),*), ($( $kdf_ty:ty ),*), ($( $kem_ty:ty ),*)) => {
        dispatch_testcase!(@tup1 $tv, ($( $aead_ty ),*), ($( $kdf_ty ),*), ($( $kem_ty ),*))
    };
    // Step 2: Expand with respect to every AEAD
    (@tup1 $tv:ident, ($( $aead_ty:ty ),*), $kdf_tup:tt, $kem_tup:tt) => {
        $(
            dispatch_testcase!(@tup2 $tv, $aead_ty, $kdf_tup, $kem_tup);
        )*
    };
    // Step 3: Expand with respect to every KDF
    (@tup2 $tv:ident, $aead_ty:ty, ($( $kdf_ty:ty ),*), $kem_tup:tt) => {
        $(
            dispatch_testcase!(@tup3 $tv, $aead_ty, $kdf_ty, $kem_tup);
        )*
    };
    // Step 4: Expand with respect to every KEM
    (@tup3 $tv:ident, $aead_ty:ty, $kdf_ty:ty, ($( $kem_ty:ty ),*)) => {
        $(
            dispatch_testcase!(@base $tv, $aead_ty, $kdf_ty, $kem_ty);
        )*
    };
    // Step 5: Now that we're only dealing with 1 type of each kind, do the dispatch. If the test
    // vector matches the IDs of these types, run the test case.
    (@base $tv:ident, $aead_ty:ty, $kdf_ty:ty, $kem_ty:ty) => {
        if let (<$aead_ty>::AEAD_ID, <$kdf_ty>::KDF_ID, <$kem_ty>::KEM_ID) =
            ($tv.aead_id, $tv.kdf_id, $tv.kem_id)
        {
            println!(
                "Running test case on {}, {}, {}",
                stringify!($aead_ty),
                stringify!($kdf_ty),
                stringify!($kem_ty)
            );

            let tv = $tv.clone();
            test_case::<$aead_ty, $kdf_ty, $kem_ty>(tv);

            // This is so that code that comes after a dispatch_testcase! invocation will know that
            // the test vector matched no known ciphersuites
            continue;
        }
    };
}

#[test]
fn kat_test() {
    let file = File::open("test-vectors-580119b.json").unwrap();
    let tvs: Vec<MainTestVector> = serde_json::from_reader(file).unwrap();

    for tv in tvs.into_iter() {
        // Ignore everything that doesn't use X25519 or P256, since that's all we support right now
        if tv.kem_id != DhP256HkdfSha256::KEM_ID && tv.kem_id != X25519HkdfSha256::KEM_ID {
            continue;
        }

        // This unrolls into 18 `if let` statements
        dispatch_testcase!(
            tv,
            (AesGcm128, AesGcm256, ChaCha20Poly1305),
            (HkdfSha256, HkdfSha384, HkdfSha512),
            (X25519HkdfSha256, DhP256HkdfSha256)
        );

        // The above macro has a `continue` in every branch. We only get to this line if it failed
        // to match every combination of the above primitives.
        panic!(
            "Unrecognized (AEAD ID, KDF ID, KEM ID) combo: ({}, {}, {})",
            tv.aead_id, tv.kdf_id, tv.kem_id
        );
    }
}
