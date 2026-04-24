use crate::{
    aead::{Aead, AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as KdfTrait, KdfShake256},
    kem::{
        DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, Kem as KemTrait, MlKem768P256,
        SharedSecret, X25519HkdfSha256, XWing,
    },
    op_mode::{OpModeR, PskBundle},
    setup::setup_receiver,
    Deserializable, HpkeError, Serializable,
};

use std::{fs::File, string::String, vec::Vec};

use serde::{de::Error as SError, Deserialize, Deserializer};

// For known-answer tests we need to be able to encap with fixed randomness. This allows that.
pub(crate) trait TestableKem: KemTrait {
    /// The ephemeral key used in encapsulation. This is the same thing as a private key in the
    /// case of DHKEM, but this is not always true
    type EphemeralKey: Deserializable;

    // Encapsulate with a fixed ephemeral key. Only makes sense in DHKEMs
    #[doc(hidden)]
    fn encap_with_eph(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        sk_eph: Self::EphemeralKey,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError>;

    // Encapsulate with fixed randomness
    #[doc(hidden)]
    fn encap_det(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        randomness: &[u8],
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError>;
}

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
    bytes_from_hex(deserializer).map(Some)
}

// Each individual test case looks like this
#[derive(Clone, serde::Deserialize, Debug)]
struct MainTestVector {
    // Parameters
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    #[serde(deserialize_with = "bytes_from_hex")]
    info: Vec<u8>,

    // Keying material
    #[serde(rename = "ikmR", deserialize_with = "bytes_from_hex")]
    ikm_recip: Vec<u8>,
    #[serde(default, rename = "ikmS", deserialize_with = "bytes_from_hex_opt")]
    ikm_sender: Option<Vec<u8>>,
    #[serde(rename = "ikmE", deserialize_with = "bytes_from_hex")]
    ikm_eph: Vec<u8>,

    // Private keys
    #[serde(rename = "skRm", deserialize_with = "bytes_from_hex")]
    sk_recip: Vec<u8>,
    #[serde(default, rename = "skSm", deserialize_with = "bytes_from_hex_opt")]
    sk_sender: Option<Vec<u8>>,
    #[serde(default, rename = "skEm", deserialize_with = "bytes_from_hex_opt")]
    sk_eph: Option<Vec<u8>>,

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
    #[serde(default, rename = "pkEm", deserialize_with = "bytes_from_hex_opt")]
    _pk_eph: Option<Vec<u8>>,

    // Key schedule inputs and computations
    #[serde(rename = "enc", deserialize_with = "bytes_from_hex")]
    encapped_key: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_hex")]
    shared_secret: Vec<u8>,
    #[serde(
        default,
        rename = "key_schedule_context",
        deserialize_with = "bytes_from_hex_opt"
    )]
    _hpke_context: Option<Vec<u8>>,
    #[serde(default, rename = "secret", deserialize_with = "bytes_from_hex_opt")]
    _key_schedule_secret: Option<Vec<u8>>,
    #[serde(rename = "key", deserialize_with = "bytes_from_hex")]
    _aead_key: Vec<u8>,
    #[serde(rename = "base_nonce", deserialize_with = "bytes_from_hex")]
    _aead_base_nonce: Vec<u8>,
    #[serde(rename = "exporter_secret", deserialize_with = "bytes_from_hex")]
    _exporter_secret: Vec<u8>,

    encryptions: Vec<EncryptionTestVector>,
    exports: Vec<ExporterTestVector>,
}

#[derive(Clone, serde::Deserialize, Debug)]
struct EncryptionTestVector {
    #[serde(rename = "pt", deserialize_with = "bytes_from_hex")]
    plaintext: Vec<u8>,
    #[serde(deserialize_with = "bytes_from_hex")]
    aad: Vec<u8>,
    #[serde(rename = "nonce", deserialize_with = "bytes_from_hex")]
    _nonce: Vec<u8>,
    #[serde(rename = "ct", deserialize_with = "bytes_from_hex")]
    ciphertext: Vec<u8>,
}

#[derive(Clone, serde::Deserialize, Debug)]
struct ExporterTestVector {
    #[serde(rename = "exporter_context", deserialize_with = "bytes_from_hex")]
    export_ctx: Vec<u8>,
    #[serde(rename = "L")]
    export_len: usize,
    #[serde(rename = "exported_value", deserialize_with = "bytes_from_hex")]
    export_val: Vec<u8>,
}

/// Returns a keypair given the secret bytes and pubkey bytes
fn deser_keypair<Kem: KemTrait>(
    sk_bytes: &[u8],
    pk_bytes: &[u8],
) -> (Kem::PrivateKey, Kem::PublicKey) {
    // Deserialize the secret key
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(sk_bytes).unwrap();
    // Deserialize the pubkey
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(pk_bytes).unwrap();

    (sk, pk)
}

/// Constructs an `OpModeR` from the given components. The variant constructed is determined solely
/// by `mode_id`. This will panic if there is insufficient data to construct the variants specified
/// by `mode_id`.
fn make_op_mode_r<'a, Kem: KemTrait>(
    mode_id: u8,
    pk: Option<Kem::PublicKey>,
    psk: Option<&'a [u8]>,
    psk_id: Option<&'a [u8]>,
) -> OpModeR<'a, Kem> {
    // Deserialize the optional bundle
    let bundle = psk.map(|bytes| PskBundle::new(bytes, psk_id.unwrap()).unwrap());

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
fn test_case<A: Aead, Kdf: KdfTrait, Kem: TestableKem>(tv: MainTestVector) {
    // First, deserialize all the relevant keys so we can reconstruct the encapped key
    let recip_keypair = deser_keypair::<Kem>(&tv.sk_recip, &tv.pk_recip);
    let sender_keypair = {
        let pk_sender = &tv.pk_sender.as_ref();
        tv.sk_sender
            .as_ref()
            .map(|sk| deser_keypair::<Kem>(sk, pk_sender.unwrap()))
    };

    // Make sure the keys match what we would've gotten had we used DeriveKeyPair
    {
        let derived_kp = Kem::derive_keypair(&tv.ikm_recip);
        assert_serializable_eq!(recip_keypair.0, derived_kp.0, "sk recip doesn't match");
        assert_serializable_eq!(recip_keypair.1, derived_kp.1, "pk recip doesn't match");
    }
    if let Some(kp) = sender_keypair.as_ref() {
        let derived_kp = Kem::derive_keypair(&tv.ikm_sender.unwrap());
        assert_serializable_eq!(kp.0, derived_kp.0, "sk sender doesn't match");
        assert_serializable_eq!(kp.1, derived_kp.1, "pk sender doesn't match");
    }

    let (sk_recip, pk_recip) = recip_keypair;

    // Now derive the encapped key with the deterministic encap function, using ikm_eph as the
    // ephemeral keying material
    let sender_keypair = sender_keypair.as_ref().map(|(sk, pk)| (sk, pk)); // &(_, _) -> (&_, &_)
    let (shared_secret, encapped_key) =
        Kem::encap_det(&pk_recip, sender_keypair, tv.ikm_eph.as_slice()).expect("encap failed");

    // Check that encap_with_eph is the same as encap_det when the ephemeral secret key (DHKEM only)
    // is given
    if let Some(sk_eph) = tv
        .sk_eph
        .map(|b| Kem::EphemeralKey::from_bytes(&b).unwrap())
    {
        let (other_shared_secret, other_encapped_key) =
            Kem::encap_with_eph(&pk_recip, sender_keypair, sk_eph).expect("encap failed");

        assert!(
            shared_secret.0 == other_shared_secret.0,
            "ikm shared secret doesn't match sk_eph shared secret"
        );
        assert_serializable_eq!(
            encapped_key,
            other_encapped_key,
            "ikm encapped key doesn't match sk_eph encapped key"
        );
    }

    // Assert that the derived shared secret key is identical to the one provided
    assert_eq!(
        shared_secret.0.as_slice(),
        tv.shared_secret.as_slice(),
        "shared_secret doesn't match"
    );

    // Assert that the derived encapped key is identical to the one provided
    {
        let provided_encapped_key =
            <Kem as KemTrait>::EncappedKey::from_bytes(&tv.encapped_key).unwrap();
        assert_serializable_eq!(
            encapped_key,
            provided_encapped_key,
            "encapped keys don't match"
        );
    }

    // We're going to test the encryption contexts. First, construct the appropriate OpMode.
    let mode = make_op_mode_r(
        tv.mode,
        sender_keypair.map(|(_, pk)| pk.clone()),
        tv.psk.as_deref(),
        tv.psk_id.as_deref(),
    );
    let mut aead_ctx = setup_receiver::<A, Kdf, Kem>(&mode, &sk_recip, &encapped_key, &tv.info)
        .expect("setup_receiver failed");

    // Go through all the plaintext-ciphertext pairs of this test vector and assert the
    // ciphertext decrypts to the corresponding plaintext
    for enc_packet in tv.encryptions {
        // Descructure the vector
        let EncryptionTestVector {
            aad,
            ciphertext,
            plaintext,
            ..
        } = enc_packet;

        // Open the ciphertext and assert that it succeeds
        let decrypted = aead_ctx.open(&ciphertext, &aad).expect("open failed");

        // Assert the decrypted payload equals the expected plaintext
        assert_eq!(decrypted, plaintext, "plaintexts don't match");
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
    let ref_tvs: Vec<MainTestVector> = {
        let file = File::open("test-vectors-5f503c5.json").unwrap();
        serde_json::from_reader(file).unwrap()
    };

    let pq_tvs: Vec<MainTestVector> = {
        let file = File::open("test-vectors-go-8aa8a04.json").unwrap();
        serde_json::from_reader(file).unwrap()
    };

    for tv in ref_tvs.into_iter().chain(pq_tvs.into_iter()) {
        // Ignore everything that doesn't use X25519, P256, P384, P521, XWing, or
        // MLKEM768-P256, since that's all we support right now
        if tv.kem_id != X25519HkdfSha256::KEM_ID
            && tv.kem_id != DhP256HkdfSha256::KEM_ID
            && tv.kem_id != DhP384HkdfSha384::KEM_ID
            && tv.kem_id != DhP521HkdfSha512::KEM_ID
            && tv.kem_id != XWing::KEM_ID
            && tv.kem_id != MlKem768P256::KEM_ID
        {
            continue;
        }

        // This unrolls into 36 `if let` statements
        dispatch_testcase!(
            tv,
            (AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead),
            (HkdfSha256, HkdfSha384, HkdfSha512, KdfShake256),
            (
                X25519HkdfSha256,
                DhP256HkdfSha256,
                DhP384HkdfSha384,
                DhP521HkdfSha512,
                XWing,
                MlKem768P256
            )
        );

        // The above macro has a `continue` in every branch. We only get to this line if it failed
        // to match every combination of the above primitives.
        panic!(
            "Unrecognized (AEAD ID, KDF ID, KEM ID) combo: ({}, {}, {})",
            tv.aead_id, tv.kdf_id, tv.kem_id
        );
    }
}
