use hpke::{
    aead::{Aead as AeadTrait, AeadCtxR, AeadTag},
    inout::InOutBuf,
    kdf::Kdf as KdfTrait,
    kem::Kem as KemTrait,
    setup_receiver, setup_sender, OpModeR, OpModeS, PskBundle,
};

use criterion::{criterion_main, Criterion};
use rand::random;
use rand_core::Rng;
use std::time::Instant;

// Length of AAD for all seal/open benchmarks
const AAD_LEN: usize = 64;
// Length of plaintext and ciphertext for all seal/open benchmarks
const MSG_LEN: usize = 64;
// Length of PSK. Since we're only testing the 128-bit security level, make it 128 bits
const PSK_LEN: usize = 16;

// Generic function to bench the specified ciphersuite. If `supports_auth` is false, only Base and
// Psk operation modes are benchmarked (PQ KEMs don't support Auth/AuthPsk).
fn bench_ciphersuite<Aead, Kdf, Kem>(group_name: &str, c: &mut Criterion, supports_auth: bool)
where
    Aead: AeadTrait,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    let mut group = c.benchmark_group(group_name);

    // Bench keypair generation
    group.bench_function("gen_keypair", |b| b.iter(Kem::gen_keypair));

    // Make a recipient keypair to encrypt to
    let (sk_recip, pk_recip) = Kem::gen_keypair();

    // Make a PSK bundle for OpModePsk and OpModeAuthPsk
    let psk = random::<[u8; PSK_LEN]>();
    let psk_id = random::<[u8; 8]>();
    let psk_bundle = PskBundle::new(&psk, &psk_id).unwrap();

    // Make a sender keypair for OpModeAuth and OpModeAuthPsk
    let (sk_sender, pk_sender) = Kem::gen_keypair();

    // Construct the opmodes we'll use in setup_sender and setup_receiver.
    // PQ KEMs only support Base and Psk.
    let mut opmodes: Vec<&str> = vec!["base", "psk"];
    let mut opmodes_s: Vec<OpModeS<Kem>> = vec![OpModeS::Base, OpModeS::Psk(psk_bundle)];
    let mut opmodes_r: Vec<OpModeR<Kem>> = vec![OpModeR::Base, OpModeR::Psk(psk_bundle)];
    if supports_auth {
        opmodes.extend_from_slice(&["auth", "authpsk"]);
        opmodes_s.push(OpModeS::Auth((sk_sender.clone(), pk_sender.clone())));
        opmodes_s.push(OpModeS::AuthPsk((sk_sender, pk_sender.clone()), psk_bundle));
        opmodes_r.push(OpModeR::Auth(pk_recip.clone()));
        opmodes_r.push(OpModeR::AuthPsk(pk_recip.clone(), psk_bundle));
    }

    // Bench setup_sender() for each opmode
    for (mode, opmode_s) in opmodes.iter().zip(opmodes_s.iter()) {
        let bench_name = format!("setup_sender[mode={}]", mode);
        group.bench_function(bench_name, |b| {
            b.iter(|| setup_sender::<Aead, Kdf, Kem>(opmode_s, &pk_recip, b"bench setup sender"))
        });
    }

    // Collect the encapsulated keys from each setup_sender under each opmode. We will pass these
    // to setup_receiver in a moment
    let encapped_keys = opmodes_s.iter().map(|opmode_s| {
        setup_sender::<Aead, Kdf, Kem>(opmode_s, &pk_recip, b"bench setup receiver")
            .unwrap()
            .0
    });

    // Bench setup_receiver for each opmode
    for ((mode, opmode_r), encapped_key) in opmodes.iter().zip(opmodes_r).zip(encapped_keys) {
        let bench_name = format!("setup_receiver[mode={}]", mode);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                setup_receiver::<Aead, Kdf, Kem>(
                    &opmode_r,
                    &sk_recip,
                    &encapped_key,
                    b"bench setup sender",
                )
                .unwrap()
            })
        });
    }

    // Make the encryption context so we can benchmark seal()
    let (_, mut encryption_ctx) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &pk_recip, b"bench seal").unwrap();

    // Bench seal_inout_detached() on a MSG_LEN-byte plaintext and AAD_LEN-byte AAD
    let bench_name = format!("seal_inout_detached[msglen={},aadlen={}]", MSG_LEN, AAD_LEN);
    group.bench_function(bench_name, |b| {
        // Pick random inputs
        let mut plaintext = random::<[u8; MSG_LEN]>();
        let aad = random::<[u8; AAD_LEN]>();

        b.iter(|| {
            encryption_ctx
                .seal_inout_detached(InOutBuf::from(&mut plaintext[..]), &aad)
                .unwrap()
        })
    });

    // Bench open_inout_detached() on MSG_LEN-bytes ciphertexts with AAD_LEN-byte AADs. This is
    // more complicated than the other benchmarks because we need to first construct and store a
    // ton of ciphertexts that we can open in sequence.
    let bench_name = format!("open_inout_detached[msglen={},aadlen={}]", MSG_LEN, AAD_LEN);
    group.bench_function(bench_name, |b| {
        b.iter_custom(|iters| {
            // Make a decryption context and however many (ciphertexts, aad, tag) tuples the
            // bencher tells us we need
            let (mut decryption_ctx, ciphertext_aad_tags) =
                make_decryption_ctx_with_ciphertexts::<Aead, Kdf, Kem>(iters as usize);

            // Start the timer, open every ciphertext in quick succession, then stop the timer
            let start = Instant::now();
            for (mut ciphertext, aad, tag) in ciphertext_aad_tags.into_iter() {
                // black_box makes sure the compiler doesn't optimize away this computation
                std::hint::black_box(
                    decryption_ctx
                        .open_inout_detached(InOutBuf::from(&mut ciphertext[..]), &aad, &tag)
                        .unwrap(),
                );
            }
            start.elapsed()
        });
    });
}

// A tuple of (ciphertext, aad, auth_tag) resulting from a call to seal()
type CiphertextAadTag<A> = ([u8; MSG_LEN], [u8; AAD_LEN], AeadTag<A>);

// Constructs a decryption context with num_ciphertexts many CiphertextAadTag tuples that are
// decryptable in sequence
fn make_decryption_ctx_with_ciphertexts<Aead, Kdf, Kem>(
    num_ciphertexts: usize,
) -> (AeadCtxR<Aead, Kdf, Kem>, Vec<CiphertextAadTag<Aead>>)
where
    Aead: AeadTrait,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    let mut csprng = rand::rng();

    // Make up the recipient's keypair and setup an encryption context
    let (sk_recip, pk_recip) = Kem::gen_keypair();
    let (encapped_key, mut encryption_ctx) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &pk_recip, b"bench seal").unwrap();

    // Construct num_ciphertext many (plaintext, aad) pairs and pass them through seal()
    let mut ciphertext_aad_tags = Vec::with_capacity(num_ciphertexts);
    for _ in 0..num_ciphertexts {
        // Make the plaintext and AAD random
        let mut plaintext = [0u8; MSG_LEN];
        let mut aad = [0u8; AAD_LEN];
        csprng.fill_bytes(&mut plaintext);
        csprng.fill_bytes(&mut aad);

        // Seal the random plaintext and AAD
        let tag = encryption_ctx
            .seal_inout_detached(InOutBuf::from(&mut plaintext[..]), &aad)
            .unwrap();
        // Rename for clarity. Encryption happened in-place
        let ciphertext = plaintext;

        // Collect the ciphertext, AAD, and authentication tag
        ciphertext_aad_tags.push((ciphertext, aad, tag));
    }

    // Build the recipient's decryption context from the sender's encapsulated key
    let decryption_ctx =
        setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk_recip, &encapped_key, b"bench seal")
            .unwrap();

    (decryption_ctx, ciphertext_aad_tags)
}

pub fn benches() {
    let mut c = Criterion::default().configure_from_args();

    // NIST ciphersuite at the 128-bit security level is AES-GCM-128, HKDF-SHA256, and ECDH-P256
    #[cfg(all(feature = "nistp", feature = "aes"))]
    bench_ciphersuite::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>(
        "Classical-NIST[seclevel=128]",
        &mut c,
        true,
    );

    // Non-NIST ciphersuite at the 128-bit security level is ChaCha20Poly1305, HKDF-SHA256, and X25519
    #[cfg(all(feature = "x25519", feature = "chacha"))]
    bench_ciphersuite::<
        hpke::aead::ChaCha20Poly1305,
        hpke::kdf::HkdfSha256,
        hpke::kem::X25519HkdfSha256,
    >("Classical-NonNIST[seclevel=128]", &mut c, true);

    // Pure ML-KEM-768 at the 128-bit security level
    #[cfg(all(feature = "mlkem", feature = "aes"))]
    bench_ciphersuite::<hpke::aead::AesGcm128, hpke::kdf::KdfShake128, hpke::kem::MlKem768>(
        "MLKEM768-NIST[seclevel=128]",
        &mut c,
        false,
    );

    // Pure ML-KEM-1024 at the 256-bit security level
    #[cfg(all(feature = "mlkem", feature = "aes"))]
    bench_ciphersuite::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024>(
        "MLKEM1024-NIST[seclevel=256]",
        &mut c,
        false,
    );

    // Hybrid ML-KEM-768 + NIST-P256 at the 128-bit security level
    #[cfg(all(feature = "mlkem", feature = "nistp", feature = "aes"))]
    bench_ciphersuite::<hpke::aead::AesGcm128, hpke::kdf::KdfShake128, hpke::kem::MlKem768P256>(
        "MLKEM768P256-NIST[seclevel=128]",
        &mut c,
        false,
    );

    // Hybrid ML-KEM-1024 + NIST-P384 at the 256-bit security level
    #[cfg(all(feature = "mlkem", feature = "nistp", feature = "aes"))]
    bench_ciphersuite::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024P384>(
        "MLKEM1024P384-NIST[seclevel=256]",
        &mut c,
        false,
    );

    // X-Wing hybrid PQ KEM with ChaCha20Poly1305 and SHAKE256
    #[cfg(all(feature = "mlkem", feature = "chacha"))]
    bench_ciphersuite::<hpke::aead::ChaCha20Poly1305, hpke::kdf::KdfTurboShake128, hpke::kem::XWing>(
        "XWing-NonNIST[seclevel=128]",
        &mut c,
        false,
    );
}

criterion_main!(benches);
