use hpke::{
    aead::{Aead as AeadTrait, AeadCtxR, AeadTag},
    kdf::Kdf as KdfTrait,
    kem::Kem as KemTrait,
    setup_receiver, setup_sender, OpModeR, OpModeS, PskBundle,
};

use criterion::{black_box, criterion_main, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::Instant;

// Length of AAD for all seal/open benchmarks
const AAD_LEN: usize = 64;
// Length of plaintext and ciphertext for all seal/open benchmarks
const MSG_LEN: usize = 64;
// Length of PSK. Since we're only testing the 128-bit security level, make it 128 bits
const PSK_LEN: usize = 16;

// Generic function to bench the specified ciphersuite
fn bench_ciphersuite<Aead, Kdf, Kem>(group_name: &str, c: &mut Criterion)
where
    Aead: AeadTrait,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    let mut csprng = StdRng::from_entropy();

    let mut group = c.benchmark_group(group_name);

    // Bench keypair generation
    group.bench_function("gen_keypair", |b| b.iter(|| Kem::gen_keypair(&mut csprng)));

    // Make a recipient keypair to encrypt to
    let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);

    // Make a PSK bundle for OpModePsk and OpModeAuthPsk
    let mut psk = [0u8; PSK_LEN];
    let mut psk_id = [0u8; 8];
    csprng.fill_bytes(&mut psk);
    csprng.fill_bytes(&mut psk_id);
    let psk_bundle = PskBundle {
        psk: &psk,
        psk_id: &psk_id,
    };

    // Make a sender keypair for OpModeAuth and OpModeAuthPsk
    let (sk_sender, pk_sender) = Kem::gen_keypair(&mut csprng);

    // Construct all the opmodes we'll use in setup_sender and setup_receiver
    let opmodes = ["base", "auth", "psk", "authpsk"];
    let opmodes_s = vec![
        OpModeS::Base,
        OpModeS::Auth((sk_sender.clone(), pk_sender.clone())),
        OpModeS::Psk(psk_bundle),
        OpModeS::AuthPsk((sk_sender, pk_sender.clone()), psk_bundle),
    ];
    let opmodes_r = vec![
        OpModeR::Base,
        OpModeR::Psk(psk_bundle),
        OpModeR::Auth(pk_recip.clone()),
        OpModeR::AuthPsk(pk_recip.clone(), psk_bundle),
    ];

    // Bench setup_sender() for each opmode
    for (mode, opmode_s) in opmodes.iter().zip(opmodes_s.iter()) {
        let bench_name = format!("setup_sender[mode={}]", mode);
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                setup_sender::<Aead, Kdf, Kem, _>(
                    opmode_s,
                    &pk_recip,
                    b"bench setup sender",
                    &mut csprng,
                )
            })
        });
    }

    // Collect the encapsulated keys from each setup_sender under each opmode. We will pass these
    // to setup_receiver in a moment
    let encapped_keys = opmodes_s.iter().map(|opmode_s| {
        setup_sender::<Aead, Kdf, Kem, _>(
            &opmode_s,
            &pk_recip,
            b"bench setup receiver",
            &mut csprng,
        )
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
        setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk_recip, b"bench seal", &mut csprng)
            .unwrap();

    // Bench seal() on a MSG_LEN-byte plaintext and AAD_LEN-byte AAD
    let bench_name = format!("seal[msglen={},aadlen={}]", MSG_LEN, AAD_LEN);
    group.bench_function(bench_name, |b| {
        // Pick random inputs
        let mut plaintext = [0u8; MSG_LEN];
        let mut aad = [0u8; AAD_LEN];
        csprng.fill_bytes(&mut plaintext);
        csprng.fill_bytes(&mut aad);

        b.iter(|| encryption_ctx.seal(&mut plaintext, &aad).unwrap())
    });

    // Bench open() on MSG_LEN-bytes ciphertexts with AAD_LEN-byte AADs. This is more complicated
    // than the other benchmarks because we need to first construct and store a ton of ciphertexts
    // that we can open() in sequence.
    let bench_name = format!("open[msglen={},aadlen={}]", MSG_LEN, AAD_LEN);
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
                black_box(decryption_ctx.open(&mut ciphertext, &aad, &tag).unwrap());
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
    let mut csprng = StdRng::from_entropy();

    // Make up the recipient's keypair and setup an encryption context
    let (sk_recip, pk_recip) = Kem::gen_keypair(&mut csprng);
    let (encapped_key, mut encryption_ctx) =
        setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk_recip, b"bench seal", &mut csprng)
            .unwrap();

    // Construct num_ciphertext many (plaintext, aad) pairs and pass them through seal()
    let mut ciphertext_aad_tags = Vec::with_capacity(num_ciphertexts);
    for _ in 0..num_ciphertexts {
        // Make the plaintext and AAD random
        let mut plaintext = [0u8; MSG_LEN];
        let mut aad = [0u8; AAD_LEN];
        csprng.fill_bytes(&mut plaintext);
        csprng.fill_bytes(&mut aad);

        // Seal the random plaintext and AAD
        let tag = encryption_ctx.seal(&mut plaintext, &aad).unwrap();
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
    #[cfg(feature = "p256")]
    bench_ciphersuite::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>(
        "NIST[seclevel=128]",
        &mut c,
    );

    // Non-NIST ciphersuite at the 128-bit security level is ChaCha20Poly1305, HKDF-SHA256, and X25519
    #[cfg(feature = "x25519")]
    bench_ciphersuite::<
        hpke::aead::ChaCha20Poly1305,
        hpke::kdf::HkdfSha256,
        hpke::kem::X25519HkdfSha256,
    >("Non-NIST[seclevel=128]", &mut c);
}

criterion_main!(benches);
