use crate::aead::Aead;

/// The implementation of ChaCha20-Poly1305
pub struct ChaCha20Poly1305;

impl Aead for ChaCha20Poly1305 {
    type AeadImpl = chacha20poly1305::ChaCha20Poly1305;

    // RFC 9180 §7.3: ChaCha20Poly1305
    const AEAD_ID: u16 = 0x0003;
}
