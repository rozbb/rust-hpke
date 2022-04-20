use crate::aead::Aead;

/// The implementation of AES-128-GCM
pub struct AesGcm128;

impl Aead for AesGcm128 {
    type AeadImpl = aes_gcm::Aes128Gcm;

    // RFC 9180 §7.3: AES-128-GCM
    const AEAD_ID: u16 = 0x0001;
}

/// The implementation of AES-256-GCM
pub struct AesGcm256 {}

impl Aead for AesGcm256 {
    type AeadImpl = aes_gcm::Aes256Gcm;

    // RFC 9180 §7.3: AES-256-GCM
    const AEAD_ID: u16 = 0x0002;
}
