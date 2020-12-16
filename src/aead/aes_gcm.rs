use crate::aead::Aead;

/// The implementation of AES-GCM-128
pub struct AesGcm128;

impl Aead for AesGcm128 {
    type AeadImpl = aes_gcm::Aes128Gcm;

    // draft07 §7.3: AES-GCM-128
    const AEAD_ID: u16 = 0x0001;
}

/// The implementation of AES-GCM-128
pub struct AesGcm256 {}

impl Aead for AesGcm256 {
    type AeadImpl = aes_gcm::Aes256Gcm;

    // draft07 §7.3: AES-GCM-256
    const AEAD_ID: u16 = 0x0002;
}
