use digest::{BlockInput, Digest, FixedOutput, Input, Reset};
use sha2::Sha256;

// Pretty much all the KDF functionality is covered by the hkdf crate

/// Represents key derivation functionality
pub trait Kdf {
    /// The underlying hash function
    type HashImpl: Digest + Input + BlockInput + FixedOutput + Reset + Default + Clone;

    /// The algorithm identifier for a KDF implementation
    const KDF_ID: u16;
}

/// The implementation of HKDF-SHA256
pub struct HkdfSha256 {}

impl Kdf for HkdfSha256 {
    type HashImpl = Sha256;

    // draft02 §8.2: HKDF-SHA256
    const KDF_ID: u16 = 0x0001;
}
