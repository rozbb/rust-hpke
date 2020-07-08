use crate::{aead::Aead, kdf::Kdf as KdfTrait, kem::Kem as KemTrait};

use byteorder::{BigEndian, ByteOrder};

/// Represents a ciphersuite context. That's "KEMXX", where `XX` is the KEM ID
pub(crate) type KemSuiteId = [u8; 5];

/// Represents a ciphersuite context. That's "HPKEXXYYZZ", where `XX` is the KEM ID, `YY` is the
/// KDF ID, and `ZZ` is the AEAD ID
pub(crate) type FullSuiteId = [u8; 10];

/// Constructs the `suite_id` used as binding context in all KDF functions in this file. Concretely,
/// `suite_id = concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))`
pub(crate) fn full_suite_id<A, Kdf, Kem>() -> FullSuiteId
where
    A: Aead,
    Kdf: KdfTrait,
    Kem: KemTrait,
{
    // XX is the KEM ID, YY is the KDF ID, ZZ is the AEAD ID
    let mut suite_id = *b"HPKEXXYYZZ";

    // Write the ciphersuite identifiers to the buffer. Forgive the explicit indexing.
    BigEndian::write_u16(&mut suite_id[4..6], Kem::KEM_ID);
    BigEndian::write_u16(&mut suite_id[6..8], Kdf::KDF_ID);
    BigEndian::write_u16(&mut suite_id[8..10], A::AEAD_ID);

    suite_id
}

/// Constructs the `suite_id` used as binding context in all KDF functions in this file.
/// Concretely, `suite_id = concat("KEM", I2OSP(kem_id, 2))`
pub(crate) fn kem_suite_id<Kem: KemTrait>() -> KemSuiteId {
    // XX is the KEM ID
    let mut suite_id = *b"KEMXX";

    // Write the KEM ID to the buffer. Forgive the explicit indexing.
    BigEndian::write_u16(&mut suite_id[3..5], Kem::KEM_ID);

    suite_id
}
