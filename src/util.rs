use crate::{aead::Aead, kdf::Kdf as KdfTrait, kem::Kem as KemTrait, HpkeError};

use byteorder::{BigEndian, ByteOrder};

/// Represents a ciphersuite context. That's "KEMXX", where `XX` is the KEM ID
pub(crate) type KemSuiteId = [u8; 5];

/// Represents a ciphersuite context. That's "HPKEXXYYZZ", where `XX` is the KEM ID, `YY` is the
/// KDF ID, and `ZZ` is the AEAD ID
pub(crate) type FullSuiteId = [u8; 10];

// RFC 9180 §5.1
// suite_id = concat(
//   "HPKE",
//   I2OSP(kem_id, 2),
//   I2OSP(kdf_id, 2),
//   I2OSP(aead_id, 2)
// )

/// Constructs the `suite_id` used as binding context in all functions in `setup` and `aead`
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

// RFC 9180 §4.1
// suite_id = concat("KEM", I2OSP(kem_id, 2))

/// Constructs the `suite_id` used as binding context in all functions in `kem`
pub(crate) fn kem_suite_id<Kem: KemTrait>() -> KemSuiteId {
    // XX is the KEM ID
    let mut suite_id = *b"KEMXX";

    // Write the KEM ID to the buffer. Forgive the explicit indexing.
    BigEndian::write_u16(&mut suite_id[3..5], Kem::KEM_ID);

    suite_id
}

/// Returns a const expression that evaluates to the number of arguments it received
macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
}

/// Given a length L and a sequence of n bytestrings with length at most L, this does a
/// non-allocating concatentation of the bytestrings. It constructs a big buffer of n*L many bytes
/// writes everything into there, and keeps track of how many bytes it wrote. The macro returns
/// `(buf, num_bytes_written)`.
macro_rules! concat_with_known_maxlen {
    ( $maxlen:expr, $( $slice:expr ),* ) => {{
        // The length of the big buffer is the number of items we're concatting times the max
        // length of the items. count! tells us how many items we're concatting.
        const BUFLEN: usize = count!($($slice)*) * $maxlen;

        // Make the big buffer and iteratively write each slice to the remaining unused space.
        // This panics if if we ever run out of space.
        let mut buf = [0u8; BUFLEN];
        let mut unused_space = &mut buf[..];
        $(
            unused_space = crate::util::write_to_buf(unused_space, $slice);
        )*

        let num_bytes_written = BUFLEN - unused_space.len();
        (buf, num_bytes_written)
    }};
}

/// A helper function that writes to a buffer and returns a slice containing the unwritten portion.
/// If this crate were allowed to use std, we'd just use std::io::Write instead.
pub(crate) fn write_to_buf<'a>(buf: &'a mut [u8], to_write: &[u8]) -> &'a mut [u8] {
    buf[..to_write.len()].copy_from_slice(to_write);
    &mut buf[to_write.len()..]
}

/// Takes two lengths and returns an `Err(Error::IncorrectInputLength)` iff they don't match
pub(crate) fn enforce_equal_len(expected_len: usize, given_len: usize) -> Result<(), HpkeError> {
    if given_len != expected_len {
        Err(HpkeError::IncorrectInputLength(expected_len, given_len))
    } else {
        Ok(())
    }
}
