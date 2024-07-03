use crate::{aead::Aead, kdf::Kdf as KdfTrait, kem::Kem as KemTrait, HpkeError, Serializable};

/// Represents a ciphersuite context. That's "KEMXX", where `XX` is the KEM ID
pub(crate) type KemSuiteId = [u8; 5];

/// Represents a ciphersuite context. That's "HPKEXXYYZZ", where `XX` is the KEM ID, `YY` is the
/// KDF ID, and `ZZ` is the AEAD ID
pub(crate) type FullSuiteId = [u8; 10];

/// Writes a u16 to a bytestring in big-endian order. `buf.len()` MUST be 2
#[rustfmt::skip]
pub(crate) fn write_u16_be(buf: &mut [u8], n: u16) {
    assert_eq!(buf.len(), 2);
    buf[0] = ((n & 0xff00) >> 8) as u8;
    buf[1] =  (n & 0x00ff)       as u8;
}

/// Writes a u64 to a bytestring in big-endian order. `buf.len()` MUST be 8
#[rustfmt::skip]
pub(crate) fn write_u64_be(buf: &mut [u8], n: u64) {
    assert_eq!(buf.len(), 8);
    buf[0] = ((n & 0xff00000000000000) >> 56) as u8;
    buf[1] = ((n & 0x00ff000000000000) >> 48) as u8;
    buf[2] = ((n & 0x0000ff0000000000) >> 40) as u8;
    buf[3] = ((n & 0x000000ff00000000) >> 32) as u8;
    buf[4] = ((n & 0x00000000ff000000) >> 24) as u8;
    buf[5] = ((n & 0x0000000000ff0000) >> 16) as u8;
    buf[6] = ((n & 0x000000000000ff00) >>  8) as u8;
    buf[7] =  (n & 0x00000000000000ff)        as u8;
}

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
    write_u16_be(&mut suite_id[4..6], Kem::KEM_ID);
    write_u16_be(&mut suite_id[6..8], Kdf::KDF_ID);
    write_u16_be(&mut suite_id[8..10], A::AEAD_ID);

    suite_id
}

// RFC 9180 §4.1
// suite_id = concat("KEM", I2OSP(kem_id, 2))

/// Constructs the `suite_id` used as binding context in all functions in `kem`
pub(crate) fn kem_suite_id<Kem: KemTrait>() -> KemSuiteId {
    // XX is the KEM ID
    let mut suite_id = *b"KEMXX";

    // Write the KEM ID to the buffer. Forgive the explicit indexing.
    write_u16_be(&mut suite_id[3..5], Kem::KEM_ID);

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

/// Helper function for `Serializable::write_exact`. Takes a buffer and a serializable type `T` and
/// panics iff `buf.len() != T::size()`.
pub(crate) fn enforce_outbuf_len<T: Serializable>(buf: &[u8]) {
    let size = T::size();
    let buf_len = buf.len();
    assert!(
        size == buf_len,
        "write_exact(): serialized size ({}) does not equal buffer length ({})",
        size,
        buf_len,
    );
}
