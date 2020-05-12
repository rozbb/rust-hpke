use crate::kdf::Kdf;

use digest::{generic_array::typenum::Unsigned, Digest};

/// For use with `static_zeros`. This only needs to be as long as the longest hash function digest.
/// 128 bytes should be enough for anybody.
const ZEROS: &[u8] = &[0u8; 128];

/// Returns an immutable slice into a static array of zeros. The slice length is the digest length
/// of the underlying hash function. This function is defined so we don't have to keep allocating
/// the default value of a `Psk`, which is `[0u8; HashImpl::OutputSize]`.
pub(crate) fn static_zeros<K: Kdf>() -> &'static [u8] {
    &ZEROS[..<<K as Kdf>::HashImpl as Digest>::OutputSize::to_usize()]
}
