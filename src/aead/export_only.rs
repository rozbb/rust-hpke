use crate::aead::Aead;

use aead::{
    AeadCore as BaseAeadCore, AeadInPlace as BaseAeadInPlace, KeyInit as BaseKeyInit,
    KeySizeUser as BaseKeySizeUser,
};
use generic_array::typenum;

/// An inert underlying Aead implementation. The open/seal routines panic. The `new()` function
/// returns an `EmptyAeadImpl`, and that is all of the functionality this struct has.
#[doc(hidden)]
#[derive(Clone)]
pub struct EmptyAeadImpl;

impl BaseAeadCore for EmptyAeadImpl {
    // The nonce size has to be bigger than the sequence size (currently u64), otherwise we get an
    // underflow error on seal()/open() before we can even panic
    type NonceSize = typenum::U128;
    type TagSize = typenum::U0;
    type CiphertextOverhead = typenum::U0;
}

impl BaseAeadInPlace for EmptyAeadImpl {
    fn encrypt_in_place_detached(
        &self,
        _: &aead::Nonce<Self>,
        _: &[u8],
        _: &mut [u8],
    ) -> Result<aead::Tag<Self>, aead::Error> {
        panic!("Cannot encrypt with an export-only encryption context!");
    }

    fn decrypt_in_place_detached(
        &self,
        _: &aead::Nonce<Self>,
        _: &[u8],
        _: &mut [u8],
        _: &aead::Tag<Self>,
    ) -> Result<(), aead::Error> {
        panic!("Cannot decrypt with an export-only encryption context!");
    }
}

impl BaseKeySizeUser for EmptyAeadImpl {
    type KeySize = typenum::U0;
}

impl BaseKeyInit for EmptyAeadImpl {
    // Ignore the key, since we can't encrypt or decrypt anything anyway. Just return the object
    fn new(_: &aead::Key<Self>) -> Self {
        EmptyAeadImpl
    }
}

/// An AEAD which can **only** be used for its `export()` function. The `open()` and `seal()`
/// methods on an `AeadCtxR` or `AeadCtxS` which uses this AEAD underlyingly **will panic** if you
/// call them
pub struct ExportOnlyAead;

impl Aead for ExportOnlyAead {
    type AeadImpl = EmptyAeadImpl;

    // RFC 9180 §7.3: Export-only
    const AEAD_ID: u16 = 0xFFFF;
}
