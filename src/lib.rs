/// Describes things that can go wrong when trying to seal or open a ciphertext
#[derive(Clone, Copy, Debug)]
pub enum HpkeError {
    /// The nonce sequence counter has already overflowed
    SeqOverflow,
    /// The authentication tag was invalid when opening
    InvalidTag,
    /// An error occured during encryption
    Encryption,
}

pub mod aead;
pub mod dh;
pub mod kdf;
pub mod kem;
pub mod op_mode;
pub mod setup;

#[cfg(test)]
mod test_util;

#[doc(inline)]
pub use crate::aead::AeadCtx;
#[doc(inline)]
pub use dh::{DiffieHellman, Marshallable};
#[doc(inline)]
pub use kdf::Kdf;
#[doc(inline)]
pub use kem::EncappedKey;
#[doc(inline)]
pub use op_mode::{OpModeR, OpModeS, Psk, PskBundle};
#[doc(inline)]
pub use setup::{setup_receiver, setup_sender};
