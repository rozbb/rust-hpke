//-------- no_std stuff --------//
#![no_std]

#[cfg(feature = "std")]
#[allow(unused_imports)]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

//-------- Testing stuff --------//

// Re-export this version of generic_array, since that's what's used everywhere in this crate
pub use digest::generic_array;

// kat_tests requries "std" and serde
#[cfg(all(test, feature = "std"))]
#[macro_use]
extern crate serde_derive;

// kat_tests requries "std" for file IO
#[cfg(all(test, feature = "std"))]
mod kat_tests;

#[cfg(test)]
mod test_util;

//-------- Modules and exports--------//

pub mod aead;
pub mod dh;
pub mod kdf;
pub mod kem;
pub mod op_mode;
mod prelude;
pub mod setup;

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

//-------- Top-level types --------//

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
