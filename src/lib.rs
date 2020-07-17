//-------- no_std stuff --------//
#![no_std]

#[cfg(feature = "std")]
#[allow(unused_imports)]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

//-------- Testing stuff --------//

// Re-export this version of generic_array, since that's what's used everywhere in this crate
pub use digest::generic_array;

// kat_tests tests all the implemented ciphersuites, and thus needs all the dependencies. It also
// needs std for file IO.
#[cfg(all(test, feature = "std", feature = "x25519-dalek", feature = "p256"))]
mod kat_tests;

// kat_tests requires serde
#[cfg(all(test, feature = "std", feature = "x25519-dalek", feature = "p256"))]
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
mod test_util;

//-------- Modules and exports--------//

#[macro_use]
mod util;

pub mod aead;
pub mod kdf;
pub mod kem;
pub mod kex;
pub mod op_mode;
pub mod setup;
pub mod single_shot;

#[doc(inline)]
pub use crate::aead::{AeadCtxR, AeadCtxS};
#[doc(inline)]
pub use kem::{EncappedKey, Kem};
#[doc(inline)]
pub use kex::{KeyExchange, Marshallable, Unmarshallable};
#[doc(inline)]
pub use op_mode::{OpModeR, OpModeS, PskBundle};
#[doc(inline)]
pub use setup::{setup_receiver, setup_sender};
#[doc(inline)]
pub use single_shot::{single_shot_open, single_shot_seal};

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
    /// A key exchange input or output was invalid
    InvalidKeyExchange,
    /// The KDF was asked to output too many bytes
    InvalidKdfLength,
    /// The unmarshaller was given a bad encoding
    InvalidEncoding,
}

impl core::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self {
            HpkeError::SeqOverflow => "Sequence overflow",
            HpkeError::InvalidTag => "Invalid tag",
            HpkeError::Encryption => "Encryption error",
            HpkeError::InvalidKeyExchange => "Key exchange validation error",
            HpkeError::InvalidKdfLength => "Too many bytes requested from KDF",
            HpkeError::InvalidEncoding => "Cannot marshal byte sequence: invalid encoding",
        };
        f.write_str(kind)
    }
}

// An Error type is just something that's Debug and Display
#[cfg(feature = "std")]
impl std::error::Error for HpkeError {}
