//! This is a pure Rust implementation of the
//! [HPKE](https://datatracker.ietf.org/doc/rfc9180/) hybrid encryption scheme (RFC 9180). The
//! purpose of hybrid encryption is to use allow someone to send secure messages to an entity whose
//! public key they know.
//!
//! # Example
//!
//! Here's an example of Alice sending an encrypted message to Bob. The example uses the
//! [`easy`] module, which removes a lot of the code noise. To do things the harder way, see
//! [`examples/client_server.rs`](https://github.com/rozbb/rust-hpke/blob/main/examples/client_server.rs).
//!
//! ```
//! # #[cfg(all(feature = "alloc", feature = "x25519", feature = "chacha", feature = "getrandom"))]
//! # {
//! // We will be using the "easy" interface for the ciphersuite
//! // (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305)
//! use hpke::{
//!     easy::x25519_chacha::{
//!         gen_keypair, setup_receiver, setup_sender, AeadTag, EncappedKey, PrivateKey, PublicKey,
//!     },
//!     Deserializable, Serializable,
//! };
//! // Alternatively, you can just `use hpke::easy::x25519_chacha::*;`
//!
//! // Bob generates his keypair
//! let (bob_sk, bob_pk) = gen_keypair();
//!
//! // This is a description string for the session. Both Alice and Bob need to know this value.
//! // It's not secret.
//! let info_str = b"Alice and Bob's weekly chat";
//!
//! // Alice creates an encryption context that only Bob can derive a copy of
//! let (encapsulated_key, mut encryption_context) =
//!     setup_sender(&bob_pk, info_str).expect("invalid server pubkey!");
//!
//! // Alice encrypts a message to Bob. `aad` is authenticated associated data that is not
//! // encrypted.
//! let msg = b"fronthand or backhand?";
//! let aad = b"a gentleman's game";
//! // To seal without allocating:
//! //   use hpke::inout::InOutBuf;
//! //   let auth_tag = encryption_context.seal_inout_detached(InOutBuf::from(&mut msg), aad)?;
//! // To seal with allocating:
//! let ciphertext = encryption_context.seal(msg, aad).expect("encryption failed!");
//!
//! // ~~~
//! // Alice sends the encapsulated key, message ciphertext, AAD, and auth tag to Bob over the
//! // internet. Alice doesn't care if it's an insecure connection, because only Bob can read
//! // her ciphertext.
//! // ~~~
//!
//! // Somewhere far away, Bob receives the data and makes a decryption session
//! let mut decryption_context =
//!     setup_receiver(&bob_sk, &encapsulated_key, info_str).expect("failed to set up receiver!");
//! // To open without allocating:
//! //   use hpke::inout::InOutBuf;
//! //   decryption_context.open_inout_detached(InOutBuf::from(&mut ciphertext), aad, &auth_tag)
//! // To open with allocating:
//! let plaintext = decryption_context.open(&ciphertext, aad).expect("invalid ciphertext!");
//!
//! assert_eq!(&plaintext, b"fronthand or backhand?");
//! # }
//! ```

// Show necessary feature flag next to feature-gated items
#![cfg_attr(docsrs, feature(doc_cfg))]
//-------- no_std stuff --------//
#![no_std]

// Known-answer tests need std for file IO
#[cfg(feature = "kat")]
#[macro_use]
extern crate std;

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "alloc")]
pub(crate) use alloc::vec::Vec;

//-------- Testing stuff --------//

#[cfg(all(test, feature = "kat"))]
mod kat_tests;

#[cfg(test)]
mod test_util;

//-------- Modules and exports--------//

// Re-export our versions of hybrid_array, rand_core, and inout, since their traits and types are
// exposed in this crate
pub use ::aead::inout;
pub use hybrid_array;
pub use rand_core;

#[macro_use]
mod util;

pub mod aead;
mod dhkex;
#[cfg(all(feature = "getrandom", feature = "alloc"))]
pub mod easy;
pub mod kdf;
pub mod kem;
mod op_mode;
mod setup;
mod single_shot;
#[cfg(feature = "hazmat-streaming-enc")]
pub mod streaming_enc;

#[doc(inline)]
pub use kem::Kem;
#[doc(inline)]
pub use op_mode::{OpModeR, OpModeS, PskBundle};
#[cfg(feature = "getrandom")]
#[doc(inline)]
pub use setup::setup_sender;
#[doc(inline)]
pub use setup::{setup_receiver, setup_sender_with_rng};
#[cfg(feature = "getrandom")]
#[doc(inline)]
pub use single_shot::single_shot_seal_inout_detached;
#[doc(inline)]
pub use single_shot::{single_shot_open_inout_detached, single_shot_seal_inout_detached_with_rng};

#[cfg(all(feature = "alloc", feature = "getrandom"))]
#[doc(inline)]
pub use single_shot::single_shot_seal;
#[doc(inline)]
#[cfg(feature = "alloc")]
pub use single_shot::{single_shot_open, single_shot_seal_with_rng};

//-------- Top-level types --------//

use hybrid_array::{typenum::marker_traits::Unsigned, Array, ArraySize};

/// Describes things that can go wrong in the HPKE protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpkeError {
    /// The allowed number of message encryptions has been reached
    MessageLimitReached,
    /// An error occurred while opening a ciphertext
    OpenError,
    /// An error occurred while sealing a plaintext
    SealError,
    /// The KDF was asked to output too many bytes
    KdfOutputTooLong,
    /// An invalid input value was encountered
    ValidationError,
    /// Encapsulation failed
    EncapError,
    /// Decapsulation failed
    DecapError,
    /// An input isn't the right length. First value is the expected length, second is the given
    /// length.
    IncorrectInputLength(usize, usize),
    /// A preshared key bundle was constructed incorrectly
    InvalidPskBundle,
}

impl core::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HpkeError::MessageLimitReached => write!(f, "Message limit reached"),
            HpkeError::OpenError => write!(f, "Failed to open ciphertext"),
            HpkeError::SealError => write!(f, "Failed to seal plaintext"),
            HpkeError::KdfOutputTooLong => write!(f, "Too many bytes requested from KDF"),
            HpkeError::ValidationError => write!(f, "Input value is invalid"),
            HpkeError::EncapError => write!(f, "Encapsulation failed"),
            HpkeError::DecapError => write!(f, "Decapsulation failed"),
            HpkeError::IncorrectInputLength(expected, given) => write!(
                f,
                "Incorrect input length. Expected {} bytes. Got {}.",
                expected, given
            ),
            HpkeError::InvalidPskBundle => {
                write!(f, "Preshared key bundle is missing a key or key ID")
            }
        }
    }
}

/// Implemented by types that have a fixed-length byte representation
pub trait Serializable {
    /// Serialized size in bytes
    type OutputSize: ArraySize;

    /// Serializes `self` to the given slice. `buf` MUST have length equal to `Self::size()`.
    ///
    /// Panics
    /// ======
    /// Panics if `buf.len() != Self::size()`.
    fn write_exact(&self, buf: &mut [u8]);

    /// Serializes `self` to a new array
    fn to_bytes(&self) -> Array<u8, Self::OutputSize> {
        // Make a buffer of the correct size and write to it
        let mut buf = Array::default();
        self.write_exact(&mut buf);
        // Return the buffer
        buf
    }

    /// Returns the size (in bytes) of this type when serialized
    fn size() -> usize {
        Self::OutputSize::to_usize()
    }
}

/// Implemented by types that can be deserialized from byte representation
pub trait Deserializable: Serializable + Sized {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError>;
}

// An Error type is just something that's Debug and Display
impl core::error::Error for HpkeError {}
