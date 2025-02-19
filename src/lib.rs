//! # hpke
//! **WARNING:** This code has not been audited. Use at your own discretion.
//!
//! This is a pure Rust implementation of the
//! [HPKE](https://datatracker.ietf.org/doc/rfc9180/) hybrid encryption scheme (RFC 9180). The
//! purpose of hybrid encryption is to use allow someone to send secure messages to an entity whose
//! public key they know. Here's an example of Alice and Bob, where Alice knows Bob's public key:
//!
//! ```
//! # #[cfg(any(feature = "alloc", feature = "std"))] {
//! # #[cfg(feature = "x25519")]
//! # {
//! # use rand::{rngs::StdRng, SeedableRng};
//! # use hpke::{
//! #     aead::ChaCha20Poly1305,
//! #     kdf::HkdfSha384,
//! #     kem::X25519HkdfSha256,
//! #     Kem as KemTrait, OpModeR, OpModeS, setup_receiver, setup_sender,
//! # };
//! // These types define the ciphersuite Alice and Bob will be using
//! type Kem = X25519HkdfSha256;
//! type Aead = ChaCha20Poly1305;
//! type Kdf = HkdfSha384;
//!
//! let mut csprng = StdRng::from_os_rng();
//! # let (bob_sk, bob_pk) = Kem::gen_keypair(&mut csprng);
//!
//! // This is a description string for the session. Both Alice and Bob need to know this value.
//! // It's not secret.
//! let info_str = b"Alice and Bob's weekly chat";
//!
//! // Alice initiates a session with Bob. OpModeS::Base means that Alice is not authenticating
//! // herself at all. If she had a public key herself, or a pre-shared secret that Bob also
//! // knew, she'd be able to authenticate herself. See the OpModeS and OpModeR types for more
//! // detail.
//! let (encapsulated_key, mut encryption_context) =
//!     hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &bob_pk, info_str, &mut csprng)
//!         .expect("invalid server pubkey!");
//!
//! // Alice encrypts a message to Bob. `aad` is authenticated associated data that is not
//! // encrypted.
//! let msg = b"fronthand or backhand?";
//! let aad = b"a gentleman's game";
//! // To seal without allocating:
//! //     let auth_tag = encryption_context.seal_in_place_detached(&mut msg, aad)?;
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
//!     hpke::setup_receiver::<Aead, Kdf, Kem>(
//!         &OpModeR::Base,
//!         &bob_sk,
//!         &encapsulated_key,
//!         info_str,
//!     ).expect("failed to set up receiver!");
//! // To open without allocating:
//! //     decryption_context.open_in_place_detached(&mut ciphertext, aad, &auth_tag)
//! // To open with allocating:
//! let plaintext = decryption_context.open(&ciphertext, aad).expect("invalid ciphertext!");
//!
//! assert_eq!(&plaintext, b"fronthand or backhand?");
//! # }
//! # }
//! ```

// The doc_cfg feature is only available in nightly. It lets us mark items in documentation as
// dependent on specific features.
#![cfg_attr(docsrs, feature(doc_cfg))]
//-------- no_std stuff --------//
#![no_std]

#[cfg(feature = "std")]
#[allow(unused_imports)]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
pub(crate) use std::vec::Vec;

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
pub(crate) use alloc::vec::Vec;

//-------- Testing stuff --------//

// kat_tests tests all the implemented ciphersuites, and thus needs all the dependencies. It also
// needs std for file IO.
#[cfg(all(
    test,
    feature = "std",
    feature = "x25519",
    feature = "p256",
    feature = "p384",
    feature = "p521"
))]
mod kat_tests;

#[cfg(test)]
mod test_util;

//-------- Modules and exports--------//

// Re-export our versions of generic_array and rand_core, since their traits and types are exposed
// in this crate
pub use generic_array;
pub use rand_core;

#[macro_use]
mod util;

pub mod aead;
mod dhkex;
pub mod kdf;
pub mod kem;
mod op_mode;
mod setup;
mod single_shot;

#[doc(inline)]
pub use kem::Kem;
#[doc(inline)]
pub use op_mode::{OpModeR, OpModeS, PskBundle};
#[doc(inline)]
pub use setup::{setup_receiver, setup_sender};
#[doc(inline)]
pub use single_shot::{single_shot_open_in_place_detached, single_shot_seal_in_place_detached};

#[doc(inline)]
#[cfg(any(feature = "alloc", feature = "std"))]
pub use single_shot::{single_shot_open, single_shot_seal};

//-------- Top-level types --------//

use generic_array::{typenum::marker_traits::Unsigned, ArrayLength, GenericArray};

/// Describes things that can go wrong in the HPKE protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpkeError {
    /// The allowed number of message encryptions has been reached
    MessageLimitReached,
    /// An error occurred while opening a ciphertext
    OpenError,
    /// An error occured while sealing a plaintext
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
    type OutputSize: ArrayLength<u8>;

    /// Serializes `self` to the given slice. `buf` MUST have length equal to `Self::size()`.
    ///
    /// Panics
    /// ======
    /// Panics if `buf.len() != Self::size()`.
    fn write_exact(&self, buf: &mut [u8]);

    /// Serializes `self` to a new array
    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Make a buffer of the correct size and write to it
        let mut buf = GenericArray::default();
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
#[cfg(feature = "std")]
impl std::error::Error for HpkeError {}
