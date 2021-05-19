//! # hpke
//! **WARNING:** This code has not been audited. Use at your own discretion.
//!
//! This is a pure Rust implementation of the
//! [HPKE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke/) hybrid encryption scheme. The
//! purpose of hybrid encryption is to use allow someone to send secure messages to an entity whose
//! public key they know. Here's an example of Alice and Bob, where Alice knows Bob's public key:
//!
//! ```
//! # #[cfg(feature = "x25519")]
//! # {
//! # use hpke::{
//! #     aead::ChaCha20Poly1305,
//! #     kdf::HkdfSha384,
//! #     kem::X25519HkdfSha256,
//! #     EncappedKey, Kem as KemTrait, OpModeR, OpModeS, setup_receiver, setup_sender,
//! # };
//! // These types define the ciphersuite Alice and Bob will be using
//! type Kem = X25519HkdfSha256;
//! type Aead = ChaCha20Poly1305;
//! type Kdf = HkdfSha384;
//!
//! # let (bob_sk, bob_pk) = Kem::gen_keypair();
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
//!     hpke::setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &bob_pk, info_str)
//!         .expect("invalid server pubkey!");
//!
//! // Alice encrypts a message to Bob. msg gets encrypted in place, and aad is authenticated
//! // associated data that is not encrypted.
//! let mut msg = *b"fronthand or backhand?";
//! let aad = b"a gentleman's game";
//! let auth_tag = encryption_context
//!     .seal(&mut msg, aad)
//!     .expect("encryption failed!");
//! // The msg was encrypted in-place. So rename it for clarity
//! let ciphertext = msg;
//! # let mut ciphertext = ciphertext; // Make it mutable so Bob can decrypt in place
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
//! decryption_context.open(&mut ciphertext, aad, &auth_tag).expect("invalid ciphertext!");
//! // The ciphertext was decrypted in-place. So rename it for clarity
//! let plaintext = ciphertext;
//!
//! assert_eq!(&plaintext, b"fronthand or backhand?");
//! # }
//! ```

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

// kat_tests tests all the implemented ciphersuites, and thus needs all the dependencies. It also
// needs std for file IO.
#[cfg(all(test, feature = "std", feature = "x25519", feature = "p256"))]
mod kat_tests;

// kat_tests requires serde
#[cfg(all(test, feature = "std", feature = "x25519", feature = "p256"))]
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
mod test_util;

//-------- Modules and exports--------//

// Re-export this version of generic_array, since that's what's used everywhere in this crate
pub use generic_array;

#[macro_use]
mod util;

pub mod aead;
pub mod kdf;
pub mod kem;
pub mod kex;
pub mod op_mode;
pub mod setup;
pub mod single_shot;

#[cfg(feature = "serde_impls")]
mod serde_impls;

#[doc(inline)]
pub use crate::aead::{AeadCtxR, AeadCtxS};
#[doc(inline)]
pub use kem::{EncappedKey, Kem};
#[doc(inline)]
pub use kex::{Deserializable, Serializable};
#[doc(inline)]
pub use op_mode::{OpModeR, OpModeS, PskBundle};
#[doc(inline)]
pub use setup::{setup_receiver, setup_sender};
#[doc(inline)]
pub use single_shot::{single_shot_open, single_shot_seal};

//-------- Top-level types --------//

/// Describes things that can go wrong when trying to seal or open a ciphertext
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpkeError {
    /// The allowed number of message encryptions has been reached
    MessageLimitReached,
    /// The authentication tag was invalid when opening
    InvalidTag,
    /// An unspecified error occured during encryption
    Encryption,
    /// A key exchange input or output was invalid
    InvalidKeyExchange,
    /// The KDF was asked to output too many bytes
    InvalidKdfLength,
    /// The deserializer was given a bad encoding
    InvalidEncoding,
}

impl core::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self {
            HpkeError::MessageLimitReached => "Message limit reached",
            HpkeError::InvalidTag => "Invalid tag",
            HpkeError::Encryption => "Encryption error",
            HpkeError::InvalidKeyExchange => "Key exchange validation error",
            HpkeError::InvalidKdfLength => "Too many bytes requested from KDF",
            HpkeError::InvalidEncoding => "Cannot deserialize byte sequence: invalid encoding",
        };
        f.write_str(kind)
    }
}

// An Error type is just something that's Debug and Display
#[cfg(feature = "std")]
impl std::error::Error for HpkeError {}
