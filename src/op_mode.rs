use crate::prelude::*;
use crate::{
    kdf::Kdf as KdfTrait,
    kex::{KeyExchange, Marshallable},
    util::static_zeros,
};

use core::marker::PhantomData;

use digest::generic_array::GenericArray;
use zeroize::Zeroizing;

/// A preshared key, i.e., a secret that the sender and recipient both know before any exchange has
/// happened
pub struct Psk<Kdf: KdfTrait> {
    bytes: Zeroizing<Vec<u8>>,
    marker: PhantomData<Kdf>,
}

impl<Kdf: KdfTrait> Psk<Kdf> {
    /// Constructs a preshared key from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Psk<Kdf> {
        Psk {
            bytes: Zeroizing::new(bytes),
            marker: PhantomData,
        }
    }
}

// We can't use #[derive(Clone)] because the compiler thinks that K has to be Clone.
impl<Kdf: KdfTrait> Clone for Psk<Kdf> {
    fn clone(&self) -> Self {
        // Do the obvious thing
        Psk {
            bytes: self.bytes.clone(),
            marker: self.marker,
        }
    }
}

/// Contains preshared key bytes and an identifier
pub struct PskBundle<Kdf: KdfTrait> {
    /// The preshared key
    pub psk: Psk<Kdf>,
    /// An bytestring that uniquely identifies this PSK
    pub psk_id: Vec<u8>,
}

// We can't use #[derive(Clone)] because the compiler thinks that K has to be Clone.
impl<Kdf: KdfTrait> Clone for PskBundle<Kdf> {
    fn clone(&self) -> Self {
        // Do the obvious thing
        PskBundle {
            psk: self.psk.clone(),
            psk_id: self.psk_id.clone(),
        }
    }
}

/// The operation mode of the receiver's side of HPKE. This determines what information is folded
/// into the encryption context derived in the `setup_receiver` functions. You can include a
/// preshared key, the identity key of the sender, both, or neither.
pub enum OpModeR<Kex: KeyExchange, Kdf: KdfTrait> {
    /// No extra information included
    Base,
    /// A preshared key known to the sender and receiver
    Psk(PskBundle<Kdf>),
    /// The identity public key of the sender
    Auth(Kex::PublicKey),
    /// Both of the above
    AuthPsk(Kex::PublicKey, PskBundle<Kdf>),
}

// Helper function for setup_receiver
impl<'a, Kex: KeyExchange, Kdf: KdfTrait> OpModeR<Kex, Kdf> {
    /// Returns the sender's identity pubkey if it's specified
    pub(crate) fn get_pk_sender_id(&self) -> Option<&Kex::PublicKey> {
        match self {
            OpModeR::Auth(pk) => Some(pk),
            OpModeR::AuthPsk(pk, _) => Some(pk),
            _ => None,
        }
    }
}

/// The operation mode of the sender's side of HPKE. This determines what information is folded
/// into the encryption context derived in the `setup_sender` functions. You can include a
/// preshared key, the identity key of the sender, both, or neither.
pub enum OpModeS<Kex: KeyExchange, Kdf: KdfTrait> {
    /// No extra information included
    Base,
    /// A preshared key known to the sender and receiver
    Psk(PskBundle<Kdf>),
    /// The identity keypair of the sender
    Auth((Kex::PrivateKey, Kex::PublicKey)),
    /// Both of the above
    AuthPsk((Kex::PrivateKey, Kex::PublicKey), PskBundle<Kdf>),
}

// Helpers functions for setup_sender and testing
impl<Kex: KeyExchange, Kdf: KdfTrait> OpModeS<Kex, Kdf> {
    /// Returns the sender's identity pubkey if it's specified
    pub(crate) fn get_sender_id_keypair(&self) -> Option<&(Kex::PrivateKey, Kex::PublicKey)> {
        match self {
            OpModeS::Auth(keypair) => Some(keypair),
            OpModeS::AuthPsk(keypair, _) => Some(keypair),
            _ => None,
        }
    }
}

// A convenience type. This is just a fixed-size array containing the bytes of a pubkey.
type MarshalledPubkey<Kex> =
    GenericArray<u8, <<Kex as KeyExchange>::PublicKey as Marshallable>::OutputSize>;

/// Represents the convenience methods necessary for getting default values out of the operation
/// mode. These are defined in draft02 §6.1.
pub(crate) trait OpMode<Kex: KeyExchange> {
    /// Gets the mode ID (hardcoded based on variant)
    fn mode_id(&self) -> u8;
    /// If this is an auth mode, returns the sender's pubkey. Otherwise returns zeros.
    fn get_marshalled_sender_pk(&self) -> MarshalledPubkey<Kex>;
    /// If this is a PSK mode, returns the PSK. Otherwise returns zeros.
    fn get_psk_bytes(&self) -> &[u8];
    /// If this is a PSK mode, returns the PSK ID. Otherwise returns the empty string.
    fn get_psk_id(&self) -> &[u8];
}

impl<Kex: KeyExchange, Kdf: KdfTrait> OpMode<Kex> for OpModeR<Kex, Kdf> {
    // Defined in draft02 §5.0
    fn mode_id(&self) -> u8 {
        match self {
            OpModeR::Base => 0x00,
            OpModeR::Psk(..) => 0x01,
            OpModeR::Auth(..) => 0x02,
            OpModeR::AuthPsk(..) => 0x03,
        }
    }

    // Returns the sender's identity key if it's set in the mode, otherwise returns
    // [0u8; Kex::PublicKey::OutputSize]
    fn get_marshalled_sender_pk(&self) -> MarshalledPubkey<Kex> {
        // draft02 §6.1: default_pkIm = zero(Npk)
        match self {
            OpModeR::Auth(pk) => pk.marshal(),
            OpModeR::AuthPsk(pk, _) => pk.marshal(),
            _ => <MarshalledPubkey<Kex> as Default>::default(),
        }
    }

    // Returns the preshared key bytes if it's set in the mode, otherwise returns
    // [0u8; Kdf::HashImpl::OutputSize]
    fn get_psk_bytes(&self) -> &[u8] {
        // draft02 §6.1: default_psk = zero(Nh)
        match self {
            OpModeR::Psk(bundle) => &bundle.psk.bytes,
            OpModeR::AuthPsk(_, bundle) => &bundle.psk.bytes,
            _ => static_zeros::<Kdf>(),
        }
    }

    // Returns the preshared key ID if it's set in the mode, otherwise returns the emtpy string
    fn get_psk_id(&self) -> &[u8] {
        // draft02 §6.1: default_pskID = zero(0)
        match self {
            OpModeR::Psk(p) => &p.psk_id,
            OpModeR::AuthPsk(_, p) => &p.psk_id,
            _ => b"",
        }
    }
}

// I know there's a bunch of code reuse here, but it's not so much that I feel the need to abstract
// something away
impl<Kex: KeyExchange, Kdf: KdfTrait> OpMode<Kex> for OpModeS<Kex, Kdf> {
    // Defined in draft02 §5.0
    fn mode_id(&self) -> u8 {
        match self {
            OpModeS::Base => 0x00,
            OpModeS::Psk(..) => 0x01,
            OpModeS::Auth(..) => 0x02,
            OpModeS::AuthPsk(..) => 0x03,
        }
    }

    // Returns the sender's identity key if it's set in the mode, otherwise returns
    // [0u8; Kex::PublicKey::OutputSize]
    fn get_marshalled_sender_pk(&self) -> MarshalledPubkey<Kex> {
        // draft02 §6.1: default_pkIm = zero(Npk)
        // Since this OpMode stores just the secret key, we have to convert it to a pubkey before
        // returning it.
        match self {
            OpModeS::Auth((_, pk)) => pk.marshal(),
            OpModeS::AuthPsk((_, pk), _) => pk.marshal(),
            _ => <MarshalledPubkey<Kex> as Default>::default(),
        }
    }

    // Returns the preshared key bytes if it's set in the mode, otherwise returns
    // [0u8; Kdf::Hashfunction::OutputSize]
    fn get_psk_bytes(&self) -> &[u8] {
        // draft02 §6.1: default_psk = zero(Nh)
        match self {
            OpModeS::Psk(bundle) => &bundle.psk.bytes,
            OpModeS::AuthPsk(_, bundle) => &bundle.psk.bytes,
            _ => static_zeros::<Kdf>(),
        }
    }

    // Returns the preshared key ID if it's set in the mode, otherwise returns the emtpy string
    fn get_psk_id(&self) -> &[u8] {
        // draft02 §6.1: default_pskID = zero(0)
        match self {
            OpModeS::Psk(p) => &p.psk_id,
            OpModeS::AuthPsk(_, p) => &p.psk_id,
            _ => b"",
        }
    }
}
