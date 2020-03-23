use crate::{
    dh::{DiffieHellman, Marshallable},
    kdf::Kdf,
};

use digest::{generic_array::GenericArray, Digest};

/// This is a hairy type signature, but it's just a fixed-size array of bytes whose length is the
/// digest size of the underlying hash function
pub type Psk<K> = GenericArray<u8, <<K as Kdf>::HashImpl as Digest>::OutputSize>;

/// Contains preshared key bytes as well as well as an identifier
pub struct PskBundle<K: Kdf> {
    pub psk: Psk<K>,
    pub psk_id: Vec<u8>,
}

/// The operation mode of the receiver's side of HPKE. This determines what information is folded
/// into the encryption context derived in the `setup_receiver` functions. You can include a
/// preshared key, the identity key of the sender, both, or neither.
pub enum OpModeR<Dh: DiffieHellman, K: Kdf> {
    /// No extra information included
    Base,
    /// A preshared key known to the sender and receiver
    Psk(PskBundle<K>),
    /// The identity public key of the sender
    Auth(Dh::PublicKey),
    /// Both of the above
    PskAuth(PskBundle<K>, Dh::PublicKey),
}

// Helper function for setup_receiver
impl<'a, Dh: DiffieHellman, K: Kdf> OpModeR<Dh, K> {
    /// Returns the sender's identity pubkey if it's specified
    pub(crate) fn get_pk_sender_id(&self) -> Option<&Dh::PublicKey> {
        match self {
            OpModeR::Auth(pk) => Some(pk),
            OpModeR::PskAuth(_, pk) => Some(pk),
            _ => None,
        }
    }
}

/// The operation mode of the sender's side of HPKE. This determines what information is folded
/// into the encryption context derived in the `setup_sender` functions. You can include a
/// preshared key, the identity key of the sender, both, or neither.
pub enum OpModeS<Dh: DiffieHellman, K: Kdf> {
    /// No extra information included
    Base,
    /// A preshared key known to the sender and receiver
    Psk(PskBundle<K>),
    /// The identity public key of the sender
    Auth(Dh::PrivateKey),
    /// Both of the above
    PskAuth(PskBundle<K>, Dh::PrivateKey),
}

// Helpers functions for setup_sender and testing
impl<Dh: DiffieHellman, K: Kdf> OpModeS<Dh, K> {
    /// Returns the sender's identity pubkey if it's specified
    pub(crate) fn get_sk_sender_id(&self) -> Option<&Dh::PrivateKey> {
        match self {
            OpModeS::Auth(sk) => Some(sk),
            OpModeS::PskAuth(_, sk) => Some(sk),
            _ => None,
        }
    }
}

// A convenience type. This is just a fixed-size array containing the bytes of a pubkey.
type MarshalledPubkey<Dh> =
    GenericArray<u8, <<Dh as DiffieHellman>::PublicKey as Marshallable>::OutputSize>;

/// Represents the convenience methods necessary for getting default values out of the operation
/// mode. These are defined in draft02 §6.1.
pub(crate) trait OpMode<Dh: DiffieHellman, K: Kdf> {
    /// Gets the mode ID (hardcoded based on variant)
    fn mode_id(&self) -> u8;
    /// If this is an auth mode, returns the sender's pubkey. Otherwise returns zeros.
    fn get_marshalled_sender_pk(&self) -> MarshalledPubkey<Dh>;
    /// If this is a PSK mode, returns the PSK. Otherwise returns zeros.
    fn get_psk(&self) -> Psk<K>;
    /// If this is a PSK mode, returns the PSK ID. Otherwise returns the empty string.
    fn get_psk_id(&self) -> &[u8];
}

impl<Dh: DiffieHellman, K: Kdf> OpMode<Dh, K> for OpModeR<Dh, K> {
    // Defined in draft02 §5.0
    fn mode_id(&self) -> u8 {
        match self {
            OpModeR::Base => 0x00,
            OpModeR::Psk(..) => 0x01,
            OpModeR::Auth(..) => 0x02,
            OpModeR::PskAuth(..) => 0x03,
        }
    }

    // Returns the sender's identity key if it's set in the mode, otherwise returns
    // [0u8; Dh::PublicKey::OutputSize]
    fn get_marshalled_sender_pk(&self) -> MarshalledPubkey<Dh> {
        // draft02 §5.1: default_pkIm = zero(Npk)
        match self {
            OpModeR::Auth(pk) => pk.marshal(),
            OpModeR::PskAuth(_, pk) => pk.marshal(),
            _ => <MarshalledPubkey<Dh> as Default>::default(),
        }
    }

    // Returns the preshared key if it's set in the mode, otherwise returns
    // [0u8; Kdf::Hashfunction::OutputSize]
    fn get_psk(&self) -> Psk<K> {
        // draft02 §5.1: default_psk = zero(Nh)
        match self {
            OpModeR::Psk(p) => p.psk.clone(),
            OpModeR::PskAuth(p, _) => p.psk.clone(),
            _ => Psk::<K>::default(),
        }
    }

    // Returns the preshared key ID if it's set in the mode, otherwise returns the emtpy string
    fn get_psk_id(&self) -> &[u8] {
        // draft02 §5.1: default_pskID = zero(0)
        match self {
            OpModeR::Psk(p) => &p.psk_id,
            OpModeR::PskAuth(p, _) => &p.psk_id,
            _ => b"",
        }
    }
}

// I know there's a bunch of code reuse here, but it's not so much that I feel the need to abstract
// something away
impl<Dh: DiffieHellman, K: Kdf> OpMode<Dh, K> for OpModeS<Dh, K> {
    // Defined in draft02 §5.0
    fn mode_id(&self) -> u8 {
        match self {
            OpModeS::Base => 0x00,
            OpModeS::Psk(..) => 0x01,
            OpModeS::Auth(..) => 0x02,
            OpModeS::PskAuth(..) => 0x03,
        }
    }

    // Returns the sender's identity key if it's set in the mode, otherwise returns
    // [0u8; Dh::PublicKey::OutputSize]
    fn get_marshalled_sender_pk(&self) -> MarshalledPubkey<Dh> {
        // draft02 §5.1: default_pkIm = zero(Npk)
        // Since this OpMode stores just the secret key, we have to convert it to a pubkey before
        // returning it.
        match self {
            OpModeS::Auth(sk) => {
                let pk = Dh::sk_to_pk(sk);
                pk.marshal()
            }
            OpModeS::PskAuth(_, sk) => {
                let pk = Dh::sk_to_pk(sk);
                pk.marshal()
            }
            _ => <MarshalledPubkey<Dh> as Default>::default(),
        }
    }

    // Returns the preshared key if it's set in the mode, otherwise returns
    // [0u8; Kdf::Hashfunction::OutputSize]
    fn get_psk(&self) -> Psk<K> {
        // draft02 §5.1: default_psk = zero(Nh)
        match self {
            OpModeS::Psk(p) => p.psk.clone(),
            OpModeS::PskAuth(p, _) => p.psk.clone(),
            _ => Psk::<K>::default(),
        }
    }

    // Returns the preshared key ID if it's set in the mode, otherwise returns the emtpy string
    fn get_psk_id(&self) -> &[u8] {
        // draft02 §5.1: default_pskID = zero(0)
        match self {
            OpModeS::Psk(p) => &p.psk_id,
            OpModeS::PskAuth(p, _) => &p.psk_id,
            _ => b"",
        }
    }
}
