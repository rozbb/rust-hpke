use crate::{kem::Kem as KemTrait, HpkeError};

/// Contains preshared key bytes and an identifier. This is intended to go inside an `OpModeR` or
/// `OpModeS` struct.
#[derive(Clone, Copy)]
pub struct PskBundle<'a> {
    /// The preshared key
    psk: &'a [u8],
    /// A bytestring that uniquely identifies this PSK
    psk_id: &'a [u8],
}

impl<'a> PskBundle<'a> {
    /// Creates a new preshared key bundle from the given preshared key and its ID
    ///
    /// Errors
    /// ======
    /// `psk` and `psk_id` must either both be empty or both be nonempty. If one is empty while
    /// the other is not, then this returns [`HpkeError::InvalidPskBundle`].
    ///
    /// Other requirements
    /// ==================
    /// Other requirements from the HPKE spec: `psk` MUST contain at least 32 bytes of entropy.
    /// Further, `psk.len()` SHOULD be at least as long as an extracted key from the KDF you use
    /// with `setup_sender`/`setup_receiver`, i.e., at least `Kdf::extracted_key_size()`.
    pub fn new(psk: &'a [u8], psk_id: &'a [u8]) -> Result<Self, HpkeError> {
        // RFC 9180 §5.1: The psk and psk_id fields MUST appear together or not at all
        if (psk.is_empty() && psk_id.is_empty()) || (!psk.is_empty() && !psk_id.is_empty()) {
            Ok(PskBundle { psk, psk_id })
        } else {
            Err(HpkeError::InvalidPskBundle)
        }
    }
}

/// The operation mode of the HPKE session (receiver's view). This is how the sender authenticates
/// their identity to the receiver. This authentication information can include a preshared key,
/// the identity key of the sender, both, or neither. `Base` is the only mode that does not provide
/// any kind of sender identity authentication.
pub enum OpModeR<'a, Kem: KemTrait> {
    /// No extra information included
    Base,
    /// A preshared key known to the sender and receiver. If the bundle contents is empty strings,
    /// then this is equivalent to `Base`.
    Psk(PskBundle<'a>),
    /// The identity public key of the sender
    Auth(Kem::PublicKey),
    /// Both of the above
    AuthPsk(Kem::PublicKey, PskBundle<'a>),
}

// Helper function for setup_receiver
impl<Kem: KemTrait> OpModeR<'_, Kem> {
    /// Returns the sender's identity pubkey if it's specified
    pub(crate) fn get_pk_sender_id(&self) -> Option<&Kem::PublicKey> {
        match self {
            OpModeR::Auth(pk) => Some(pk),
            OpModeR::AuthPsk(pk, _) => Some(pk),
            _ => None,
        }
    }
}

/// The operation mode of the HPKE session (sender's view). This is how the sender authenticates
/// their identity to the receiver. This authentication information can include a preshared key,
/// the identity key of the sender, both, or neither. `Base` is the only mode that does not provide
/// any kind of sender identity authentication.
pub enum OpModeS<'a, Kem: KemTrait> {
    /// No extra information included
    Base,
    /// A preshared key known to the sender and receiver. If the bundle contents is empty strings,
    /// then this is equivalent to `Base`.
    Psk(PskBundle<'a>),
    /// The identity keypair of the sender
    Auth((Kem::PrivateKey, Kem::PublicKey)),
    /// Both of the above
    AuthPsk((Kem::PrivateKey, Kem::PublicKey), PskBundle<'a>),
}

// Helpers functions for setup_sender and testing
impl<Kem: KemTrait> OpModeS<'_, Kem> {
    /// Returns the sender's identity pubkey if it's specified
    pub(crate) fn get_sender_id_keypair(&self) -> Option<(&Kem::PrivateKey, &Kem::PublicKey)> {
        match self {
            OpModeS::Auth(keypair) => Some((&keypair.0, &keypair.1)),
            OpModeS::AuthPsk(keypair, _) => Some((&keypair.0, &keypair.1)),
            _ => None,
        }
    }
}

/// Represents the convenience methods necessary for getting default values out of the operation
/// mode
pub(crate) trait OpMode<Kem: KemTrait> {
    /// Gets the mode ID (hardcoded based on variant)
    fn mode_id(&self) -> u8;
    /// If this is a PSK mode, returns the PSK. Otherwise returns the empty string.
    fn get_psk_bytes(&self) -> &[u8];
    /// If this is a PSK mode, returns the PSK ID. Otherwise returns the empty string.
    fn get_psk_id(&self) -> &[u8];
}

impl<Kem: KemTrait> OpMode<Kem> for OpModeR<'_, Kem> {
    // Defined in RFC 9180 §5 Table 1
    fn mode_id(&self) -> u8 {
        match self {
            OpModeR::Base => 0x00,
            OpModeR::Psk(..) => 0x01,
            OpModeR::Auth(..) => 0x02,
            OpModeR::AuthPsk(..) => 0x03,
        }
    }

    // Returns the preshared key bytes if it's set in the mode, otherwise returns
    // [0u8; Kdf::HashImpl::OutputSize]
    fn get_psk_bytes(&self) -> &[u8] {
        // RFC 9180 §5.1: default_psk = ""
        match self {
            OpModeR::Psk(bundle) => bundle.psk,
            OpModeR::AuthPsk(_, bundle) => bundle.psk,
            _ => &[],
        }
    }

    // Returns the preshared key ID if it's set in the mode, otherwise returns the emtpy string
    fn get_psk_id(&self) -> &[u8] {
        // RFC 9180 §5.1: default_psk_id = ""
        match self {
            OpModeR::Psk(p) => p.psk_id,
            OpModeR::AuthPsk(_, p) => p.psk_id,
            _ => &[],
        }
    }
}

// I know there's a bunch of code reuse here, but it's not so much that I feel the need to abstract
// something away
impl<Kem: KemTrait> OpMode<Kem> for OpModeS<'_, Kem> {
    // Defined in RFC 9180 §5 Table 1
    fn mode_id(&self) -> u8 {
        match self {
            OpModeS::Base => 0x00,
            OpModeS::Psk(..) => 0x01,
            OpModeS::Auth(..) => 0x02,
            OpModeS::AuthPsk(..) => 0x03,
        }
    }

    // Returns the preshared key bytes if it's set in the mode, otherwise returns
    // [0u8; Kdf::Hashfunction::OutputSize]
    fn get_psk_bytes(&self) -> &[u8] {
        // RFC 9180 §5.1: default_psk = ""
        match self {
            OpModeS::Psk(bundle) => bundle.psk,
            OpModeS::AuthPsk(_, bundle) => bundle.psk,
            _ => &[],
        }
    }

    // Returns the preshared key ID if it's set in the mode, otherwise returns the emtpy string
    fn get_psk_id(&self) -> &[u8] {
        // RFC 9180 §5.1: default_psk_id = ""
        match self {
            OpModeS::Psk(p) => p.psk_id,
            OpModeS::AuthPsk(_, p) => p.psk_id,
            _ => &[],
        }
    }
}

// Test that you can only make a PskBundle if both fields are empty or both fields are nonempty
#[test]
fn psk_bundle_validation() {
    assert!(PskBundle::new(b"hello", b"world").is_ok());
    assert!(PskBundle::new(b"", b"").is_ok());
    assert!(PskBundle::new(b"hello", b"").is_err());
    assert!(PskBundle::new(b"", b"world").is_err());
}
