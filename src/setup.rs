use crate::{
    aead::{Aead, AeadCtx},
    dh::{DiffieHellman, Marshallable, SharedSecret},
    kdf::Kdf,
    kem::{self, EncappedKey},
};

use byteorder::{BigEndian, ByteOrder};
use digest::{generic_array::GenericArray, Digest};
use rand::{CryptoRng, RngCore};

/// This is a hairy type signature, but it's just a fixed-size array of bytes whose length is the
/// digest size of the underlying hash function
pub type Psk<K> = GenericArray<u8, <<K as Kdf>::HashImpl as Digest>::OutputSize>;

/// Contains preshared key bytes as well as well as an identifier
pub struct PskBundle<'a, K: Kdf> {
    psk: Psk<K>,
    psk_id: &'a [u8],
}

/// The operation mode of HPKE. This determines what information is folded into the encryption
/// context derived in the `setup_*` functions. You can include a preshared key, the identity key
/// of the sender, both, or neither.
pub enum OpMode<'a, Dh: DiffieHellman, K: Kdf> {
    /// No extra information included
    Base,
    /// A preshared key known to the sender and receiver
    Psk(PskBundle<'a, K>),
    /// The identity public key of the sender
    Auth(Dh::PublicKey),
    /// Both of the above
    PskAuth(PskBundle<'a, K>, Dh::PublicKey),
}

// A convenience type. This is just a fixed-size array containing the bytes of a pubkey.
type MarshalledPubkey<Dh> =
    GenericArray<u8, <<Dh as DiffieHellman>::PublicKey as Marshallable>::OutputSize>;

// We need these convenience methods for getting default values out of the operation mode. These
// are defined in draft02 §6.1
impl<'a, Dh: DiffieHellman, K: Kdf> OpMode<'a, Dh, K> {
    fn mode_id(&self) -> u8 {
        match self {
            OpMode::Base => 0x00,
            OpMode::Psk(..) => 0x01,
            OpMode::Auth(..) => 0x02,
            OpMode::PskAuth(..) => 0x03,
        }
    }

    // Returns the sender's identity key if it's set in the mode, otherwise returns
    // [0u8; Dh::PublicKey::OutputSize]
    fn get_marshalled_sender_pk(&self) -> MarshalledPubkey<Dh> {
        // default_pkIm = zero(Npk)
        match self {
            OpMode::Auth(pk) => pk.marshal(),
            OpMode::PskAuth(_, pk) => pk.marshal(),
            _ => <MarshalledPubkey<Dh> as Default>::default(),
        }
    }

    // Returns the preshared key if it's set in the mode, otherwise returns
    // [0u8; Kdf::Hashfunction::OutputSize]
    fn get_psk(&self) -> Psk<K> {
        // default_psk = zero(Nh)
        match self {
            OpMode::Psk(p) => p.psk.clone(),
            OpMode::PskAuth(p, _) => p.psk.clone(),
            _ => Psk::<K>::default(),
        }
    }

    // Returns the preshared key ID if it's set in the mode, otherwise returns the emtpy string
    fn get_psk_id(&self) -> &'a [u8] {
        // default_pskID = zero(0)
        match self {
            OpMode::Psk(p) => p.psk_id,
            OpMode::PskAuth(p, _) => p.psk_id,
            _ => b"",
        }
    }
}

/* From draft02 §6.1
 *
    struct {
        // Mode and algorithms
        uint8 mode;
        uint16 kem_id;
        uint16 kdf_id;
        uint16 aead_id;

        // Public inputs to this key exchange
        opaque enc[Nenc];
        opaque pkR[Npk];
        opaque pkI[Npk];

        // Cryptographic hash of application-supplied pskID
        opaque pskID_hash[Nh];

        // Cryptographic hash of application-supplied info
        opaque info_hash[Nh];
    } HPKEContext;
*/

// This is the KeySchedule function defined in draft02 §5.1. It runs a KDF over all the parameters,
// inputs, and secrets, and spits out a key-nonce pair to be used for symmetric encryption
fn derive_enc_ctx<'a, A: Aead, Dh: DiffieHellman, K: Kdf>(
    mode: &OpMode<Dh, K>,
    pk_recip: &Dh::PublicKey,
    shared_secret: SharedSecret<Dh>,
    encapped_key: &EncappedKey<Dh>,
    info: &[u8],
) -> AeadCtx<A> {
    // In KeySchedule(),
    //     pkRm = Marshal(pkR)
    //     ciphersuite = concat(encode_big_endian(kem_id, 2),
    //                          encode_big_endian(kdf_id, 2),
    //                          encode_big_endian(aead_id, 2))
    //     pskID_hash = Hash(pskID)
    //     info_hash = Hash(info)
    //     context = concat(mode, ciphersuite, enc, pkRm, pkIm, pskID_hash, info_hash)
    //
    // `context` comes out to `7 + Nenc + 2*Npk + 2*Nh` bytes, where `Npk` is the size of a
    // marshalled pubkey, and `Nh` is the digest size of the KDF
    let context_bytes: Vec<u8> = {
        let mut buf = Vec::new();

        buf.push(mode.mode_id());

        BigEndian::write_u16(&mut buf, Dh::KEM_ID);
        BigEndian::write_u16(&mut buf, K::KDF_ID);
        BigEndian::write_u16(&mut buf, A::AEAD_ID);

        buf.extend(encapped_key.marshal());
        buf.extend(pk_recip.marshal().as_ref());
        buf.extend(mode.get_marshalled_sender_pk().as_ref());

        let psk_id_hash = K::HashImpl::digest(mode.get_psk_id());
        let info_hash = K::HashImpl::digest(info);

        buf.extend(psk_id_hash.as_slice());
        buf.extend(info_hash.as_slice());

        buf
    };

    // In KeySchedule(),
    //     secret = Extract(psk, zz)
    //     key = Expand(secret, concat("hpke key", context), Nk)
    //     nonce = Expand(secret, concat("hpke nonce", context), Nn)
    //     return Context(key, nonce)
    //
    // Instead of `secret` we derive an HKDF context which we run .expand() on to derive the
    // key-nonce pair.
    let (_, hkdf_ctx) = {
        let psk = mode.get_psk();
        let shared_secret_bytes: Vec<u8> = shared_secret.into();
        hkdf::Hkdf::<K::HashImpl>::extract(Some(&psk), &shared_secret_bytes)
    };
    // The info strings for HKDF::expand
    let key_info = [&b"hpke key"[..], &context_bytes].concat();
    let nonce_info = [&b"hpke nonce"[..], &context_bytes].concat();

    // Empty fixed-size buffers
    let mut key = crate::aead::Key::<A>::default();
    let mut nonce = crate::aead::Nonce::<A>::default();

    // Fill the key and nonce. This only errors if the key and nonce values are 255x the digest
    // size of the hash function. Since these values are fixed at compile time, we don't worry
    // about it.
    hkdf_ctx
        .expand(&key_info, key.as_mut_slice())
        .expect("aead key len is way too big");
    hkdf_ctx
        .expand(&nonce_info, nonce.as_mut_slice())
        .expect("aead nonce len is way too big");

    AeadCtx::new(key, nonce)
}

// From draft02 §5.1.4:
//     def SetupAuthPSKS(pkR, info, psk, pskID, skS):
//       zz, enc = AuthEncap(pkR, skS)
//       pkSm = Marshal(pk(skS))
//       return enc, KeySchedule(mode_auth_psk, pkR, zz, enc, info,
//                               psk, pskID, pkSm)
/// Initiates an encryption context to the given recipient
///
/// Returns: An encapsulated public key (intended to be sent to the recipient), and an encryption
/// context.
pub fn setup_sender<A, Dh, K, R>(
    mode: &OpMode<Dh, K>,
    pk_recip: &Dh::PublicKey,
    info: &[u8],
    csprng: &mut R,
) -> (EncappedKey<Dh>, AeadCtx<A>)
where
    A: Aead,
    Dh: DiffieHellman,
    K: Kdf,
    R: CryptoRng + RngCore,
{
    // Do the encapsulation
    let (shared_secret, encapped_key) = kem::encap(pk_recip, csprng);
    // Use everything to derive an encryption context
    let enc_ctx = derive_enc_ctx(mode, pk_recip, shared_secret, &encapped_key, info);

    (encapped_key, enc_ctx)
}

// def SetupBaseR(enc, skR, info):
//   zz = Decap(enc, skR)
//   return KeySchedule(mode_base, pk(skR), zz, enc, info,
//                      default_psk, default_pskID, default_pkIm)
/// Initiates an encryption context given a private key sk and a encapsulated key which was
/// encapsulated to `sk`'s corresponding public key
///
/// Returns: An encryption context
pub fn setup_receiver<A, Dh, K, R>(
    mode: &OpMode<Dh, K>,
    encapped_key: &EncappedKey<Dh>,
    sk_recip: &Dh::PrivateKey,
    info: &[u8],
) -> AeadCtx<A>
where
    A: Aead,
    Dh: DiffieHellman,
    K: Kdf,
    R: CryptoRng + RngCore,
{
    // Do the decapsulation
    let shared_secret = kem::decap(sk_recip, encapped_key);
    // Get the pubkey corresponding to the recipient's private key
    let pk_recip = Dh::sk_to_pk(sk_recip);

    // Use everything to derive an encryption context
    derive_enc_ctx(mode, &pk_recip, shared_secret, &encapped_key, info)
}
