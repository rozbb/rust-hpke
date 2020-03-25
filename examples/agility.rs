#![allow(dead_code)]
//! Here's the gist of this file: Instead of doing things at the type level, you can use zero-sized
//! types and runtime validity checks to do all of HPKE. This file is a rough idea of how one would
//! go about implementing that. There isn't too much repetition. The main part where you have to
//! get clever is in `agile_setup_*`, where you have to have a match statement with up to 3·3·5 =
//! 45 branches for all the different AEAD-DH-KDF combinations. Practically speaking, though,
//! that's not a big number, so writing that out and using a macro for the actual work (e.g.,
//! `do_setup_sender!`) seems to be the way to go.
//!
//! The other point of this file is to demonstrate how messy crypto agility makes things. Many
//! people have different needs when it comes to agility, so I implore you **DO NOT COPY THIS FILE
//! BLINDLY**. Think about what you actually need, make that instead, and make sure to write lots
//! of runtime checks.

use hpke::{
    aead::{Aead, AeadCtx, AeadTag, AesGcm128, AesGcm256, AssociatedData, ChaCha20Poly1305},
    dh::{DiffieHellman, Marshallable, MarshalledPrivateKey, MarshalledPublicKey, X25519},
    kdf::{HkdfSha256, Kdf},
    kem::MarshalledEncappedKey,
    op_mode::{Psk, PskBundle},
    setup_receiver, setup_sender, EncappedKey, HpkeError, OpModeR, OpModeS,
};

use rand::{CryptoRng, RngCore};

// In your head, just replace "agile" with "dangerous" :)

trait AgileAeadCtx {
    fn seal<'a>(
        &mut self,
        plaintext: &mut [u8],
        aad: AssociatedData<'a>,
    ) -> Result<AgileAeadTag, HpkeError>;

    fn open<'a>(
        &mut self,
        ciphertext: &mut [u8],
        aad: AssociatedData<'a>,
        tag_bytes: &[u8],
    ) -> Result<(), AgileHpkeError>;
}

type AgileAeadTag = Vec<u8>;

#[derive(Debug)]
enum AgileHpkeError {
    /// When you don't give an algorithm an array of the length it wants. Error is of the form
    /// `(thing_with_wrong_len, expected_len, given_len)`.
    LengthMismatch(&'static str, usize, usize),
    /// When you don't give an algorithm an array of the length it wants. Error is of the form
    /// `((alg1, alg1_location) , (alg2, alg2_location))`.
    AlgMismatch((&'static str, &'static str), (&'static str, &'static str)),
    /// When you get an algorithm identifier you don't recognize. Error is of the form
    /// `(alg, given_id)`.
    UnknownAlgIdent(&'static str, u16),
    /// Represents an error in the `hpke` crate
    HpkeError(HpkeError),
}

impl<A: Aead, K: Kdf> AgileAeadCtx for AeadCtx<A, K> {
    fn seal<'a>(
        &mut self,
        plaintext: &mut [u8],
        aad: AssociatedData<'a>,
    ) -> Result<Vec<u8>, HpkeError> {
        self.seal(plaintext, aad).map(|tag| tag.to_vec())
    }

    fn open<'a>(
        &mut self,
        ciphertext: &mut [u8],
        aad: AssociatedData<'a>,
        tag_bytes: &[u8],
    ) -> Result<(), AgileHpkeError> {
        let tag = {
            let mut tag_buf = <AeadTag<A> as Default>::default();
            let expected_len = tag_buf.len();
            let given_len = tag_bytes.len();
            if expected_len != given_len {
                return Err(AgileHpkeError::LengthMismatch(
                    "tag",
                    expected_len,
                    given_len,
                ));
            }
            tag_buf.clone_from_slice(tag_bytes);
            tag_buf
        };
        self.open(ciphertext, aad, &tag)
            .map_err(|e| AgileHpkeError::HpkeError(e))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AeadAlg {
    AesGcm128,
    AesGcm256,
    ChaCha20Poly1305,
}

impl AeadAlg {
    fn name(&self) -> &'static str {
        match self {
            AeadAlg::AesGcm128 => "AesGcm128",
            AeadAlg::AesGcm256 => "AesGcm256",
            AeadAlg::ChaCha20Poly1305 => "ChaCha20Poly1305",
        }
    }

    fn try_from_u16(id: u16) -> Result<AeadAlg, AgileHpkeError> {
        let res = match id {
            0x01 => AeadAlg::AesGcm128,
            0x02 => AeadAlg::AesGcm256,
            0x03 => AeadAlg::ChaCha20Poly1305,
            _ => return Err(AgileHpkeError::UnknownAlgIdent("AeadAlg", id)),
        };

        Ok(res)
    }

    fn to_u16(&self) -> u16 {
        match self {
            AeadAlg::AesGcm128 => 0x01,
            AeadAlg::AesGcm256 => 0x02,
            AeadAlg::ChaCha20Poly1305 => 0x03,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum KdfAlg {
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

impl KdfAlg {
    fn name(&self) -> &'static str {
        match self {
            KdfAlg::HkdfSha256 => "HkdfSha256",
            KdfAlg::HkdfSha384 => "HkdfSha384",
            KdfAlg::HkdfSha512 => "HkdfSha512",
        }
    }

    fn try_from_u16(id: u16) -> Result<KdfAlg, AgileHpkeError> {
        let res = match id {
            0x01 => KdfAlg::HkdfSha256,
            0x02 => KdfAlg::HkdfSha384,
            0x03 => KdfAlg::HkdfSha512,
            _ => return Err(AgileHpkeError::UnknownAlgIdent("KdfAlg", id)),
        };

        Ok(res)
    }

    fn to_u16(&self) -> u16 {
        match self {
            KdfAlg::HkdfSha256 => 0x01,
            KdfAlg::HkdfSha384 => 0x02,
            KdfAlg::HkdfSha512 => 0x03,
        }
    }

    fn get_digest_len(&self) -> usize {
        match self {
            KdfAlg::HkdfSha256 => 32,
            KdfAlg::HkdfSha384 => 48,
            KdfAlg::HkdfSha512 => 64,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DhAlg {
    X25519,
    X448,
    P256,
    P384,
    P521,
}

impl DhAlg {
    fn name(&self) -> &'static str {
        match self {
            DhAlg::X25519 => "X25519",
            DhAlg::X448 => "X448",
            DhAlg::P256 => "P256",
            DhAlg::P384 => "P384",
            DhAlg::P521 => "P521",
        }
    }

    fn try_from_u16(id: u16) -> Result<DhAlg, AgileHpkeError> {
        let res = match id {
            0x10 => DhAlg::P256,
            0x11 => DhAlg::P384,
            0x12 => DhAlg::P521,
            0x20 => DhAlg::X25519,
            0x21 => DhAlg::X448,
            _ => return Err(AgileHpkeError::UnknownAlgIdent("KdfAlg", id)),
        };

        Ok(res)
    }

    fn to_u16(&self) -> u16 {
        match self {
            DhAlg::P256 => 0x10,
            DhAlg::P384 => 0x11,
            DhAlg::P521 => 0x12,
            DhAlg::X25519 => 0x20,
            DhAlg::X448 => 0x21,
        }
    }

    fn get_pubkey_len(&self) -> usize {
        match self {
            DhAlg::X25519 => 32,
            DhAlg::X448 => 56,
            DhAlg::P256 => 65,
            DhAlg::P384 => 97,
            DhAlg::P521 => 133,
        }
    }
}

#[derive(Clone)]
struct AgilePublicKey {
    dh_alg: DhAlg,
    pubkey_bytes: Vec<u8>,
}

impl AgilePublicKey {
    fn try_lift<Dh: DiffieHellman>(self) -> Result<Dh::PublicKey, AgileHpkeError> {
        let mut key_buf = <MarshalledPublicKey<Dh> as Default>::default();
        if self.pubkey_bytes.len() != key_buf.len() {
            return Err(AgileHpkeError::LengthMismatch(
                "AgilePublicKey",
                key_buf.len(),
                self.pubkey_bytes.len(),
            ));
        }

        key_buf.clone_from_slice(&self.pubkey_bytes);
        Ok(Dh::PublicKey::unmarshal(key_buf))
    }
}

#[derive(Clone)]
struct AgileEncappedKey {
    dh_alg: DhAlg,
    encapped_key_bytes: Vec<u8>,
}

impl AgileEncappedKey {
    fn try_lift<Dh: DiffieHellman>(self) -> Result<EncappedKey<Dh>, AgileHpkeError> {
        let mut key_buf = <MarshalledEncappedKey<Dh> as Default>::default();
        if self.encapped_key_bytes.len() != key_buf.len() {
            return Err(AgileHpkeError::LengthMismatch(
                "AgileEncappedKey",
                key_buf.len(),
                self.encapped_key_bytes.len(),
            ));
        }

        key_buf.clone_from_slice(&self.encapped_key_bytes);
        Ok(EncappedKey::<Dh>::unmarshal(key_buf))
    }
}

#[derive(Clone)]
struct AgilePrivateKey {
    dh_alg: DhAlg,
    privkey_bytes: Vec<u8>,
}

impl AgilePrivateKey {
    fn try_lift<Dh: DiffieHellman>(self) -> Result<Dh::PrivateKey, AgileHpkeError> {
        let mut key_buf = <MarshalledPrivateKey<Dh> as Default>::default();
        if self.privkey_bytes.len() != key_buf.len() {
            return Err(AgileHpkeError::LengthMismatch(
                "AgilePrivateKey",
                key_buf.len(),
                self.privkey_bytes.len(),
            ));
        }

        key_buf.clone_from_slice(&self.privkey_bytes);
        Ok(Dh::PrivateKey::unmarshal(key_buf))
    }
}

// The leg work of agile_gen_keypair
macro_rules! do_gen_keypair {
    ($dh_ty:ty, $dh_alg:ident, $csprng:ident) => {{
        type Dh = $dh_ty;
        let dh_alg = $dh_alg;
        let csprng = $csprng;

        let (sk, pk) = Dh::gen_keypair(csprng);
        let sk = AgilePrivateKey {
            dh_alg: dh_alg,
            privkey_bytes: sk.marshal().to_vec(),
        };
        let pk = AgilePublicKey {
            dh_alg: dh_alg,
            pubkey_bytes: pk.marshal().to_vec(),
        };

        (sk, pk)
    }};
}

fn agile_gen_keypair<R: CryptoRng + RngCore>(
    dh_alg: DhAlg,
    csprng: &mut R,
) -> (AgilePrivateKey, AgilePublicKey) {
    match dh_alg {
        DhAlg::X25519 => do_gen_keypair!(X25519, dh_alg, csprng),
        _ => unimplemented!(),
    }
}

#[derive(Clone)]
struct AgileOpModeR {
    dh_alg: DhAlg,
    kdf_alg: KdfAlg,
    op_mode_ty: AgileOpModeRTy,
}

impl AgileOpModeR {
    fn try_lift<Dh: DiffieHellman, K: Kdf>(self) -> Result<OpModeR<Dh, K>, AgileHpkeError> {
        let res = match self.op_mode_ty {
            AgileOpModeRTy::Base => OpModeR::Base,
            AgileOpModeRTy::Psk(bundle) => OpModeR::Psk(bundle.try_lift::<K>()?),
            AgileOpModeRTy::Auth(pk) => OpModeR::Auth(pk.try_lift::<Dh>()?),
            AgileOpModeRTy::AuthPsk(pk, bundle) => {
                OpModeR::AuthPsk(pk.try_lift::<Dh>()?, bundle.try_lift::<K>()?)
            }
        };

        Ok(res)
    }

    fn validate(&self) -> Result<(), AgileHpkeError> {
        match &self.op_mode_ty {
            AgileOpModeRTy::Base => (),
            AgileOpModeRTy::Psk(bundle) => {
                if bundle.dh_alg != self.dh_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.dh_alg.name(), "AgileOpModeR::dh_alg"),
                        (
                            bundle.dh_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePskBundle::dh_alg",
                        ),
                    ));
                } else if bundle.kdf_alg != self.kdf_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kdf_alg.name(), "AgileOpModeR::kdf_alg"),
                        (
                            bundle.kdf_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePskBundle::kdf_alg",
                        ),
                    ));
                }
            }
            AgileOpModeRTy::Auth(pk) => {
                if pk.dh_alg != self.dh_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.dh_alg.name(), "AgileOpModeR::dh_alg"),
                        (
                            pk.dh_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePublicKey::dh_alg",
                        ),
                    ));
                }
            }
            AgileOpModeRTy::AuthPsk(pk, bundle) => {
                if bundle.dh_alg != self.dh_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.dh_alg.name(), "AgileOpModeR::dh_alg"),
                        (
                            bundle.dh_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePskBundle::dh_alg",
                        ),
                    ));
                } else if bundle.kdf_alg != self.kdf_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kdf_alg.name(), "AgileOpModeR::kdf_alg"),
                        (
                            bundle.kdf_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePskBundle::kdf_alg",
                        ),
                    ));
                } else if pk.dh_alg != self.dh_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.dh_alg.name(), "AgileOpModeR::dh_alg"),
                        (
                            pk.dh_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePublicKey::dh_alg",
                        ),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
enum AgileOpModeRTy {
    Base,
    Psk(AgilePskBundle),
    Auth(AgilePublicKey),
    AuthPsk(AgilePublicKey, AgilePskBundle),
}

#[derive(Clone)]
struct AgileOpModeS {
    dh_alg: DhAlg,
    kdf_alg: KdfAlg,
    op_mode_ty: AgileOpModeSTy,
}

impl AgileOpModeS {
    fn try_lift<Dh: DiffieHellman, K: Kdf>(self) -> Result<OpModeS<Dh, K>, AgileHpkeError> {
        let res = match self.op_mode_ty {
            AgileOpModeSTy::Base => OpModeS::Base,
            AgileOpModeSTy::Psk(bundle) => OpModeS::Psk(bundle.try_lift::<K>()?),
            AgileOpModeSTy::Auth(sk) => OpModeS::Auth(sk.try_lift::<Dh>()?),
            AgileOpModeSTy::AuthPsk(sk, bundle) => {
                OpModeS::AuthPsk(sk.try_lift::<Dh>()?, bundle.try_lift::<K>()?)
            }
        };

        Ok(res)
    }

    fn validate(&self) -> Result<(), AgileHpkeError> {
        match &self.op_mode_ty {
            AgileOpModeSTy::Base => (),
            AgileOpModeSTy::Psk(bundle) => {
                if bundle.dh_alg != self.dh_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.dh_alg.name(), "AgileOpModeS::dh_alg"),
                        (
                            bundle.dh_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePskBundle::dh_alg",
                        ),
                    ));
                } else if bundle.kdf_alg != self.kdf_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kdf_alg.name(), "AgileOpModeS::kdf_alg"),
                        (
                            bundle.kdf_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePskBundle::kdf_alg",
                        ),
                    ));
                }
            }
            AgileOpModeSTy::Auth(sk) => {
                if sk.dh_alg != self.dh_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.dh_alg.name(), "AgileOpModeS::dh_alg"),
                        (
                            sk.dh_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePrivateKey::dh_alg",
                        ),
                    ));
                }
            }
            AgileOpModeSTy::AuthPsk(sk, bundle) => {
                if bundle.dh_alg != self.dh_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.dh_alg.name(), "AgileOpModeS::dh_alg"),
                        (
                            bundle.dh_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePskBundle::dh_alg",
                        ),
                    ));
                } else if bundle.kdf_alg != self.kdf_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kdf_alg.name(), "AgileOpModeS::kdf_alg"),
                        (
                            bundle.kdf_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePskBundle::kdf_alg",
                        ),
                    ));
                } else if sk.dh_alg != self.dh_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.dh_alg.name(), "AgileOpModeS::dh_alg"),
                        (
                            sk.dh_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePrivateKey::dh_alg",
                        ),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
enum AgileOpModeSTy {
    Base,
    Psk(AgilePskBundle),
    Auth(AgilePrivateKey),
    AuthPsk(AgilePrivateKey, AgilePskBundle),
}

#[derive(Clone)]
struct AgilePskBundle {
    dh_alg: DhAlg,
    kdf_alg: KdfAlg,
    psk_bytes: Vec<u8>,
    psk_id: Vec<u8>,
}

impl AgilePskBundle {
    fn try_lift<K: Kdf>(self) -> Result<PskBundle<K>, AgileHpkeError> {
        let mut psk = <Psk<K> as Default>::default();
        if psk.len() != self.psk_bytes.len() {
            return Err(AgileHpkeError::LengthMismatch(
                "AgilePskBundle",
                psk.len(),
                self.psk_bytes.len(),
            ));
        }
        psk.clone_from_slice(&self.psk_bytes);

        Ok(PskBundle {
            psk: psk,
            psk_id: self.psk_id,
        })
    }
}

// The leg work of agile_setup_sender
macro_rules! do_setup_sender {
    ($aead_ty:ty, $dh_ty:ty, $kdf_ty:ty, $mode:ident, $pk_recip:ident, $info:ident, $csprng:ident) => {{
        type A = $aead_ty;
        type Dh = $dh_ty;
        type K = $kdf_ty;

        let dh_alg = $mode.dh_alg;
        let mode = $mode.clone().try_lift::<Dh, K>()?;
        let pk_recip = $pk_recip.clone().try_lift::<Dh>()?;
        let info = $info;
        let csprng = $csprng;

        let (encapped_key, aead_ctx) = setup_sender::<A, Dh, K, _>(&mode, &pk_recip, info, csprng);
        let encapped_key = AgileEncappedKey {
            dh_alg: dh_alg,
            encapped_key_bytes: encapped_key.marshal().to_vec(),
        };

        Ok((encapped_key, Box::new(aead_ctx)))
    }};
}

fn agile_setup_sender<R: CryptoRng + RngCore>(
    aead_alg: AeadAlg,
    mode: &AgileOpModeS,
    pk_recip: &AgilePublicKey,
    info: &[u8],
    csprng: &mut R,
) -> Result<(AgileEncappedKey, Box<dyn AgileAeadCtx>), AgileHpkeError> {
    // Do all the necessary validation
    mode.validate()?;
    if mode.dh_alg != pk_recip.dh_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (mode.dh_alg.name(), "mode::dh_alg"),
            (pk_recip.dh_alg.name(), "pk_recip::dh_alg"),
        ));
    }

    // In a complete implementation, this would have 45 branches
    match (aead_alg, mode.dh_alg, mode.kdf_alg) {
        (AeadAlg::ChaCha20Poly1305, DhAlg::X25519, KdfAlg::HkdfSha256) => do_setup_sender!(
            ChaCha20Poly1305,
            X25519,
            HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm128, DhAlg::X25519, KdfAlg::HkdfSha256) => {
            do_setup_sender!(AesGcm128, X25519, HkdfSha256, mode, pk_recip, info, csprng)
        }
        (AeadAlg::AesGcm256, DhAlg::X25519, KdfAlg::HkdfSha256) => {
            do_setup_sender!(AesGcm256, X25519, HkdfSha256, mode, pk_recip, info, csprng)
        }
        _ => unimplemented!(),
    }
}

// The leg work of agile_setup_receiver
macro_rules! do_setup_receiver {
    ($aead_ty:ty, $dh_ty:ty, $kdf_ty:ty, $mode:ident, $sk_recip:ident, $encapped_key:ident, $info:ident) => {{
        type A = $aead_ty;
        type Dh = $dh_ty;
        type K = $kdf_ty;

        let mode = $mode.clone().try_lift::<Dh, K>()?;
        let sk_recip = $sk_recip.clone().try_lift::<Dh>()?;
        let encapped_key = $encapped_key.clone().try_lift::<Dh>()?;
        let info = $info;

        let aead_ctx = setup_receiver::<A, Dh, K>(&mode, &sk_recip, &encapped_key, info);
        Ok(Box::new(aead_ctx))
    }};
}

fn agile_setup_receiver(
    aead_alg: AeadAlg,
    mode: &AgileOpModeR,
    sk_recip: &AgilePrivateKey,
    encapped_key: &AgileEncappedKey,
    info: &[u8],
) -> Result<Box<dyn AgileAeadCtx>, AgileHpkeError> {
    // Do all the necessary validation
    mode.validate()?;
    if mode.dh_alg != sk_recip.dh_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (mode.dh_alg.name(), "mode::dh_alg"),
            (sk_recip.dh_alg.name(), "sk_recip::dh_alg"),
        ));
    }
    if sk_recip.dh_alg != encapped_key.dh_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (sk_recip.dh_alg.name(), "sk_recip::dh_alg"),
            (encapped_key.dh_alg.name(), "encapped_key::dh_alg"),
        ));
    }

    // In a complete implementation, this would have 45 branches
    match (aead_alg, mode.dh_alg, mode.kdf_alg) {
        (AeadAlg::ChaCha20Poly1305, DhAlg::X25519, KdfAlg::HkdfSha256) => do_setup_receiver!(
            ChaCha20Poly1305,
            X25519,
            HkdfSha256,
            mode,
            sk_recip,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm128, DhAlg::X25519, KdfAlg::HkdfSha256) => do_setup_receiver!(
            AesGcm128,
            X25519,
            HkdfSha256,
            mode,
            sk_recip,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm256, DhAlg::X25519, KdfAlg::HkdfSha256) => do_setup_receiver!(
            AesGcm256,
            X25519,
            HkdfSha256,
            mode,
            sk_recip,
            encapped_key,
            info
        ),
        _ => unimplemented!(),
    }
}

fn main() {
    let mut csprng = rand::thread_rng();

    let supported_aead_algs = &[
        AeadAlg::AesGcm128,
        AeadAlg::AesGcm256,
        AeadAlg::ChaCha20Poly1305,
    ];
    let supported_dh_algs = &[DhAlg::X25519];
    let supported_kdf_algs = &[KdfAlg::HkdfSha256];

    // For every combination of supported algorithms, test an encryption-decryption round trip
    for &aead_alg in supported_aead_algs {
        for &dh_alg in supported_dh_algs {
            for &kdf_alg in supported_kdf_algs {
                let info = b"we're gonna agile him in his clavicle";

                // Make a random sender keypair and PSK bundle
                let (sk_sender, pk_sender) = agile_gen_keypair(dh_alg, &mut csprng);
                let psk_bundle = {
                    let mut psk_bytes = vec![0u8; kdf_alg.get_digest_len()];
                    let psk_id = b"preshared key attempt #5, take 2".to_vec();
                    csprng.fill_bytes(&mut psk_bytes);
                    AgilePskBundle {
                        dh_alg,
                        kdf_alg,
                        psk_bytes,
                        psk_id,
                    }
                };

                // Make two agreeing OpModes (AuthPsk is the most complicated, so we're just using
                // that).
                let op_mode_s_ty = AgileOpModeSTy::AuthPsk(sk_sender, psk_bundle.clone());
                let op_mode_s = AgileOpModeS {
                    dh_alg: dh_alg,
                    kdf_alg: kdf_alg,
                    op_mode_ty: op_mode_s_ty,
                };
                let op_mode_r_ty = AgileOpModeRTy::AuthPsk(pk_sender, psk_bundle.clone());
                let op_mode_r = AgileOpModeR {
                    dh_alg: dh_alg,
                    kdf_alg: kdf_alg,
                    op_mode_ty: op_mode_r_ty,
                };

                // Set up the sender's encryption context
                let (sk_recip, pk_recip) = agile_gen_keypair(dh_alg, &mut csprng);
                let (encapped_key, mut aead_ctx1) =
                    agile_setup_sender(aead_alg, &op_mode_s, &pk_recip, &info[..], &mut csprng)
                        .unwrap();

                // Set up the receivers's encryption context
                let mut aead_ctx2 =
                    agile_setup_receiver(aead_alg, &op_mode_r, &sk_recip, &encapped_key, &info[..])
                        .unwrap();

                // Test an encryption-decryption round trip
                let msg = b"paper boy paper boy";
                let aad = AssociatedData(b"all about that paper, boy");
                let mut plaintext = *msg;
                let tag = aead_ctx1.seal(&mut plaintext, aad).unwrap();
                let mut ciphertext = plaintext;
                aead_ctx2.open(&mut ciphertext, aad, &tag).unwrap();
                let roundtrip_plaintext = ciphertext;

                // Assert that the derived plaintext equals the original message
                assert_eq!(&roundtrip_plaintext, msg);
            }
        }
    }

    println!("PEAK AGILITY ACHIEVED");
}
