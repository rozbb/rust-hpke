#![allow(dead_code)]
//! Here's the gist of this file: Instead of doing things at the type level, you can use zero-sized
//! types and runtime validity checks to do all of HPKE. This file is a rough idea of how one would
//! go about implementing that. There isn't too much repetition. The main part where you have to
//! get clever is in `agile_setup_*`, where you have to have a match statement with up to 3·3·5 =
//! 45 branches for all the different AEAD-KEM-KDF combinations. Practically speaking, though,
//! that's not a big number, so writing that out and using a macro for the actual work (e.g.,
//! `do_setup_sender!`) seems to be the way to go.
//!
//! The other point of this file is to demonstrate how messy crypto agility makes things. Many
//! people have different needs when it comes to agility, so I implore you **DO NOT COPY THIS FILE
//! BLINDLY**. Think about what you actually need, make that instead, and make sure to write lots
//! of runtime checks.

use hpke::{
    aead::{Aead, AeadCtx, AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as KdfTrait},
    kem::{DhP256HkdfSha256, Kem as KemTrait, X25519HkdfSha256},
    kex::{DhP256, KeyExchange, Marshallable, Unmarshallable, X25519},
    op_mode::{Psk, PskBundle},
    setup_receiver, setup_sender, EncappedKey, HpkeError, OpModeR, OpModeS,
};

use rand::{CryptoRng, RngCore};

// In your head, just replace "agile" with "dangerous" :)

trait AgileAeadCtx {
    fn seal(&mut self, plaintext: &mut [u8], aad: &[u8]) -> Result<AgileAeadTag, HpkeError>;

    fn open(
        &mut self,
        ciphertext: &mut [u8],
        aad: &[u8],
        tag_bytes: &[u8],
    ) -> Result<(), AgileHpkeError>;
}

type AgileAeadTag = Vec<u8>;

#[derive(Debug)]
enum AgileHpkeError {
    /// When you don't give an algorithm an array of the length it wants. Error is of the form
    /// `((alg1, alg1_location) , (alg2, alg2_location))`.
    AlgMismatch((&'static str, &'static str), (&'static str, &'static str)),
    /// When you get an algorithm identifier you don't recognize. Error is of the form
    /// `(alg, given_id)`.
    UnknownAlgIdent(&'static str, u16),
    /// Represents an error in the `hpke` crate
    HpkeError(HpkeError),
}

// This just wraps the HpkeError
impl From<HpkeError> for AgileHpkeError {
    fn from(e: HpkeError) -> AgileHpkeError {
        AgileHpkeError::HpkeError(e)
    }
}

impl<A: Aead, Kdf: KdfTrait> AgileAeadCtx for AeadCtx<A, Kdf> {
    fn seal(&mut self, plaintext: &mut [u8], aad: &[u8]) -> Result<Vec<u8>, HpkeError> {
        self.seal(plaintext, aad).map(|tag| tag.marshal().to_vec())
    }

    fn open(
        &mut self,
        ciphertext: &mut [u8],
        aad: &[u8],
        tag_bytes: &[u8],
    ) -> Result<(), AgileHpkeError> {
        let tag = AeadTag::<A>::unmarshal(tag_bytes)?;
        self.open(ciphertext, aad, &tag).map_err(|e| e.into())
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
enum KexAlg {
    X25519,
    X448,
    DhP256,
    DhP384,
    DhP521,
}

impl KexAlg {
    fn name(&self) -> &'static str {
        match self {
            KexAlg::X25519 => "X25519",
            KexAlg::X448 => "X448",
            KexAlg::DhP256 => "P256",
            KexAlg::DhP384 => "P384",
            KexAlg::DhP521 => "P521",
        }
    }

    fn get_pubkey_len(&self) -> usize {
        match self {
            KexAlg::X25519 => 32,
            KexAlg::X448 => 56,
            KexAlg::DhP256 => 65,
            KexAlg::DhP384 => 97,
            KexAlg::DhP521 => 133,
        }
    }
}

struct KemAlg {
    kex_alg: KexAlg,
    kdf_alg: KdfAlg,
}

impl KemAlg {
    fn try_from_u16(id: u16) -> Result<KemAlg, AgileHpkeError> {
        let res = match id {
            0x10 => KemAlg {
                kex_alg: KexAlg::DhP256,
                kdf_alg: KdfAlg::HkdfSha256,
            },
            0x11 => KemAlg {
                kex_alg: KexAlg::DhP384,
                kdf_alg: KdfAlg::HkdfSha384,
            },
            0x12 => KemAlg {
                kex_alg: KexAlg::DhP521,
                kdf_alg: KdfAlg::HkdfSha512,
            },
            0x20 => KemAlg {
                kex_alg: KexAlg::X25519,
                kdf_alg: KdfAlg::HkdfSha256,
            },
            0x21 => KemAlg {
                kex_alg: KexAlg::X448,
                kdf_alg: KdfAlg::HkdfSha512,
            },
            _ => return Err(AgileHpkeError::UnknownAlgIdent("KemAlg", id)),
        };

        Ok(res)
    }

    fn to_u16(&self) -> u16 {
        match self.kex_alg {
            KexAlg::DhP256 => 0x10,
            KexAlg::DhP384 => 0x11,
            KexAlg::DhP521 => 0x12,
            KexAlg::X25519 => 0x20,
            KexAlg::X448 => 0x21,
        }
    }
}

#[derive(Clone)]
struct AgilePublicKey {
    kex_alg: KexAlg,
    pubkey_bytes: Vec<u8>,
}

impl AgilePublicKey {
    fn try_lift<Kex: KeyExchange>(self) -> Result<Kex::PublicKey, AgileHpkeError> {
        Kex::PublicKey::unmarshal(&self.pubkey_bytes).map_err(|e| e.into())
    }
}

#[derive(Clone)]
struct AgileEncappedKey {
    kex_alg: KexAlg,
    encapped_key_bytes: Vec<u8>,
}

impl AgileEncappedKey {
    fn try_lift<Kex: KeyExchange>(self) -> Result<EncappedKey<Kex>, AgileHpkeError> {
        EncappedKey::<Kex>::unmarshal(&self.encapped_key_bytes).map_err(|e| e.into())
    }
}

#[derive(Clone)]
struct AgilePrivateKey {
    kex_alg: KexAlg,
    privkey_bytes: Vec<u8>,
}

impl AgilePrivateKey {
    fn try_lift<Kex: KeyExchange>(self) -> Result<Kex::PrivateKey, AgileHpkeError> {
        Kex::PrivateKey::unmarshal(&self.privkey_bytes).map_err(|e| e.into())
    }
}

#[derive(Clone)]
struct AgileKeypair(AgilePrivateKey, AgilePublicKey);

impl AgileKeypair {
    fn try_lift<Kex: KeyExchange>(
        self,
    ) -> Result<(Kex::PrivateKey, Kex::PublicKey), AgileHpkeError> {
        Ok((self.0.try_lift::<Kex>()?, self.1.try_lift::<Kex>()?))
    }

    fn validate(&self) -> Result<(), AgileHpkeError> {
        if self.0.kex_alg != self.1.kex_alg {
            Err(AgileHpkeError::AlgMismatch(
                (self.0.kex_alg.name(), "AgileKeypair::privkey"),
                (self.1.kex_alg.name(), "AgileKeypair::pubkey"),
            ))
        } else {
            Ok(())
        }
    }
}

// The leg work of agile_gen_keypair
macro_rules! do_gen_keypair {
    ($kex_ty:ty, $kex_alg:ident, $csprng:ident) => {{
        type Kex = $kex_ty;
        let kex_alg = $kex_alg;
        let csprng = $csprng;

        let (sk, pk) = Kex::gen_keypair(csprng);
        let sk = AgilePrivateKey {
            kex_alg: kex_alg,
            privkey_bytes: sk.marshal().to_vec(),
        };
        let pk = AgilePublicKey {
            kex_alg: kex_alg,
            pubkey_bytes: pk.marshal().to_vec(),
        };

        AgileKeypair(sk, pk)
    }};
}

fn agile_gen_keypair<R: CryptoRng + RngCore>(kex_alg: KexAlg, csprng: &mut R) -> AgileKeypair {
    match kex_alg {
        KexAlg::X25519 => do_gen_keypair!(X25519, kex_alg, csprng),
        KexAlg::DhP256 => do_gen_keypair!(DhP256, kex_alg, csprng),
        _ => unimplemented!(),
    }
}

#[derive(Clone)]
struct AgileOpModeR {
    kex_alg: KexAlg,
    kdf_alg: KdfAlg,
    op_mode_ty: AgileOpModeRTy,
}

impl AgileOpModeR {
    fn try_lift<Kex: KeyExchange, Kdf: KdfTrait>(
        self,
    ) -> Result<OpModeR<Kex, Kdf>, AgileHpkeError> {
        let res = match self.op_mode_ty {
            AgileOpModeRTy::Base => OpModeR::Base,
            AgileOpModeRTy::Psk(bundle) => OpModeR::Psk(bundle.try_lift::<Kdf>()?),
            AgileOpModeRTy::Auth(pk) => OpModeR::Auth(pk.try_lift::<Kex>()?),
            AgileOpModeRTy::AuthPsk(pk, bundle) => {
                OpModeR::AuthPsk(pk.try_lift::<Kex>()?, bundle.try_lift::<Kdf>()?)
            }
        };

        Ok(res)
    }

    fn validate(&self) -> Result<(), AgileHpkeError> {
        match &self.op_mode_ty {
            AgileOpModeRTy::Base => (),
            AgileOpModeRTy::Psk(bundle) => {
                if bundle.kex_alg != self.kex_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kex_alg.name(), "AgileOpModeR::kex_alg"),
                        (
                            bundle.kex_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePskBundle::kex_alg",
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
                if pk.kex_alg != self.kex_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kex_alg.name(), "AgileOpModeR::kex_alg"),
                        (
                            pk.kex_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePublicKey::kex_alg",
                        ),
                    ));
                }
            }
            AgileOpModeRTy::AuthPsk(pk, bundle) => {
                if bundle.kex_alg != self.kex_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kex_alg.name(), "AgileOpModeR::kex_alg"),
                        (
                            bundle.kex_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePskBundle::kex_alg",
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
                } else if pk.kex_alg != self.kex_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kex_alg.name(), "AgileOpModeR::kex_alg"),
                        (
                            pk.kex_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePublicKey::kex_alg",
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
    kex_alg: KexAlg,
    kdf_alg: KdfAlg,
    op_mode_ty: AgileOpModeSTy,
}

impl AgileOpModeS {
    fn try_lift<Kex: KeyExchange, Kdf: KdfTrait>(
        self,
    ) -> Result<OpModeS<Kex, Kdf>, AgileHpkeError> {
        let res = match self.op_mode_ty {
            AgileOpModeSTy::Base => OpModeS::Base,
            AgileOpModeSTy::Psk(bundle) => OpModeS::Psk(bundle.try_lift::<Kdf>()?),
            AgileOpModeSTy::Auth(keypair) => OpModeS::Auth(keypair.try_lift::<Kex>()?),
            AgileOpModeSTy::AuthPsk(keypair, bundle) => {
                OpModeS::AuthPsk(keypair.try_lift::<Kex>()?, bundle.try_lift::<Kdf>()?)
            }
        };

        Ok(res)
    }

    fn validate(&self) -> Result<(), AgileHpkeError> {
        match &self.op_mode_ty {
            AgileOpModeSTy::Base => (),
            AgileOpModeSTy::Psk(bundle) => {
                if bundle.kex_alg != self.kex_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kex_alg.name(), "AgileOpModeS::kex_alg"),
                        (
                            bundle.kex_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePskBundle::kex_alg",
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
            AgileOpModeSTy::Auth(keypair) => {
                keypair.validate()?;
                if keypair.0.kex_alg != self.kex_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kex_alg.name(), "AgileOpModeS::kex_alg"),
                        (
                            keypair.0.kex_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePrivateKey::kex_alg",
                        ),
                    ));
                }
            }
            AgileOpModeSTy::AuthPsk(keypair, bundle) => {
                keypair.validate()?;
                if bundle.kex_alg != self.kex_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kex_alg.name(), "AgileOpModeS::kex_alg"),
                        (
                            bundle.kex_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePskBundle::kex_alg",
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
                } else if keypair.0.kex_alg != self.kex_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kex_alg.name(), "AgileOpModeS::kex_alg"),
                        (
                            keypair.0.kex_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePrivateKey::kex_alg",
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
    Auth(AgileKeypair),
    AuthPsk(AgileKeypair, AgilePskBundle),
}

#[derive(Clone)]
struct AgilePskBundle {
    kex_alg: KexAlg,
    kdf_alg: KdfAlg,
    psk_bytes: Vec<u8>,
    psk_id: Vec<u8>,
}

impl AgilePskBundle {
    fn try_lift<Kdf: KdfTrait>(self) -> Result<PskBundle<Kdf>, AgileHpkeError> {
        let psk = Psk::<Kdf>::from_bytes(self.psk_bytes);

        Ok(PskBundle {
            psk,
            psk_id: self.psk_id,
        })
    }
}

// The leg work of agile_setup_sender
macro_rules! do_setup_sender {
    ($aead_ty:ty, $kdf_ty:ty, $kem_ty:ty, $mode:ident, $pk_recip:ident, $info:ident, $csprng:ident) => {{
        type A = $aead_ty;
        type Kdf = $kdf_ty;
        type Kem = $kem_ty;
        type Kex = <Kem as KemTrait>::Kex;

        let kex_alg = $mode.kex_alg;
        let mode = $mode.clone().try_lift::<Kex, Kdf>()?;
        let pk_recip = $pk_recip.clone().try_lift::<Kex>()?;
        let info = $info;
        let csprng = $csprng;

        let (encapped_key, aead_ctx) =
            setup_sender::<A, _, Kem, _>(&mode, &pk_recip, info, csprng)?;
        let encapped_key = AgileEncappedKey {
            kex_alg: kex_alg,
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
    if mode.kex_alg != pk_recip.kex_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (mode.kex_alg.name(), "mode::kex_alg"),
            (pk_recip.kex_alg.name(), "pk_recip::kex_alg"),
        ));
    }

    // In a complete implementation, this would have 45 branches
    match (aead_alg, mode.kex_alg, mode.kdf_alg) {
        (AeadAlg::ChaCha20Poly1305, KexAlg::X25519, KdfAlg::HkdfSha256) => do_setup_sender!(
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::X25519, KdfAlg::HkdfSha384) => do_setup_sender!(
            ChaCha20Poly1305,
            HkdfSha384,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::X25519, KdfAlg::HkdfSha512) => do_setup_sender!(
            ChaCha20Poly1305,
            HkdfSha512,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm128, KexAlg::X25519, KdfAlg::HkdfSha256) => do_setup_sender!(
            AesGcm128,
            HkdfSha256,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm128, KexAlg::X25519, KdfAlg::HkdfSha384) => do_setup_sender!(
            AesGcm128,
            HkdfSha384,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm128, KexAlg::X25519, KdfAlg::HkdfSha512) => do_setup_sender!(
            AesGcm128,
            HkdfSha512,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm256, KexAlg::X25519, KdfAlg::HkdfSha256) => do_setup_sender!(
            AesGcm256,
            HkdfSha256,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm256, KexAlg::X25519, KdfAlg::HkdfSha384) => do_setup_sender!(
            AesGcm256,
            HkdfSha384,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm256, KexAlg::X25519, KdfAlg::HkdfSha512) => do_setup_sender!(
            AesGcm256,
            HkdfSha512,
            X25519HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::DhP256, KdfAlg::HkdfSha256) => do_setup_sender!(
            ChaCha20Poly1305,
            HkdfSha256,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::DhP256, KdfAlg::HkdfSha384) => do_setup_sender!(
            ChaCha20Poly1305,
            HkdfSha384,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::DhP256, KdfAlg::HkdfSha512) => do_setup_sender!(
            ChaCha20Poly1305,
            HkdfSha512,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm128, KexAlg::DhP256, KdfAlg::HkdfSha256) => do_setup_sender!(
            AesGcm128,
            HkdfSha256,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm128, KexAlg::DhP256, KdfAlg::HkdfSha384) => do_setup_sender!(
            AesGcm128,
            HkdfSha384,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm128, KexAlg::DhP256, KdfAlg::HkdfSha512) => do_setup_sender!(
            AesGcm128,
            HkdfSha512,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm256, KexAlg::DhP256, KdfAlg::HkdfSha256) => do_setup_sender!(
            AesGcm256,
            HkdfSha256,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm256, KexAlg::DhP256, KdfAlg::HkdfSha384) => do_setup_sender!(
            AesGcm256,
            HkdfSha384,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        (AeadAlg::AesGcm256, KexAlg::DhP256, KdfAlg::HkdfSha512) => do_setup_sender!(
            AesGcm256,
            HkdfSha512,
            DhP256HkdfSha256,
            mode,
            pk_recip,
            info,
            csprng
        ),
        _ => unimplemented!(),
    }
}

// The leg work of agile_setup_receiver
macro_rules! do_setup_receiver {
    ($aead_ty:ty, $kdf_ty:ty, $kem_ty:ty, $mode:ident, $recip_keypair:ident, $encapped_key:ident, $info:ident) => {{
        type A = $aead_ty;
        type Kdf = $kdf_ty;
        type Kem = $kem_ty;
        type Kex = <Kem as KemTrait>::Kex;

        let mode = $mode.clone().try_lift::<Kex, Kdf>()?;
        let (sk_recip, _) = $recip_keypair.clone().try_lift::<Kex>()?;
        let encapped_key = $encapped_key.clone().try_lift::<Kex>()?;
        let info = $info;

        let aead_ctx = setup_receiver::<A, _, Kem>(&mode, &sk_recip, &encapped_key, info)?;
        Ok(Box::new(aead_ctx))
    }};
}

fn agile_setup_receiver(
    aead_alg: AeadAlg,
    mode: &AgileOpModeR,
    recip_keypair: &AgileKeypair,
    encapped_key: &AgileEncappedKey,
    info: &[u8],
) -> Result<Box<dyn AgileAeadCtx>, AgileHpkeError> {
    // Do all the necessary validation
    recip_keypair.validate()?;
    mode.validate()?;
    if mode.kex_alg != recip_keypair.0.kex_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (mode.kex_alg.name(), "mode::kex_alg"),
            (recip_keypair.0.kex_alg.name(), "recip_keypair::kex_alg"),
        ));
    }
    if recip_keypair.0.kex_alg != encapped_key.kex_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (recip_keypair.0.kex_alg.name(), "recip_keypair::kex_alg"),
            (encapped_key.kex_alg.name(), "encapped_key::kex_alg"),
        ));
    }

    // In a complete implementation, this would have 45 branches
    match (aead_alg, mode.kex_alg, mode.kdf_alg) {
        (AeadAlg::ChaCha20Poly1305, KexAlg::X25519, KdfAlg::HkdfSha256) => do_setup_receiver!(
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::X25519, KdfAlg::HkdfSha384) => do_setup_receiver!(
            ChaCha20Poly1305,
            HkdfSha384,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::X25519, KdfAlg::HkdfSha512) => do_setup_receiver!(
            ChaCha20Poly1305,
            HkdfSha512,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm128, KexAlg::X25519, KdfAlg::HkdfSha256) => do_setup_receiver!(
            AesGcm128,
            HkdfSha256,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm128, KexAlg::X25519, KdfAlg::HkdfSha384) => do_setup_receiver!(
            AesGcm128,
            HkdfSha384,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm128, KexAlg::X25519, KdfAlg::HkdfSha512) => do_setup_receiver!(
            AesGcm128,
            HkdfSha512,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm256, KexAlg::X25519, KdfAlg::HkdfSha256) => do_setup_receiver!(
            AesGcm256,
            HkdfSha256,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm256, KexAlg::X25519, KdfAlg::HkdfSha384) => do_setup_receiver!(
            AesGcm256,
            HkdfSha384,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm256, KexAlg::X25519, KdfAlg::HkdfSha512) => do_setup_receiver!(
            AesGcm256,
            HkdfSha512,
            X25519HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::DhP256, KdfAlg::HkdfSha256) => do_setup_receiver!(
            ChaCha20Poly1305,
            HkdfSha256,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::DhP256, KdfAlg::HkdfSha384) => do_setup_receiver!(
            ChaCha20Poly1305,
            HkdfSha384,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::ChaCha20Poly1305, KexAlg::DhP256, KdfAlg::HkdfSha512) => do_setup_receiver!(
            ChaCha20Poly1305,
            HkdfSha512,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm128, KexAlg::DhP256, KdfAlg::HkdfSha256) => do_setup_receiver!(
            AesGcm128,
            HkdfSha256,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm128, KexAlg::DhP256, KdfAlg::HkdfSha384) => do_setup_receiver!(
            AesGcm128,
            HkdfSha384,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm128, KexAlg::DhP256, KdfAlg::HkdfSha512) => do_setup_receiver!(
            AesGcm128,
            HkdfSha512,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm256, KexAlg::DhP256, KdfAlg::HkdfSha256) => do_setup_receiver!(
            AesGcm256,
            HkdfSha256,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm256, KexAlg::DhP256, KdfAlg::HkdfSha384) => do_setup_receiver!(
            AesGcm256,
            HkdfSha384,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
            encapped_key,
            info
        ),
        (AeadAlg::AesGcm256, KexAlg::DhP256, KdfAlg::HkdfSha512) => do_setup_receiver!(
            AesGcm256,
            HkdfSha512,
            DhP256HkdfSha256,
            mode,
            recip_keypair,
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
    let supported_kex_algs = &[KexAlg::X25519, KexAlg::DhP256];
    let supported_kdf_algs = &[KdfAlg::HkdfSha256, KdfAlg::HkdfSha384, KdfAlg::HkdfSha512];

    // For every combination of supported algorithms, test an encryption-decryption round trip
    for &aead_alg in supported_aead_algs {
        for &kex_alg in supported_kex_algs {
            for &kdf_alg in supported_kdf_algs {
                let info = b"we're gonna agile him in his clavicle";

                // Make a random sender keypair and PSK bundle
                let sender_keypair = agile_gen_keypair(kex_alg, &mut csprng);
                let psk_bundle = {
                    let mut psk_bytes = vec![0u8; kdf_alg.get_digest_len()];
                    let psk_id = b"preshared key attempt #5, take 2".to_vec();
                    csprng.fill_bytes(&mut psk_bytes);
                    AgilePskBundle {
                        kex_alg,
                        kdf_alg,
                        psk_bytes,
                        psk_id,
                    }
                };

                // Make two agreeing OpModes (AuthPsk is the most complicated, so we're just using
                // that).
                let op_mode_s_ty =
                    AgileOpModeSTy::AuthPsk(sender_keypair.clone(), psk_bundle.clone());
                let op_mode_s = AgileOpModeS {
                    kex_alg: kex_alg,
                    kdf_alg: kdf_alg,
                    op_mode_ty: op_mode_s_ty,
                };
                let op_mode_r_ty = AgileOpModeRTy::AuthPsk(sender_keypair.1, psk_bundle.clone());
                let op_mode_r = AgileOpModeR {
                    kex_alg: kex_alg,
                    kdf_alg: kdf_alg,
                    op_mode_ty: op_mode_r_ty,
                };

                // Set up the sender's encryption context
                let recip_keypair = agile_gen_keypair(kex_alg, &mut csprng);
                let (encapped_key, mut aead_ctx1) = agile_setup_sender(
                    aead_alg,
                    &op_mode_s,
                    &recip_keypair.1,
                    &info[..],
                    &mut csprng,
                )
                .unwrap();

                // Set up the receivers's encryption context
                let mut aead_ctx2 = agile_setup_receiver(
                    aead_alg,
                    &op_mode_r,
                    &recip_keypair,
                    &encapped_key,
                    &info[..],
                )
                .unwrap();

                // Test an encryption-decryption round trip
                let msg = b"paper boy paper boy";
                let aad = b"all about that paper, boy";
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
