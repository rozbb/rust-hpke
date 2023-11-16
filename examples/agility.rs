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
    aead::{Aead, AeadCtxR, AeadCtxS, AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as KdfTrait},
    kem::{
        DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, Kem as KemTrait, X25519HkdfSha256,
    },
    setup_receiver, setup_sender, Deserializable, HpkeError, OpModeR, OpModeS, PskBundle,
    Serializable,
};

use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};

trait AgileAeadCtxS {
    fn seal_in_place_detached(
        &mut self,
        plaintext: &mut [u8],
        aad: &[u8],
    ) -> Result<AgileAeadTag, AgileHpkeError>;
    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AgileHpkeError>;
}

trait AgileAeadCtxR {
    fn open_in_place_detached(
        &mut self,
        ciphertext: &mut [u8],
        aad: &[u8],
        tag_bytes: &[u8],
    ) -> Result<(), AgileHpkeError>;
    fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AgileHpkeError>;
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

impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> AgileAeadCtxS for AeadCtxS<A, Kdf, Kem> {
    fn seal_in_place_detached(
        &mut self,
        plaintext: &mut [u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AgileHpkeError> {
        self.seal_in_place_detached(plaintext, aad)
            .map(|tag| tag.to_bytes().to_vec())
            .map_err(Into::into)
    }
    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AgileHpkeError> {
        self.seal(plaintext, aad).map_err(Into::into)
    }
}

impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> AgileAeadCtxR for AeadCtxR<A, Kdf, Kem> {
    fn open_in_place_detached(
        &mut self,
        ciphertext: &mut [u8],
        aad: &[u8],
        tag_bytes: &[u8],
    ) -> Result<(), AgileHpkeError> {
        let tag = AeadTag::<A>::from_bytes(tag_bytes)?;
        self.open_in_place_detached(ciphertext, aad, &tag)
            .map_err(Into::into)
    }
    fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AgileHpkeError> {
        self.open(ciphertext, aad).map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    fn to_u16(self) -> u16 {
        match self {
            AeadAlg::AesGcm128 => 0x01,
            AeadAlg::AesGcm256 => 0x02,
            AeadAlg::ChaCha20Poly1305 => 0x03,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    fn to_u16(self) -> u16 {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KemAlg {
    X25519HkdfSha256,
    X448HkdfSha512,
    DhP256HkdfSha256,
    DhP384HkdfSha384,
    DhP521HkdfSha512,
}

impl KemAlg {
    fn name(&self) -> &'static str {
        match self {
            KemAlg::DhP256HkdfSha256 => "DhP256HkdfSha256",
            KemAlg::DhP384HkdfSha384 => "DhP384HkdfSha384",
            KemAlg::DhP521HkdfSha512 => "DhP521HkdfSha512",
            KemAlg::X25519HkdfSha256 => "X25519HkdfSha256",
            KemAlg::X448HkdfSha512 => "X448HkdfSha512",
        }
    }

    fn try_from_u16(id: u16) -> Result<KemAlg, AgileHpkeError> {
        let res = match id {
            0x10 => KemAlg::DhP256HkdfSha256,
            0x11 => KemAlg::DhP384HkdfSha384,
            0x12 => KemAlg::DhP521HkdfSha512,
            0x20 => KemAlg::X25519HkdfSha256,
            0x21 => KemAlg::X448HkdfSha512,
            _ => return Err(AgileHpkeError::UnknownAlgIdent("KemAlg", id)),
        };

        Ok(res)
    }

    fn to_u16(self) -> u16 {
        match self {
            KemAlg::DhP256HkdfSha256 => 0x10,
            KemAlg::DhP384HkdfSha384 => 0x11,
            KemAlg::DhP521HkdfSha512 => 0x12,
            KemAlg::X25519HkdfSha256 => 0x20,
            KemAlg::X448HkdfSha512 => 0x21,
        }
    }

    fn kdf_alg(&self) -> KdfAlg {
        match self {
            KemAlg::X25519HkdfSha256 => KdfAlg::HkdfSha256,
            KemAlg::X448HkdfSha512 => KdfAlg::HkdfSha512,
            KemAlg::DhP256HkdfSha256 => KdfAlg::HkdfSha256,
            KemAlg::DhP384HkdfSha384 => KdfAlg::HkdfSha384,
            KemAlg::DhP521HkdfSha512 => KdfAlg::HkdfSha512,
        }
    }
}

#[derive(Clone)]
struct AgilePublicKey {
    kem_alg: KemAlg,
    pubkey_bytes: Vec<u8>,
}

impl AgilePublicKey {
    fn try_lift<Kem: KemTrait>(&self) -> Result<Kem::PublicKey, AgileHpkeError> {
        Kem::PublicKey::from_bytes(&self.pubkey_bytes).map_err(|e| e.into())
    }
}

#[derive(Clone)]
struct AgileEncappedKey {
    kem_alg: KemAlg,
    encapped_key_bytes: Vec<u8>,
}

impl AgileEncappedKey {
    fn try_lift<Kem: KemTrait>(&self) -> Result<Kem::EncappedKey, AgileHpkeError> {
        Kem::EncappedKey::from_bytes(&self.encapped_key_bytes).map_err(|e| e.into())
    }
}

#[derive(Clone)]
struct AgilePrivateKey {
    kem_alg: KemAlg,
    privkey_bytes: Vec<u8>,
}

impl AgilePrivateKey {
    fn try_lift<Kem: KemTrait>(&self) -> Result<Kem::PrivateKey, AgileHpkeError> {
        Kem::PrivateKey::from_bytes(&self.privkey_bytes).map_err(|e| e.into())
    }
}

#[derive(Clone)]
struct AgileKeypair(AgilePrivateKey, AgilePublicKey);

impl AgileKeypair {
    fn try_lift<Kem: KemTrait>(&self) -> Result<(Kem::PrivateKey, Kem::PublicKey), AgileHpkeError> {
        Ok((self.0.try_lift::<Kem>()?, self.1.try_lift::<Kem>()?))
    }

    fn validate(&self) -> Result<(), AgileHpkeError> {
        if self.0.kem_alg != self.1.kem_alg {
            Err(AgileHpkeError::AlgMismatch(
                (self.0.kem_alg.name(), "AgileKeypair::privkey"),
                (self.1.kem_alg.name(), "AgileKeypair::pubkey"),
            ))
        } else {
            Ok(())
        }
    }
}

// The leg work of agile_gen_keypair
macro_rules! do_gen_keypair {
    ($kem_ty:ty, $kem_alg:ident, $csprng:ident) => {{
        type Kem = $kem_ty;
        let kem_alg = $kem_alg;
        let csprng = $csprng;

        let (sk, pk) = Kem::gen_keypair(csprng);
        let sk = AgilePrivateKey {
            kem_alg,
            privkey_bytes: sk.to_bytes().to_vec(),
        };
        let pk = AgilePublicKey {
            kem_alg,
            pubkey_bytes: pk.to_bytes().to_vec(),
        };

        AgileKeypair(sk, pk)
    }};
}

fn agile_gen_keypair<R: CryptoRng + RngCore>(kem_alg: KemAlg, csprng: &mut R) -> AgileKeypair {
    match kem_alg {
        KemAlg::X25519HkdfSha256 => do_gen_keypair!(X25519HkdfSha256, kem_alg, csprng),
        KemAlg::DhP256HkdfSha256 => do_gen_keypair!(DhP256HkdfSha256, kem_alg, csprng),
        KemAlg::DhP384HkdfSha384 => do_gen_keypair!(DhP384HkdfSha384, kem_alg, csprng),
        KemAlg::DhP521HkdfSha512 => do_gen_keypair!(DhP521HkdfSha512, kem_alg, csprng),
        _ => unimplemented!(),
    }
}

#[derive(Clone)]
struct AgileOpModeR<'a> {
    kem_alg: KemAlg,
    op_mode_ty: AgileOpModeRTy<'a>,
}

impl<'a> AgileOpModeR<'a> {
    fn try_lift<Kem: KemTrait, Kdf: KdfTrait>(self) -> Result<OpModeR<'a, Kem>, AgileHpkeError> {
        let res = match self.op_mode_ty {
            AgileOpModeRTy::Base => OpModeR::Base,
            AgileOpModeRTy::Psk(bundle) => OpModeR::Psk(bundle.try_lift::<Kdf>()?),
            AgileOpModeRTy::Auth(pk) => OpModeR::Auth(pk.try_lift::<Kem>()?),
            AgileOpModeRTy::AuthPsk(pk, bundle) => {
                OpModeR::AuthPsk(pk.try_lift::<Kem>()?, bundle.try_lift::<Kdf>()?)
            }
        };

        Ok(res)
    }

    fn validate(&self) -> Result<(), AgileHpkeError> {
        match &self.op_mode_ty {
            AgileOpModeRTy::Auth(pk) => {
                if pk.kem_alg != self.kem_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kem_alg.name(), "AgileOpModeR::kem_alg"),
                        (
                            pk.kem_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePublicKey::kem_alg",
                        ),
                    ));
                }
            }
            AgileOpModeRTy::AuthPsk(pk, _) => {
                if pk.kem_alg != self.kem_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kem_alg.name(), "AgileOpModeR::kem_alg"),
                        (
                            pk.kem_alg.name(),
                            "AgileOpModeR::op_mode_ty::AgilePublicKey::kem_alg",
                        ),
                    ));
                }
            }
            _ => (),
        }

        Ok(())
    }
}

#[derive(Clone)]
enum AgileOpModeRTy<'a> {
    Base,
    Psk(AgilePskBundle<'a>),
    Auth(AgilePublicKey),
    AuthPsk(AgilePublicKey, AgilePskBundle<'a>),
}

#[derive(Clone)]
struct AgileOpModeS<'a> {
    kem_alg: KemAlg,
    op_mode_ty: AgileOpModeSTy<'a>,
}

impl<'a> AgileOpModeS<'a> {
    fn try_lift<Kem: KemTrait, Kdf: KdfTrait>(self) -> Result<OpModeS<'a, Kem>, AgileHpkeError> {
        let res = match self.op_mode_ty {
            AgileOpModeSTy::Base => OpModeS::Base,
            AgileOpModeSTy::Psk(bundle) => OpModeS::Psk(bundle.try_lift::<Kdf>()?),
            AgileOpModeSTy::Auth(keypair) => OpModeS::Auth(keypair.try_lift::<Kem>()?),
            AgileOpModeSTy::AuthPsk(keypair, bundle) => {
                OpModeS::AuthPsk(keypair.try_lift::<Kem>()?, bundle.try_lift::<Kdf>()?)
            }
        };

        Ok(res)
    }

    fn validate(&self) -> Result<(), AgileHpkeError> {
        match &self.op_mode_ty {
            AgileOpModeSTy::Auth(keypair) => {
                keypair.validate()?;
                if keypair.0.kem_alg != self.kem_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kem_alg.name(), "AgileOpModeS::kem_alg"),
                        (
                            keypair.0.kem_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePrivateKey::kem_alg",
                        ),
                    ));
                }
            }
            AgileOpModeSTy::AuthPsk(keypair, _) => {
                keypair.validate()?;
                if keypair.0.kem_alg != self.kem_alg {
                    return Err(AgileHpkeError::AlgMismatch(
                        (self.kem_alg.name(), "AgileOpModeS::kem_alg"),
                        (
                            keypair.0.kem_alg.name(),
                            "AgileOpModeS::op_mode_ty::AgilePrivateKey::kem_alg",
                        ),
                    ));
                }
            }
            _ => (),
        }

        Ok(())
    }
}

#[derive(Clone)]
enum AgileOpModeSTy<'a> {
    Base,
    Psk(AgilePskBundle<'a>),
    Auth(AgileKeypair),
    AuthPsk(AgileKeypair, AgilePskBundle<'a>),
}

#[derive(Clone, Copy)]
struct AgilePskBundle<'a>(PskBundle<'a>);

impl<'a> AgilePskBundle<'a> {
    fn try_lift<Kdf: KdfTrait>(self) -> Result<PskBundle<'a>, AgileHpkeError> {
        Ok(self.0)
    }
}

// This macro takes in all the supported AEADs, KDFs, and KEMs, and dispatches the given test
// vector to the test case with the appropriate types
macro_rules! hpke_dispatch {
    // Step 1: Roll up the AEAD, KDF, and KEM types into tuples. We'll unroll them later
    ($to_set:ident, $to_match:ident,
     ($( $aead_ty:ident ),*), ($( $kdf_ty:ident ),*), ($( $kem_ty:ident ),*), $rng_ty:ident,
     $callback:ident, $( $callback_args:ident ),* ) => {
        hpke_dispatch!(@tup1
            $to_set, $to_match,
            ($( $aead_ty ),*), ($( $kdf_ty ),*), ($( $kem_ty ),*), $rng_ty,
            $callback, ($( $callback_args ),*)
        )
    };

    // Step 2: Expand with respect to every AEAD
    (@tup1
     $to_set:ident, $to_match:ident,
     ($( $aead_ty:ident ),*), $kdf_tup:tt, $kem_tup:tt, $rng_ty:tt,
     $callback:ident, $callback_args:tt) => {
        $(
            hpke_dispatch!(@tup2
                $to_set, $to_match,
                $aead_ty, $kdf_tup, $kem_tup, $rng_ty,
                $callback, $callback_args
            );
        )*
    };

    // Step 3: Expand with respect to every KDF
    (@tup2
     $to_set:ident, $to_match:ident,
     $aead_ty:ident, ($( $kdf_ty:ident ),*), $kem_tup:tt, $rng_ty:tt,
     $callback:ident, $callback_args:tt) => {
        $(
            hpke_dispatch!(@tup3
                $to_set, $to_match,
                $aead_ty, $kdf_ty, $kem_tup, $rng_ty,
                $callback, $callback_args
            );
        )*
    };

    // Step 4: Expand with respect to every KEM
    (@tup3
     $to_set:ident, $to_match:ident,
     $aead_ty:ident, $kdf_ty:ident, ($( $kem_ty:ident ),*), $rng_ty:tt,
     $callback:ident, $callback_args:tt) => {
        $(
            hpke_dispatch!(@base
                $to_set, $to_match,
                $aead_ty, $kdf_ty, $kem_ty, $rng_ty,
                $callback, $callback_args
            );
        )*
    };

    // Step 5: Now that we're only dealing with 1 type of each kind, do the dispatch. If the test
    // vector matches the IDs of these types, run the test case.
    (@base
     $to_set:ident, $to_match:ident,
     $aead_ty:ident, $kdf_ty:ident, $kem_ty:ident, $rng_ty:ident,
     $callback:ident, ($( $callback_args:ident ),*)) => {
        if let (AeadAlg::$aead_ty, KemAlg::$kem_ty, KdfAlg::$kdf_ty) = $to_match
        {
            $to_set = Some($callback::<$aead_ty, $kdf_ty, $kem_ty, $rng_ty>($( $callback_args ),*));
        }
    };
}

// The leg work of agile_setup_receiver
fn do_setup_sender<A, Kdf, Kem, R>(
    mode: &AgileOpModeS,
    pk_recip: &AgilePublicKey,
    info: &[u8],
    csprng: &mut R,
) -> Result<(AgileEncappedKey, Box<dyn AgileAeadCtxS>), AgileHpkeError>
where
    A: 'static + Aead,
    Kdf: 'static + KdfTrait,
    Kem: 'static + KemTrait,
    R: CryptoRng + RngCore,
{
    let kem_alg = mode.kem_alg;
    let mode = mode.clone().try_lift::<Kem, Kdf>()?;
    let pk_recip = pk_recip.try_lift::<Kem>()?;

    let (encapped_key, aead_ctx) = setup_sender::<A, Kdf, Kem, _>(&mode, &pk_recip, info, csprng)?;
    let encapped_key = AgileEncappedKey {
        kem_alg,
        encapped_key_bytes: encapped_key.to_bytes().to_vec(),
    };

    Ok((encapped_key, Box::new(aead_ctx)))
}

fn agile_setup_sender<R: CryptoRng + RngCore>(
    aead_alg: AeadAlg,
    kdf_alg: KdfAlg,
    kem_alg: KemAlg,
    mode: &AgileOpModeS,
    pk_recip: &AgilePublicKey,
    info: &[u8],
    csprng: &mut R,
) -> Result<(AgileEncappedKey, Box<dyn AgileAeadCtxS>), AgileHpkeError> {
    // Do all the necessary validation
    mode.validate()?;
    if mode.kem_alg != pk_recip.kem_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (mode.kem_alg.name(), "mode::kem_alg"),
            (pk_recip.kem_alg.name(), "pk_recip::kem_alg"),
        ));
    }
    if kem_alg != mode.kem_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (kem_alg.name(), "kem_alg::kem_alg"),
            (mode.kem_alg.name(), "mode::kem_alg"),
        ));
    }

    // The triple we dispatch on
    let to_match = (aead_alg, kem_alg, kdf_alg);

    // This gets overwritten by the below macro call. It's None iff dispatch failed.
    let mut res: Option<Result<(AgileEncappedKey, Box<dyn AgileAeadCtxS>), AgileHpkeError>> = None;

    #[rustfmt::skip]
    hpke_dispatch!(
        res, to_match,
        (ChaCha20Poly1305, AesGcm128, AesGcm256),
        (HkdfSha256, HkdfSha384, HkdfSha512),
        (X25519HkdfSha256, DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512),
        R,
        do_setup_sender,
            mode,
            pk_recip,
            info,
            csprng
    );

    if res.is_none() {
        panic!("DHKEM({}) isn't impelmented yet!", kem_alg.name());
    }

    res.unwrap()
}

// The leg work of agile_setup_receiver. The Dummy type parameter is so that it can be used with
// the hpke_dispatch! macro. The macro expects its callback function to have 4 type parameters
fn do_setup_receiver<A, Kdf, Kem, Dummy>(
    mode: &AgileOpModeR,
    recip_keypair: &AgileKeypair,
    encapped_key: &AgileEncappedKey,
    info: &[u8],
) -> Result<Box<dyn AgileAeadCtxR>, AgileHpkeError>
where
    A: 'static + Aead,
    Kdf: 'static + KdfTrait,
    Kem: 'static + KemTrait,
{
    let mode = mode.clone().try_lift::<Kem, Kdf>()?;
    let (sk_recip, _) = recip_keypair.try_lift::<Kem>()?;
    let encapped_key = encapped_key.try_lift::<Kem>()?;

    let aead_ctx = setup_receiver::<A, Kdf, Kem>(&mode, &sk_recip, &encapped_key, info)?;
    Ok(Box::new(aead_ctx))
}

fn agile_setup_receiver(
    aead_alg: AeadAlg,
    kdf_alg: KdfAlg,
    kem_alg: KemAlg,
    mode: &AgileOpModeR,
    recip_keypair: &AgileKeypair,
    encapped_key: &AgileEncappedKey,
    info: &[u8],
) -> Result<Box<dyn AgileAeadCtxR>, AgileHpkeError> {
    // Do all the necessary validation
    recip_keypair.validate()?;
    mode.validate()?;
    if mode.kem_alg != recip_keypair.0.kem_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (mode.kem_alg.name(), "mode::kem_alg"),
            (recip_keypair.0.kem_alg.name(), "recip_keypair::kem_alg"),
        ));
    }
    if kem_alg != mode.kem_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (kem_alg.name(), "kem_alg::kem_alg"),
            (mode.kem_alg.name(), "mode::kem_alg"),
        ));
    }
    if recip_keypair.0.kem_alg != encapped_key.kem_alg {
        return Err(AgileHpkeError::AlgMismatch(
            (recip_keypair.0.kem_alg.name(), "recip_keypair::kem_alg"),
            (encapped_key.kem_alg.name(), "encapped_key::kem_alg"),
        ));
    }

    // The triple we dispatch on
    let to_match = (aead_alg, kem_alg, kdf_alg);

    // This gets overwritten by the below macro call. It's None iff dispatch failed.
    let mut res: Option<Result<Box<dyn AgileAeadCtxR>, AgileHpkeError>> = None;

    // Dummy type to give to the macro. do_setup_receiver doesn't use an RNG, so it doesn't need a
    // concrete RNG type. We give it the unit type to make it happy.
    type Unit = ();

    #[rustfmt::skip]
    hpke_dispatch!(
        res, to_match,
        (ChaCha20Poly1305, AesGcm128, AesGcm256),
        (HkdfSha256, HkdfSha384, HkdfSha512),
        (X25519HkdfSha256, DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512),
        Unit,
        do_setup_receiver,
            mode,
            recip_keypair,
            encapped_key,
            info
    );

    if res.is_none() {
        panic!("DHKEM({}) isn't impelmented yet!", kem_alg.name());
    }

    res.unwrap()
}

fn main() {
    let mut csprng = StdRng::from_entropy();

    let supported_aead_algs = &[
        AeadAlg::AesGcm128,
        AeadAlg::AesGcm256,
        AeadAlg::ChaCha20Poly1305,
    ];
    let supported_kem_algs = &[
        KemAlg::X25519HkdfSha256,
        KemAlg::DhP256HkdfSha256,
        KemAlg::DhP384HkdfSha384,
        KemAlg::DhP521HkdfSha512,
    ];
    let supported_kdf_algs = &[KdfAlg::HkdfSha256, KdfAlg::HkdfSha384, KdfAlg::HkdfSha512];

    // For every combination of supported algorithms, test an encryption-decryption round trip
    for &aead_alg in supported_aead_algs {
        for &kem_alg in supported_kem_algs {
            for &kdf_alg in supported_kdf_algs {
                let info = b"we're gonna agile him in his clavicle";

                // Make a random sender keypair and PSK bundle
                let sender_keypair = agile_gen_keypair(kem_alg, &mut csprng);
                let mut psk_bytes = vec![0u8; kdf_alg.get_digest_len()];
                let psk_id = b"preshared key attempt #5, take 2. action";
                let psk_bundle = {
                    csprng.fill_bytes(&mut psk_bytes);
                    AgilePskBundle(PskBundle {
                        psk: &psk_bytes,
                        psk_id,
                    })
                };

                // Make two agreeing OpModes (AuthPsk is the most complicated, so we're just using
                // that).
                let op_mode_s_ty = AgileOpModeSTy::AuthPsk(sender_keypair.clone(), psk_bundle);
                let op_mode_s = AgileOpModeS {
                    kem_alg,
                    op_mode_ty: op_mode_s_ty,
                };
                let op_mode_r_ty = AgileOpModeRTy::AuthPsk(sender_keypair.1, psk_bundle);
                let op_mode_r = AgileOpModeR {
                    kem_alg,
                    op_mode_ty: op_mode_r_ty,
                };

                // Set up the sender's encryption context
                let recip_keypair = agile_gen_keypair(kem_alg, &mut csprng);
                let (encapped_key, mut aead_ctx1) = agile_setup_sender(
                    aead_alg,
                    kdf_alg,
                    kem_alg,
                    &op_mode_s,
                    &recip_keypair.1,
                    &info[..],
                    &mut csprng,
                )
                .unwrap();

                // Set up the receivers's encryption context
                let mut aead_ctx2 = agile_setup_receiver(
                    aead_alg,
                    kdf_alg,
                    kem_alg,
                    &op_mode_r,
                    &recip_keypair,
                    &encapped_key,
                    &info[..],
                )
                .unwrap();

                // Test an encryption-decryption round trip
                let msg = b"paper boy paper boy";
                let aad = b"all about that paper, boy";
                let ciphertext = aead_ctx1.seal(msg, aad).unwrap();
                let roundtrip_plaintext = aead_ctx2.open(&ciphertext, aad).unwrap();

                // Assert that the derived plaintext equals the original message
                assert_eq!(&roundtrip_plaintext, msg);
            }
        }
    }

    println!("PEAK AGILITY ACHIEVED");
}
