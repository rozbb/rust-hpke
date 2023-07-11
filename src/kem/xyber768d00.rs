use crate::{
    kdf::{labeled_extract, HkdfSha256, LabeledExpand},
    kem::{Kem as KemTrait, SharedSecret, X25519HkdfSha256},
    util::kem_suite_id,
    Deserializable, HpkeError, Serializable,
};

use generic_array::{sequence::Concat, typenum, GenericArray};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

impl Serializable for EncappedKey {
    type OutputSize = <typenum::U1000 as core::ops::Add<typenum::U120>>::Output;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        self.x.to_bytes().concat(*<GenericArray<
            u8,
            <typenum::U1000 as core::ops::Add<typenum::U88>>::Output,
        >>::from_slice(&self.k[..]))
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != 1120 {
            return Err(HpkeError::IncorrectInputLength(1120, encoded.len()));
        }
        let x = <<X25519HkdfSha256 as KemTrait>::EncappedKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        Ok(EncappedKey {
            x,
            k: encoded[32..].try_into().unwrap(),
        })
    }
}

impl Serializable for PublicKey {
    type OutputSize = <typenum::U1000 as core::ops::Add<typenum::U216>>::Output;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        self.x.to_bytes().concat(*<GenericArray<
            u8,
            <typenum::U1000 as core::ops::Add<typenum::U184>>::Output,
        >>::from_slice(&self.k[..]))
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != 1216 {
            return Err(HpkeError::IncorrectInputLength(1216, encoded.len()));
        }
        let x = <<X25519HkdfSha256 as KemTrait>::PublicKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        Ok(PublicKey {
            x,
            k: encoded[32..].try_into().unwrap(),
        })
    }
}

impl Serializable for PrivateKey {
    type OutputSize =
        <<typenum::U1000 as core::ops::Add<typenum::U1000>>::Output as core::ops::Add<
            typenum::U432,
        >>::Output;
    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        self.x.to_bytes().concat(*<GenericArray<
            u8,
            <<typenum::U1000 as core::ops::Add<typenum::U1000>>::Output as core::ops::Add<
                typenum::U400,
            >>::Output,
        >>::from_slice(&self.k[..]))
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != 2432 {
            return Err(HpkeError::IncorrectInputLength(2432, encoded.len()));
        }
        let x = <<X25519HkdfSha256 as KemTrait>::PrivateKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        Ok(PrivateKey {
            x,
            k: encoded[32..].try_into().unwrap(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey {
    x: <X25519HkdfSha256 as KemTrait>::PublicKey,
    #[cfg_attr(feature = "serde_impls", serde(with = "serde_big_array::BigArray"))]
    k: pqc_kyber::PublicKey,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateKey {
    x: <X25519HkdfSha256 as KemTrait>::PrivateKey,
    #[cfg_attr(feature = "serde_impls", serde(with = "serde_big_array::BigArray"))]
    k: pqc_kyber::SecretKey,
}

#[derive(Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
pub struct EncappedKey {
    x: <X25519HkdfSha256 as KemTrait>::EncappedKey,
    #[cfg_attr(feature = "serde_impls", serde(with = "serde_big_array::BigArray"))]
    k: [u8; 1088],
}

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.to_bytes().ct_eq(&other.x.to_bytes()) & self.k.ct_eq(&other.k)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for PrivateKey {}

#[doc = "Represents X25519Kyber768Draft00"]
pub struct X25519Kyber768Draft00;

impl KemTrait for X25519Kyber768Draft00 {
    #[doc(hidden)]
    type NSecret = typenum::U64;

    type EncappedKey = EncappedKey;
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    const KEM_ID: u16 = 0x30;

    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let suite_id = kem_suite_id::<Self>();
        let (_, dkp_prk) = labeled_extract::<HkdfSha256>(&[], &suite_id, b"dkp_prk", ikm);
        let mut buf = [0u8; 32 + 64];
        dkp_prk
            .labeled_expand(&suite_id, b"sk", &[], &mut buf)
            .unwrap();
        let (skx, pkx) = X25519HkdfSha256::derive_keypair(&buf[..32]);
        let kpk = pqc_kyber::derive(&buf[32..]).unwrap();
        (
            PrivateKey {
                x: skx,
                k: kpk.secret,
            },
            PublicKey {
                x: pkx,
                k: kpk.public,
            },
        )
    }

    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        PublicKey {
            x: X25519HkdfSha256::sk_to_pk(&sk.x),
            k: pqc_kyber::public(&sk.k),
        }
    }

    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        if sender_id_keypair.is_some() {
            return Err(HpkeError::AuthNotSupportedError);
        }

        let (ss1, enc1) = X25519HkdfSha256::encap(&pk_recip.x, None, csprng)?;
        let (enc2, ss2) = match pqc_kyber::encapsulate(&pk_recip.k, csprng) {
            Ok(res) => res,
            Err(_e) => return Err(HpkeError::EncapError),
        };

        let mut ss = <SharedSecret<Self> as Default>::default();
        ss.0 = ss1
            .0
            .concat(*<GenericArray<u8, typenum::U32>>::from_slice(&ss2[..]));
        Ok((ss, EncappedKey { x: enc1, k: enc2 }))
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        if pk_sender_id.is_some() {
            return Err(HpkeError::AuthNotSupportedError);
        }

        let ss1 = X25519HkdfSha256::decap(&sk_recip.x, None, &encapped_key.x)?;
        let ss2 = match pqc_kyber::decapsulate(&encapped_key.k, &sk_recip.k) {
            Ok(ss) => ss,
            Err(_e) => return Err(HpkeError::DecapError),
        };

        let mut ss = <SharedSecret<Self> as Default>::default();
        ss.0 = ss1
            .0
            .concat(*<GenericArray<u8, typenum::U32>>::from_slice(&ss2[..]));
        Ok(ss)
    }
}
