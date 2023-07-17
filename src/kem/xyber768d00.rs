use crate::{
    kdf::{labeled_extract, HkdfSha256, LabeledExpand},
    kem::{Kem as KemTrait, SharedSecret, X25519HkdfSha256},
    util::enforce_equal_len,
    util::kem_suite_id,
    Deserializable, HpkeError, Serializable,
};

use generic_array::{
    sequence::Concat,
    typenum::{self, Unsigned},
    GenericArray,
};
use pqc_kyber::Keypair as KyberKeypair;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

type U1120 = <typenum::U1000 as core::ops::Add<typenum::U120>>::Output;
type U1088 = <typenum::U1000 as core::ops::Add<typenum::U88>>::Output;
type U1216 = <typenum::U1000 as core::ops::Add<typenum::U216>>::Output;
type U1184 = <typenum::U1000 as core::ops::Add<typenum::U184>>::Output;
type U2432 = <<typenum::U1000 as core::ops::Add<typenum::U1000>>::Output as core::ops::Add<
    typenum::U432,
>>::Output;
type U2400 = <<typenum::U1000 as core::ops::Add<typenum::U1000>>::Output as core::ops::Add<
    typenum::U400,
>>::Output;

impl Serializable for EncappedKey {
    // X25519Kyber768Draft00 v2 §5: Nenc of X25519Kyber768Draft00 is 1120
    type OutputSize = U1120;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Output X25519 encapped key || Kyber encapped key. That's 32 bytes + 1088 bytes += 1120.
        self.x
            .to_bytes()
            .concat(*<GenericArray<u8, U1088>>::from_slice(&self.k[..]))
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Grab the X25519 encapped key then the Kyber encapped key. The unwrap() is permitted because
        // of the enforce_equal_len above.
        let x = <<X25519HkdfSha256 as KemTrait>::EncappedKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        let k = encoded[32..].try_into().unwrap();

        Ok(EncappedKey { x, k })
    }
}

impl Serializable for PublicKey {
    // X25519Kyber768Draft00 v2 §5: Npk of X25519Kyber768Draft00 is 1216
    type OutputSize = U1216;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Output X25519 pubkey || Kyber pubkey. That's 32 bytes + 1184 bytes += 1216.
        self.x
            .to_bytes()
            .concat(*<GenericArray<u8, U1184>>::from_slice(&self.k[..]))
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Grab the X25519 pubkey then the Kyber pubkey. The unwrap() is permitted because of the
        // enforce_equal_len above.
        let x = <<X25519HkdfSha256 as KemTrait>::PublicKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        let k = encoded[32..].try_into().unwrap();

        Ok(PublicKey { x, k })
    }
}

impl Serializable for PrivateKey {
    // X25519Kyber768Draft00 v2 §5: Nsk of X25519Kyber768Draft00 is 2432
    type OutputSize = U2432;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Output X25519 privkey || Kyber privkey. That's 32 bytes + 1184 bytes += 1216.
        self.x
            .to_bytes()
            .concat(*<GenericArray<u8, U2400>>::from_slice(&self.k[..]))
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Grab the X25519 privkey then the Kyber privkey. The unwrap() is permitted because of the
        // enforce_equal_len above.
        let x = <<X25519HkdfSha256 as KemTrait>::PrivateKey as Deserializable>::from_bytes(
            &encoded[..32],
        )?;
        let k = encoded[32..].try_into().unwrap();

        Ok(PrivateKey { x, k })
    }
}

/// An X25519-Kyber768 public key. This holds an X25519 public key and a Kyber768 public key.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
#[doc(hidden)]
pub struct PublicKey {
    x: <X25519HkdfSha256 as KemTrait>::PublicKey,
    #[cfg_attr(feature = "serde_impls", serde(with = "serde_big_array::BigArray"))]
    k: pqc_kyber::PublicKey,
}

/// An X25519-Kyber768 private key. This holds an X25519 private key and a Kyber768 private key.
#[derive(Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
#[doc(hidden)]
pub struct PrivateKey {
    x: <X25519HkdfSha256 as KemTrait>::PrivateKey,
    #[cfg_attr(feature = "serde_impls", serde(with = "serde_big_array::BigArray"))]
    k: pqc_kyber::SecretKey,
}

/// Holds the content of an encapsulated secret. This is what the receiver uses to derive the
/// shared secret. Since this is a hybrid KEM, it holds a DH encapped key and a Kyber encapped key.
#[derive(Clone)]
#[cfg_attr(feature = "serde_impls", derive(serde::Serialize, serde::Deserialize))]
#[doc(hidden)]
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

#[doc = "Represents X25519Kyber768Draft00 v2"]
pub struct X25519Kyber768Draft00;

impl KemTrait for X25519Kyber768Draft00 {
    // X25519Kyber768Draft00 v2 §5: Nsecret of X25519Kyber768Draft00 is 64
    #[doc(hidden)]
    type NSecret = typenum::U64;

    type EncappedKey = EncappedKey;
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    const KEM_ID: u16 = 0x30;

    // X25519Kyber768Draft00 v2 §3.3
    // def DeriveKeyPair(ikm):
    //   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
    //   seed = LabeledExpand(dkp_prk, "sk", 32 + 64)
    //   seed1 = seed[0:32]
    //   seed2 = seed[32:96]
    //   sk1, pk1 = X25519KEM.DeriveKeyPair(seed1)
    //   sk2, pk2 = Kyber768Draft00.DeriveKeyPair(seed2)
    //   return (concat(sk1, sk2), concat(pk1, pk2))

    /// Deterministically derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material should have as many bits of entropy as it extracts for its seeds,
    /// i.e., 768 bits.
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        // Hash the IKM
        let suite_id = kem_suite_id::<Self>();
        let (_, dkp_prk) = labeled_extract::<HkdfSha256>(&[], &suite_id, b"dkp_prk", ikm);

        // Expand the randomness to fill 2 seeds
        let mut buf = [0u8; 32 + 64];
        dkp_prk
            .labeled_expand(&suite_id, b"sk", &[], &mut buf)
            .unwrap();
        let (seed1, seed2) = buf.split_at(32);

        // Generate the keypairs with the two seeds
        let (skx, pkx) = X25519HkdfSha256::derive_keypair(seed1);
        let KyberKeypair {
            public: pkk,
            secret: skk,
        } = pqc_kyber::derive(seed2).unwrap();

        (PrivateKey { x: skx, k: skk }, PublicKey { x: pkx, k: pkk })
    }

    /// Converts a X25519-Kyber768 private key to a public key
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        PublicKey {
            x: X25519HkdfSha256::sk_to_pk(&sk.x),
            k: pqc_kyber::public(&sk.k),
        }
    }

    // X25519Kyber768Draft00 v2 §3.4
    //
    // def Encap(pkR):
    //   (pkA, pkB) = pkR
    //   (ss1, enc1) = X25519KEM.Encap(pkA)
    //   (ss2, enc2) = Kyber768Draft00.Encap(pkB)
    //   return (
    //     concat(ss1, ss2),
    //     concat(enc1, enc2)
    //   )

    /// Does an X25519-Kyber768 encapsulation. This does not support sender authentication.
    /// `sender_id_keypair` must be `None`. Otherwise, this returns
    /// [`HpkeError::AuthnotSupportedError`].
    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        // Kyber doesn't support sender authentication
        if sender_id_keypair.is_some() {
            return Err(HpkeError::AuthNotSupportedError);
        }

        // Encap using both KEMs
        let (ss1, enc1) = X25519HkdfSha256::encap(&pk_recip.x, None, csprng)?;
        let (enc2, ss2) =
            pqc_kyber::encapsulate(&pk_recip.k, csprng).map_err(|_| HpkeError::EncapError)?;

        // Compute X25519 shared secret || Kyber shared secret. The unwrap() is OK because ss1.0
        // and ss2 are fixed-size arrays.
        let mut ss = <SharedSecret<Self> as Default>::default();
        ss.0 = ss1.0.concat(ss2.try_into().unwrap());
        Ok((ss, EncappedKey { x: enc1, k: enc2 }))
    }

    // X25519Kyber768Draft00 v2 §3.4
    // def Decap(enc, skR):
    //   (skA, skB) = skR
    //   enc1 = enc[0:32]
    //   enc2 = enc[32:1120]
    //   ss1 = DHKEM.Decap(enc1, skA)
    //   ss2 = Kyber768Draft00.Decap(enc2, skB)
    //   return concat(ss1, ss2)

    /// Does an X25519-Kyber768 decapsulation. This does not support sender authentication.
    /// `pk_sender_id` must be `None`. Otherwise, this returns
    /// [`HpkeError::AuthnotSupportedError`].
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        // Kyber doesn't support sender authentication
        if pk_sender_id.is_some() {
            return Err(HpkeError::AuthNotSupportedError);
        }

        // Decapsulate with both KEMs
        let ss1 = X25519HkdfSha256::decap(&sk_recip.x, None, &encapped_key.x)?;
        let ss2 = pqc_kyber::decapsulate(&encapped_key.k, &sk_recip.k)
            .map_err(|_| HpkeError::DecapError)?;

        // Compute X25519 shared secret || Kyber shared secret. The unwrap() is OK because ss1.0
        // and ss2 are fixed-size arrays.
        let mut ss = <SharedSecret<Self> as Default>::default();
        ss.0 = ss1.0.concat(ss2.try_into().unwrap());
        Ok(ss)
    }
}
