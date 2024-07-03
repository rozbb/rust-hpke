//! Traits and structs for key derivation functions

use crate::util::write_u16_be;

use digest::{core_api::BlockSizeUser, Digest, OutputSizeUser};
use generic_array::GenericArray;
use hmac::SimpleHmac;
use sha2::{Sha256, Sha384, Sha512};

const VERSION_LABEL: &[u8] = b"HPKE-v1";

// This is the maximum value of Nh. It is achieved by HKDF-SHA512 in RFC 9180 §7.2.
pub(crate) const MAX_DIGEST_SIZE: usize = 64;

// Pretty much all the KDF functionality is covered by the hkdf crate

/// Represents key derivation functionality
pub trait Kdf {
    /// The underlying hash function
    #[doc(hidden)]
    type HashImpl: Clone + Digest + OutputSizeUser + BlockSizeUser;

    /// The algorithm identifier for a KDF implementation
    const KDF_ID: u16;
}

// We use Kdf as a type parameter, so this is to avoid ambiguity.
use Kdf as KdfTrait;

// Convenience types for the functions below
pub(crate) type DigestArray<Kdf> =
    GenericArray<u8, <<Kdf as KdfTrait>::HashImpl as OutputSizeUser>::OutputSize>;
pub(crate) type SimpleHkdf<Kdf> =
    hkdf::Hkdf<<Kdf as KdfTrait>::HashImpl, SimpleHmac<<Kdf as KdfTrait>::HashImpl>>;
type SimpleHkdfExtract<Kdf> =
    hkdf::HkdfExtract<<Kdf as KdfTrait>::HashImpl, SimpleHmac<<Kdf as KdfTrait>::HashImpl>>;

/// The implementation of HKDF-SHA256
pub struct HkdfSha256 {}

impl KdfTrait for HkdfSha256 {
    #[doc(hidden)]
    type HashImpl = Sha256;

    // RFC 9180 §7.2: HKDF-SHA256
    const KDF_ID: u16 = 0x0001;
}

/// The implementation of HKDF-SHA384
pub struct HkdfSha384 {}

impl KdfTrait for HkdfSha384 {
    #[doc(hidden)]
    type HashImpl = Sha384;

    // RFC 9180 §7.2: HKDF-SHA384
    const KDF_ID: u16 = 0x0002;
}

/// The implementation of HKDF-SHA512
pub struct HkdfSha512 {}

impl KdfTrait for HkdfSha512 {
    #[doc(hidden)]
    type HashImpl = Sha512;

    // RFC 9180 §7.2: HKDF-SHA512
    const KDF_ID: u16 = 0x0003;
}

// RFC 9180 §4.1
// def ExtractAndExpand(dh, kem_context):
//   eae_prk = LabeledExtract("", "eae_prk", dh)
//   shared_secret = LabeledExpand(eae_prk, "shared_secret",
//                                 kem_context, Nsecret)
//   return shared_secret

/// Uses the given IKM to extract a secret, and then uses that secret, plus the given suite ID and
/// info string, to expand to the output buffer
#[doc(hidden)]
pub fn extract_and_expand<Kdf: KdfTrait>(
    ikm: &[u8],
    suite_id: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    // Extract using given IKM
    let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"eae_prk", ikm);
    // Expand using given info string
    hkdf_ctx.labeled_expand(suite_id, b"shared_secret", info, out)
}

// RFC 9180 §4
// def LabeledExtract(salt, label, ikm):
//   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
//   return Extract(salt, labeled_ikm)

/// Returns the HKDF context derived from `(salt=salt, ikm="HPKE-v1"||suite_id||label||ikm)`
#[doc(hidden)]
pub fn labeled_extract<Kdf: KdfTrait>(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (DigestArray<Kdf>, SimpleHkdf<Kdf>) {
    // Call HKDF-Extract with the IKM being the concatenation of all of the above
    let mut extract_ctx = SimpleHkdfExtract::<Kdf>::new(Some(salt));
    extract_ctx.input_ikm(VERSION_LABEL);
    extract_ctx.input_ikm(suite_id);
    extract_ctx.input_ikm(label);
    extract_ctx.input_ikm(ikm);
    extract_ctx.finalize()
}

// This trait only exists so I can implement it for hkdf::Hkdf
#[doc(hidden)]
pub trait LabeledExpand {
    /// Does a `LabeledExpand` key derivation function using HKDF. If `out.len()` is more than 255x
    /// the digest size (in bytes) of the underlying hash function, returns an
    /// `Err(hkdf::InvalidLength)`.
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength>;
}

impl<D> LabeledExpand for hkdf::Hkdf<D, SimpleHmac<D>>
where
    D: Clone + OutputSizeUser + Digest + BlockSizeUser,
{
    // RFC 9180 §4
    // def LabeledExpand(prk, label, info, L):
    //   labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
    //                         label, info)
    //   return Expand(prk, labeled_info, L)

    /// Does a `LabeledExpand` key derivation function using HKDF. If `out.len()` is more than 255x
    /// the digest size (in bytes) of the underlying hash function, returns an
    /// `Err(hkdf::InvalidLength)`.
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength> {
        // We need to write the length as a u16, so that's the de-facto upper bound on length
        if out.len() > u16::MAX as usize {
            // The error condition is met, since 2^16 is way bigger than 255 * digest_bytelen
            return Err(hkdf::InvalidLength);
        }

        // Encode the output length in the info string
        let mut len_buf = [0u8; 2];
        write_u16_be(&mut len_buf, out.len() as u16);

        // Call HKDF-Expand() with the info string set to the concatenation of all of the above
        let labeled_info = [&len_buf, VERSION_LABEL, suite_id, label, info];
        self.expand_multi_info(&labeled_info, out)
    }
}
