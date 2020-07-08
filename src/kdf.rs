use crate::{kem::Kem as KemTrait, prelude::*};

use byteorder::{BigEndian, ByteOrder};
use digest::{generic_array::GenericArray, BlockInput, Digest, FixedOutput, Reset, Update};
use sha2::{Sha256, Sha384, Sha512};

// This has a space because LabeledExtract calls for a space between the RFC string and the label
const RFC_STR: &[u8] = b"RFCXXXX ";

// Pretty much all the KDF functionality is covered by the hkdf crate

/// Represents key derivation functionality
pub trait Kdf {
    /// The underlying hash function
    #[doc(hidden)]
    type HashImpl: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone;

    /// The algorithm identifier for a KDF implementation
    #[doc(hidden)]
    const KDF_ID: u16;
}

// We use Kdf as a type parameter, so this is to avoid ambiguity.
use Kdf as KdfTrait;

/// The implementation of HKDF-SHA256
pub struct HkdfSha256 {}

impl KdfTrait for HkdfSha256 {
    #[doc(hidden)]
    type HashImpl = Sha256;

    // draft02 §8.2: HKDF-SHA256
    #[doc(hidden)]
    const KDF_ID: u16 = 0x0001;
}

/// The implementation of HKDF-SHA384
pub struct HkdfSha384 {}

impl KdfTrait for HkdfSha384 {
    #[doc(hidden)]
    type HashImpl = Sha384;

    // draft02 §8.2: HKDF-SHA384
    #[doc(hidden)]
    const KDF_ID: u16 = 0x0002;
}

/// The implementation of HKDF-SHA512
pub struct HkdfSha512 {}

impl KdfTrait for HkdfSha512 {
    #[doc(hidden)]
    type HashImpl = Sha512;

    // draft02 §8.2: HKDF-SHA512
    #[doc(hidden)]
    const KDF_ID: u16 = 0x0003;
}

// def ExtractAndExpand(dh, kemContext):
//   eae_prk = LabeledExtract(zero(0), "eae_prk", dh)
//   zz = LabeledExpand(eae_prk, "zz", kemContext, Nzz)
//   return zz
/// Uses the given IKM to extract a secret, and then uses that secret, plus the given suite ID and
/// info string, to expand to the output buffer
pub(crate) fn extract_and_expand<Kem: KemTrait>(
    ikm: &[u8],
    suite_id: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    // Construct the labels
    // Extract using given IKM
    let (_, hkdf_ctx) = labeled_extract::<Kem::Kdf>(&[], suite_id, b"eae_prk", ikm);
    // Expand using given info string
    hkdf_ctx.labeled_expand(suite_id, b"zz", info, out)
}

// def LabeledExtract(salt, label, IKM):
//   labeledIKM = concat("RFCXXXX ", suite_id, label, IKM)
//   return Extract(salt, labeledIKM)
/// Returns the HKDF context derived from `(salt=salt, ikm= "RFCXXXX "||suite_id||label||ikm)`
pub(crate) fn labeled_extract<Kdf: KdfTrait>(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (
    GenericArray<u8, <<Kdf as KdfTrait>::HashImpl as FixedOutput>::OutputSize>,
    hkdf::Hkdf<Kdf::HashImpl>,
) {
    // Concat the inputs to create a new IKM
    let labeled_ikm: Vec<u8> = [RFC_STR, suite_id, label, ikm].concat();
    // Extract and the HKDF context
    hkdf::Hkdf::<Kdf::HashImpl>::extract(Some(&salt), &labeled_ikm)
}

// This trait only exists so I can implement it for hkdf::Hkdf
pub(crate) trait LabeledExpand {
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength>;
}

impl<D: Update + BlockInput + FixedOutput + Reset + Default + Clone> LabeledExpand
    for hkdf::Hkdf<D>
{
    // def LabeledExpand(PRK, label, info, L):
    //   labeledInfo = concat(I2OSP(L, 2), "RFCXXXX ", suite_id, label, info)
    //   return Expand(PRK, labeledInfo, L)
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        label: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), hkdf::InvalidLength> {
        // We need to write the length as a u16, so that's the de-facto upper bound on length
        assert!(out.len() <= u16::MAX as usize);

        // Encode the output length in the info string
        let mut len_buf = [0u8; 2];
        BigEndian::write_u16(&mut len_buf, out.len() as u16);

        let labeled_info: Vec<u8> = [&len_buf, RFC_STR, suite_id, label, info].concat();
        self.expand(&labeled_info, out)
    }
}
