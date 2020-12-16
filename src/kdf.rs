use crate::kem::Kem as KemTrait;

use byteorder::{BigEndian, ByteOrder};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use generic_array::GenericArray;
use sha2::{Sha256, Sha384, Sha512};

const RFC_STR: &[u8] = b"HPKE-07";

// This is currently the maximum value of Nh. It is achieved by HKDF-SHA512.
pub(crate) const MAX_DIGEST_SIZE: usize = 512;

// Pretty much all the KDF functionality is covered by the hkdf crate

/// Represents key derivation functionality
pub trait Kdf {
    /// The underlying hash function
    #[doc(hidden)]
    type HashImpl: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone;

    /// The algorithm identifier for a KDF implementation
    const KDF_ID: u16;
}

// We use Kdf as a type parameter, so this is to avoid ambiguity.
use Kdf as KdfTrait;

/// The implementation of HKDF-SHA256
pub struct HkdfSha256 {}

// The KDF_ID constant below come from §7.2

impl KdfTrait for HkdfSha256 {
    #[doc(hidden)]
    type HashImpl = Sha256;

    const KDF_ID: u16 = 0x0001;
}

/// The implementation of HKDF-SHA384
pub struct HkdfSha384 {}

impl KdfTrait for HkdfSha384 {
    #[doc(hidden)]
    type HashImpl = Sha384;

    const KDF_ID: u16 = 0x0002;
}

/// The implementation of HKDF-SHA512
pub struct HkdfSha512 {}

impl KdfTrait for HkdfSha512 {
    #[doc(hidden)]
    type HashImpl = Sha512;

    const KDF_ID: u16 = 0x0003;
}

// def ExtractAndExpand(dh, kemContext):
//   eae_prk = LabeledExtract(zero(0), "eae_prk", dh)
//   shared_secret = LabeledExpand(eae_prk, "shared_secret", kemContext, Nsecret)
//   return shared_secret
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
    hkdf_ctx.labeled_expand(suite_id, b"shared_secret", info, out)
}

// def LabeledExtract(salt, label, ikm):
//   labeled_ikm = concat("HPKE-05 ", suite_id, label, ikm)
//   return Extract(salt, labeled_ikm)
/// Returns the HKDF context derived from `(salt=salt, ikm="HPKE-05 "||suite_id||label||ikm)`
pub(crate) fn labeled_extract<Kdf: KdfTrait>(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (
    GenericArray<u8, <<Kdf as KdfTrait>::HashImpl as FixedOutput>::OutputSize>,
    hkdf::Hkdf<Kdf::HashImpl>,
) {
    // Call HKDF-Extract with the IKM being the concatenation of all of the above
    let mut extract_ctx = hkdf::HkdfExtract::<Kdf::HashImpl>::new(Some(&salt));
    extract_ctx.input_ikm(RFC_STR);
    extract_ctx.input_ikm(suite_id);
    extract_ctx.input_ikm(label);
    extract_ctx.input_ikm(ikm);
    extract_ctx.finalize()
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
    // def LabeledExpand(prk, label, info, L):
    //   labeled_info = concat(I2OSP(L, 2), "HPKE-05 ", suite_id, label, info)
    //   return Expand(prk, labeled_info, L)
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

        // Call HKDF-Expand() with the info string set to the concatenation of all of the above
        let labeled_info = [&len_buf, RFC_STR, suite_id, label, info];
        self.expand_multi_info(&labeled_info, out)
    }
}
