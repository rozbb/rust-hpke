use crate::{
    dhkex::{DhKeyExchange, KemSuiteId},
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
};
use generic_array::GenericArray;

#[inline(always)]
pub(self) fn nist_pxxx_derive<const LEN: usize, Kdf: KdfTrait, Kem: DhKeyExchange>(
    suite_id: &KemSuiteId,
    ikm: &[u8],
) -> (Kem::PrivateKey, Kem::PublicKey) {
    // Write the label into a byte buffer and extract from the IKM
    let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"dkp_prk", ikm);

    // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
    let mut buf =
        GenericArray::<u8, <Kem::PrivateKey as crate::Serializable>::OutputSize>::default();
    // Get the key length in bits (so that we know how many iterations we should make)
    let key_len_bits = LEN * 8;
    // Determine the info size from our key length
    let slice_range = key_len_bits / u8::MAX as usize;

    for counter in 0..key_len_bits {
        let ctr_bytes = &counter.to_le_bytes()[..slice_range];
        hkdf_ctx
            .labeled_expand(suite_id, b"candidate", ctr_bytes, &mut buf)
            .unwrap();

        // P-521 bitmask is 0x01.
        // We ignore it for other NIST curves as the bitmask is 0xFF, which is a no-op on a `u8`
        #[cfg(feature = "p521")]
        if LEN == 64 {
            buf[0] &= 0x01;
        }

        // Try to convert to a valid secret key. If the conversion succeeded, return the
        // keypair. Recall the invariant of PrivateKey: it is a value in the range [1,p).
        if let Ok(sk) = <Kem::PrivateKey as crate::Deserializable>::from_bytes(&buf) {
            let pk = Kem::sk_to_pk(&sk);
            return (sk, pk);
        }
    }

    // The code should never ever get here. The likelihood that we get 256 bad samples
    // in a row for p256 is 2^-8192.
    panic!("DeriveKeyPair failed all attempts");
}

#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "p384")]
pub mod p384;
