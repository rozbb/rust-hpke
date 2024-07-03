//! Traits and structs for authenticated encryption schemes

use crate::{
    kdf::{Kdf as KdfTrait, LabeledExpand, SimpleHkdf},
    kem::Kem as KemTrait,
    setup::ExporterSecret,
    util::{enforce_equal_len, enforce_outbuf_len, full_suite_id, write_u64_be, FullSuiteId},
    Deserializable, HpkeError, Serializable,
};

use core::{default::Default, marker::PhantomData};

use aead::{AeadCore as BaseAeadCore, AeadInPlace as BaseAeadInPlace, KeyInit as BaseKeyInit};
use generic_array::GenericArray;
use zeroize::Zeroize;

/// Represents authenticated encryption functionality
pub trait Aead {
    /// The underlying AEAD implementation
    #[doc(hidden)]
    type AeadImpl: BaseAeadCore + BaseAeadInPlace + BaseKeyInit + Clone + Send + Sync;

    /// The algorithm identifier for an AEAD implementation
    const AEAD_ID: u16;
}

// A nonce is a bytestring you only use for encryption once
pub(crate) struct AeadNonce<A: Aead>(
    pub(crate) GenericArray<u8, <A::AeadImpl as BaseAeadCore>::NonceSize>,
);

// We need this for ease of testing
#[cfg(test)]
impl<A: Aead> Clone for AeadNonce<A> {
    fn clone(&self) -> AeadNonce<A> {
        AeadNonce(self.0.clone())
    }
}

// We use this to get an empty buffer we can read nonce material into
impl<A: Aead> Default for AeadNonce<A> {
    fn default() -> AeadNonce<A> {
        AeadNonce(GenericArray::<u8, <A::AeadImpl as BaseAeadCore>::NonceSize>::default())
    }
}

// Zero out nonces on drop
impl<A: Aead> Drop for AeadNonce<A> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct AeadKey<A: Aead>(
    pub(crate) GenericArray<u8, <A::AeadImpl as aead::KeySizeUser>::KeySize>,
);

// We use this to get an empty buffer we can read key material into
impl<A: Aead> Default for AeadKey<A> {
    fn default() -> AeadKey<A> {
        AeadKey(GenericArray::<
            u8,
            <A::AeadImpl as aead::KeySizeUser>::KeySize,
        >::default())
    }
}

// Zero out keys on drop
impl<A: Aead> Drop for AeadKey<A> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A sequence counter. This is set to `u64` instead of the true nonce size of an AEAD for two
/// reasons:
///
/// 1. No algorithm that would appear in HPKE would require nonce sizes less than `u64`.
/// 2. It is just about physically impossible to encrypt 2^64 messages in sequence. If a computer
///    computes 1 encryption every nanosecond, it would take over 584 years to run out of nonces.
///    Notably, unlike randomized nonces, counting in sequence doesn't parallelize, so we don't
///    have to imagine amortizing this computation across multiple computers. In conclusion, 64
///    bits should be enough for anybody.
#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
struct Seq(u64);

// RFC 9180 §5.2
// def Context<ROLE>.IncrementSeq():
//   if self.seq >= (1 << (8*Nn)) - 1:
//     raise MessageLimitReachedError
//   self.seq += 1

/// Increments the sequence counter. Returns `None` on overflow.
fn increment_seq(seq: &Seq) -> Option<Seq> {
    // Try to add 1
    seq.0.checked_add(1).map(Seq)
}

// RFC 9180 §5.2
// def Context<ROLE>.ComputeNonce(seq):
//   seq_bytes = I2OSP(seq, Nn)
//   return xor(self.base_nonce, seq_bytes)

/// Derives a nonce from the base nonce and a "sequence number". The sequence number is treated as
/// a big-endian integer with length equal to the nonce length.
fn mix_nonce<A: Aead>(base_nonce: &AeadNonce<A>, seq: &Seq) -> AeadNonce<A> {
    // Write `seq` in big-endian order into a byte buffer that's the size of a nonce
    let mut seq_buf = AeadNonce::<A>::default();
    // We just write to the last seq_size bytes. This is necessary because our AEAD nonces (>= 96
    // bits) are always bigger than the sequence buffer (64 bits). We write to the last 64 bits
    // because this is a big-endian number.
    let seq_size = core::mem::size_of::<Seq>();
    let nonce_size = base_nonce.0.len();
    write_u64_be(&mut seq_buf.0[nonce_size - seq_size..], seq.0);

    // XOR the base nonce bytes with the sequence bytes
    let new_nonce_iter = base_nonce
        .0
        .iter()
        .zip(seq_buf.0.iter())
        .map(|(nonce_byte, seq_byte)| nonce_byte ^ seq_byte);

    // This cannot fail, as the length of AeadNonce<A> is precisely the length of Seq
    AeadNonce(GenericArray::from_exact_iter(new_nonce_iter).unwrap())
}

/// An authenticated encryption tag
#[derive(Clone)]
pub struct AeadTag<A: Aead>(GenericArray<u8, <A::AeadImpl as BaseAeadCore>::TagSize>);

impl<A: Aead> Default for AeadTag<A> {
    fn default() -> AeadTag<A> {
        AeadTag(GenericArray::<u8, <A::AeadImpl as BaseAeadCore>::TagSize>::default())
    }
}

impl<A: Aead> Serializable for AeadTag<A> {
    type OutputSize = <A::AeadImpl as BaseAeadCore>::TagSize;

    // Pass to underlying to_bytes() impl
    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        buf.copy_from_slice(&self.0);
    }
}

impl<A: Aead> Deserializable for AeadTag<A> {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        enforce_equal_len(Self::size(), encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = <GenericArray<u8, Self::OutputSize> as Default>::default();
        arr.copy_from_slice(encoded);
        Ok(AeadTag(arr))
    }
}

/// The HPKE encryption context. This is what you use to `seal` plaintexts and `open` ciphertexts.
pub(crate) struct AeadCtx<A: Aead, Kdf: KdfTrait, Kem: KemTrait> {
    /// Records whether the nonce sequence counter has overflowed
    overflowed: bool,
    /// The underlying AEAD instance. This also does decryption.
    encryptor: A::AeadImpl,
    /// The base nonce which we XOR with sequence numbers
    base_nonce: AeadNonce<A>,
    /// The exporter secret, used in the `export()` method
    exporter_secret: ExporterSecret<Kdf>,
    /// The running sequence number
    seq: Seq,
    /// This binds the `AeadCtx` to the KEM that made it. Used to generate `suite_id`.
    src_kem: PhantomData<Kem>,
    /// The full ID of the ciphersuite that created this `AeadCtx`. Used for context binding.
    suite_id: FullSuiteId,
}

// Necessary for test_setup_soundness
#[cfg(test)]
impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> Clone for AeadCtx<A, Kdf, Kem> {
    fn clone(&self) -> AeadCtx<A, Kdf, Kem> {
        AeadCtx {
            overflowed: self.overflowed,
            encryptor: self.encryptor.clone(),
            base_nonce: self.base_nonce.clone(),
            exporter_secret: self.exporter_secret.clone(),
            seq: self.seq.clone(),
            src_kem: PhantomData,
            suite_id: self.suite_id,
        }
    }
}

impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> AeadCtx<A, Kdf, Kem> {
    /// Makes an AeadCtx from a raw key and nonce
    pub(crate) fn new(
        key: &AeadKey<A>,
        base_nonce: AeadNonce<A>,
        exporter_secret: ExporterSecret<Kdf>,
    ) -> AeadCtx<A, Kdf, Kem> {
        let suite_id = full_suite_id::<A, Kdf, Kem>();
        AeadCtx {
            overflowed: false,
            encryptor: <A::AeadImpl as aead::KeyInit>::new(&key.0),
            base_nonce,
            exporter_secret,
            seq: <Seq as Default>::default(),
            src_kem: PhantomData,
            suite_id,
        }
    }

    // RFC 9180 §5.3
    // def Context.Export(exporter_context, L):
    //   return LabeledExpand(self.exporter_secret, "sec",
    //                        exporter_context, L)

    /// Fills a given buffer with secret bytes derived from this encryption context. This value
    /// does not depend on sequence number, so it is constant for the lifetime of this context.
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(())` on success. If the buffer length is more than 255x the digest size (in
    /// bytes) of the underlying hash function, returns an `Err(HpkeError::KdfOutputTooLong)`. Just
    /// don't use to fill massive buffers and you'll be fine.
    pub fn export(&self, exporter_ctx: &[u8], out_buf: &mut [u8]) -> Result<(), HpkeError> {
        // Use our exporter secret as the PRK for an HKDF-Expand op. The only time this fails is
        // when the length of the PRK is not the the underlying hash function's digest size. But
        // that's guaranteed by the type system, so we can unwrap().
        let hkdf_ctx = SimpleHkdf::<Kdf>::from_prk(self.exporter_secret.0.as_slice()).unwrap();

        // This call either succeeds or returns hkdf::InvalidLength (iff the buffer length is more
        // than 255x the digest size of the underlying hash function)
        hkdf_ctx
            .labeled_expand(&self.suite_id, b"sec", exporter_ctx, out_buf)
            .map_err(|_| HpkeError::KdfOutputTooLong)
    }
}

/// The HPKE receiver's context. This is what you use to `open` ciphertexts and `export` secrets.
pub struct AeadCtxR<A: Aead, Kdf: KdfTrait, Kem: KemTrait>(AeadCtx<A, Kdf, Kem>);

// AeadCtx -> AeadCtxR via wrapping
impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> From<AeadCtx<A, Kdf, Kem>> for AeadCtxR<A, Kdf, Kem> {
    fn from(ctx: AeadCtx<A, Kdf, Kem>) -> AeadCtxR<A, Kdf, Kem> {
        AeadCtxR(ctx)
    }
}

// Necessary for test_setup_soundness
#[cfg(test)]
impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> Clone for AeadCtxR<A, Kdf, Kem> {
    fn clone(&self) -> AeadCtxR<A, Kdf, Kem> {
        self.0.clone().into()
    }
}

impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> AeadCtxR<A, Kdf, Kem> {
    // RFC 9180 §5.2
    // def ContextR.Open(aad, ct):
    //   pt = Open(self.key, self.ComputeNonce(self.seq), aad, ct)
    //   if pt == OpenError:
    //     raise OpenError
    //   self.IncrementSeq()
    //   return pt

    /// Does a "detached open in place", meaning it overwrites `ciphertext` with the resulting
    /// plaintext, and takes the tag as a separate input.
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(())` on success. If this context has been used for so many encryptions that the
    /// sequence number overflowed, returns `Err(HpkeError::MessageLimitReached)`. If this happens,
    /// `ciphertext` will be unmodified. If the tag fails to validate, returns
    /// `Err(HpkeError::OpenError)`. If this happens, `ciphertext` is in an undefined state.
    pub fn open_in_place_detached(
        &mut self,
        ciphertext: &mut [u8],
        aad: &[u8],
        tag: &AeadTag<A>,
    ) -> Result<(), HpkeError> {
        if self.0.overflowed {
            // If the sequence counter overflowed, we've been used for too long. Shut down.
            Err(HpkeError::MessageLimitReached)
        } else {
            // Compute the nonce and do the encryption in place
            let nonce = mix_nonce::<A>(&self.0.base_nonce, &self.0.seq);
            let decrypt_res = self
                .0
                .encryptor
                .decrypt_in_place_detached(&nonce.0, aad, ciphertext, &tag.0);

            if decrypt_res.is_err() {
                // Opening failed due to a bad tag
                return Err(HpkeError::OpenError);
            }

            // Opening was a success. Try to increment the sequence counter. If it fails, this was
            // our last decryption.
            match increment_seq(&self.0.seq) {
                Some(new_seq) => self.0.seq = new_seq,
                None => self.0.overflowed = true,
            }

            Ok(())
        }
    }

    /// Opens the given ciphertext and returns a plaintext
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(())` on success. If this context has been used for so many encryptions that the
    /// sequence number overflowed, returns `Err(HpkeError::MessageLimitReached)`. If the tag fails
    /// to validate, returns `Err(HpkeError::OpenError)`.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<crate::Vec<u8>, HpkeError> {
        // Make sure the auth'd ciphertext is long enough to contain a tag. If it isn't, it's
        // certainly not valid.
        let tag_len = AeadTag::<A>::size();
        let msg_len = ciphertext
            .len()
            .checked_sub(tag_len)
            .ok_or(HpkeError::OpenError)?;

        // Now deconstruct the auth'd ciphertext
        let (ciphertext, tag_slice) = ciphertext.split_at(msg_len);
        let mut buf = ciphertext.to_vec();
        let tag = {
            let mut t = <AeadTag<A> as Default>::default();
            t.0.copy_from_slice(tag_slice);
            t
        };

        // Decrypt and return the decrypted buffer
        self.open_in_place_detached(&mut buf, aad, &tag)?;
        Ok(buf)
    }

    /// Fills a given buffer with secret bytes derived from this encryption context. This value
    /// does not depend on sequence number, so it is constant for the lifetime of this context.
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(())` on success. If the buffer length is more than about 255x the digest size
    /// (in bytes) of the underlying hash function, returns an `Err(HpkeError::KdfOutputTooLong)`.
    /// The exact number is given in the "Input Length Restrictions" section of the spec. Just
    /// don't use to fill massive buffers and you'll be fine.
    pub fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Result<(), HpkeError> {
        // Pass to AeadCtx
        self.0.export(info, out_buf)
    }
}

/// The HPKE senders's context. This is what you use to `seal` plaintexts and `export` secrets.
pub struct AeadCtxS<A: Aead, Kdf: KdfTrait, Kem: KemTrait>(AeadCtx<A, Kdf, Kem>);

// AeadCtx -> AeadCtxS via wrapping
impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> From<AeadCtx<A, Kdf, Kem>> for AeadCtxS<A, Kdf, Kem> {
    fn from(ctx: AeadCtx<A, Kdf, Kem>) -> AeadCtxS<A, Kdf, Kem> {
        AeadCtxS(ctx)
    }
}

// Necessary for test_setup_soundness
#[cfg(test)]
impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> Clone for AeadCtxS<A, Kdf, Kem> {
    fn clone(&self) -> AeadCtxS<A, Kdf, Kem> {
        self.0.clone().into()
    }
}

impl<A: Aead, Kdf: KdfTrait, Kem: KemTrait> AeadCtxS<A, Kdf, Kem> {
    // RFC 9180 §5.2
    // def ContextS.Seal(aad, pt):
    //   ct = Seal(self.key, self.ComputeNonce(self.seq), aad, pt)
    //   self.IncrementSeq()
    //   return ct

    /// Does a "detached seal in place", meaning it overwrites `plaintext` with the resulting
    /// ciphertext, and returns the resulting authentication tag
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(tag)` on success.  If this context has been used for so many encryptions that
    /// the sequence number overflowed, returns `Err(HpkeError::MessageLimitReached)`. If this
    /// happens, `plaintext` will be unmodified. If an error happened during encryption, returns
    /// `Err(HpkeError::SealError)`. If this happens, the contents of `plaintext` is undefined.
    pub fn seal_in_place_detached(
        &mut self,
        plaintext: &mut [u8],
        aad: &[u8],
    ) -> Result<AeadTag<A>, HpkeError> {
        if self.0.overflowed {
            // If the sequence counter overflowed, we've been used for far too long. Shut down.
            Err(HpkeError::MessageLimitReached)
        } else {
            // Compute the nonce and do the encryption in place
            let nonce = mix_nonce::<A>(&self.0.base_nonce, &self.0.seq);
            let tag = self
                .0
                .encryptor
                .encrypt_in_place_detached(&nonce.0, aad, plaintext)
                .map_err(|_| HpkeError::SealError)?;

            // Try to increment the sequence counter. If it fails, this was our last encryption.
            match increment_seq(&self.0.seq) {
                Some(new_seq) => self.0.seq = new_seq,
                None => self.0.overflowed = true,
            }

            // Return the tag
            Ok(AeadTag(tag))
        }
    }

    /// Seals the given plaintext and returns the ciphertext
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(ciphertext)` on success.  If this context has been used for so many encryptions
    /// that the sequence number overflowed, returns `Err(HpkeError::MessageLimitReached)`. If an
    /// error happened during encryption, returns `Err(HpkeError::SealError)`.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<crate::Vec<u8>, HpkeError> {
        let msg_len = plaintext.len();
        let tag_len = AeadTag::<A>::size();

        // Make a buffer that can hold a ciphertext + tag. Copy in the plaintext
        let mut buf = vec![0u8; msg_len + tag_len];
        buf[..msg_len].copy_from_slice(plaintext);

        // Seal with a detached tag
        let tag = self.seal_in_place_detached(&mut buf[..plaintext.len()], aad)?;
        // Then append the tag to the end of the buffer. The buffer is now the auth'd ciphertext
        buf[msg_len..msg_len + tag_len].copy_from_slice(&tag.0);

        Ok(buf)
    }

    /// Fills a given buffer with secret bytes derived from this encryption context. This value
    /// does not depend on sequence number, so it is constant for the lifetime of this context.
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(())` on success. If the buffer length is more than 255x the digest size (in
    /// bytes) of the underlying hash function, returns an `Err(HpkeError::KdfOutputTooLong)`. Just
    /// don't use to fill massive buffers and you'll be fine.
    pub fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Result<(), HpkeError> {
        // Pass to AeadCtx
        self.0.export(info, out_buf)
    }
}

// Export all the AEAD implementations
mod aes_gcm;
mod chacha20_poly1305;
mod export_only;
#[doc(inline)]
pub use crate::aead::{aes_gcm::*, chacha20_poly1305::*, export_only::*};

#[cfg(test)]
mod test {
    use super::{AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead, Seq};

    use crate::{
        kdf::HkdfSha256, test_util::gen_ctx_simple_pair, Deserializable, HpkeError, Serializable,
    };

    /// Tests that AeadKey::from_bytes fails on inputs of incorrect length
    macro_rules! test_invalid_nonce {
        ($test_name:ident, $aead_ty:ty) => {
            #[test]
            fn $test_name() {
                type A = $aead_ty;

                // No AEAD tag is 5 bytes long. This should give an IncorrectInputLength error
                let tag_res = AeadTag::<A>::from_bytes(&[0; 5]);
                if let Err(e) = tag_res {
                    assert_eq!(e, HpkeError::IncorrectInputLength(AeadTag::<A>::size(), 5));
                } else {
                    panic!("AeadTag was unexpectedly valid");
                }
            }
        };
    }

    /// Tests that encryption context secret export does not change behavior based on the
    /// underlying sequence number This logic is cipher-agnostic, so we don't make the test generic
    /// over ciphers.
    #[cfg(any(feature = "alloc", feature = "std"))]
    macro_rules! test_export_idempotence {
        ($test_name:ident, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;
                type Kdf = HkdfSha256;
                // Again, this test is cipher-agnostic
                type A = ChaCha20Poly1305;

                // Set up a context. Logic is algorithm-independent, so we don't care about the
                // types here
                let (mut sender_ctx, _) = gen_ctx_simple_pair::<A, Kdf, Kem>();

                // Get an initial export secret
                let mut secret1 = [0u8; 16];
                sender_ctx
                    .export(b"test_export_idempotence", &mut secret1)
                    .unwrap();

                // Modify the context by encrypting something
                let plaintext = b"back hand";
                sender_ctx.seal(plaintext, b"").expect("seal() failed");

                // Get a second export secret
                let mut secret2 = [0u8; 16];
                sender_ctx
                    .export(b"test_export_idempotence", &mut secret2)
                    .unwrap();

                assert_eq!(secret1, secret2);
            }
        };
    }

    /// Tests that anything other than `export()` called on an `ExportOnly` context results in a
    /// panic
    #[cfg(any(feature = "alloc", feature = "std"))]
    macro_rules! test_exportonly_panics {
        ($test_name1:ident, $test_name2:ident, $kem_ty:ty) => {
            #[should_panic]
            #[test]
            fn $test_name1() {
                type Kem = $kem_ty;
                type Kdf = HkdfSha256;
                type A = ExportOnlyAead;

                // Set up a context and try encrypting
                let (mut sender_ctx, _) = gen_ctx_simple_pair::<A, Kdf, Kem>();
                let plaintext = b"back hand";
                let _ = sender_ctx.seal(plaintext, b"");
            }

            #[should_panic]
            #[test]
            fn $test_name2() {
                type Kem = $kem_ty;
                type Kdf = HkdfSha256;
                type A = ExportOnlyAead;

                // Set up a context and try decrypting an invalid ciphertext
                let (_, mut receiver_ctx) = gen_ctx_simple_pair::<A, Kdf, Kem>();
                let invalid_ciphertext = vec![0u8; 60];
                let aad = b"with my prayers";
                let _ = receiver_ctx.open(&invalid_ciphertext, aad);
            }
        };
    }

    /// Tests that sequence overflowing causes an error. This logic is cipher-agnostic, so we don't
    /// make the test generic over ciphers.
    #[cfg(any(feature = "alloc", feature = "std"))]
    macro_rules! test_overflow {
        ($test_name:ident, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;
                type Kdf = HkdfSha256;
                // Again, this test is cipher-agnostic
                type A = ChaCha20Poly1305;

                // Make a sequence number that's at the max
                let big_seq = {
                    let mut seq = <Seq as Default>::default();
                    seq.0 = u64::MAX;
                    seq
                };

                let (mut sender_ctx, mut receiver_ctx) = gen_ctx_simple_pair::<A, Kdf, Kem>();
                sender_ctx.0.seq = big_seq.clone();
                receiver_ctx.0.seq = big_seq.clone();

                // These should support precisely one more encryption before it registers an
                // overflow

                let msg = b"draxx them sklounst";
                let aad = b"you have to have the kebapi";

                // Do one round trip and ensure it works
                {
                    let mut buf = msg.clone();

                    // Encrypt the plaintext
                    let ciphertext = sender_ctx.seal(&mut buf, aad).expect("seal() failed");

                    // Now to decrypt on the other side
                    let roundtrip_plaintext =
                        receiver_ctx.open(&ciphertext, aad).expect("open() failed");

                    // Make sure the output message was the same as the input message
                    assert_eq!(msg, roundtrip_plaintext.as_slice());
                }

                // Try another round trip and ensure that we've overflowed
                {
                    // Try to encrypt the plaintext
                    match sender_ctx.seal(msg, aad) {
                        Err(HpkeError::MessageLimitReached) => {
                            // Good, this should have overflowed
                        }
                        Err(e) => panic!("seal() should have overflowed. Instead got {}", e),
                        _ => panic!("seal() should have overflowed. Instead it succeeded"),
                    }

                    // Now try to decrypt something. This isn't a valid ciphertext or tag, but the
                    // overflow should fail before the tag check fails.
                    let placeholder_ciphertext = [0u8; 32];

                    match receiver_ctx.open(&placeholder_ciphertext, aad) {
                        Err(HpkeError::MessageLimitReached) => {
                            // Good, this should have overflowed
                        }
                        Err(e) => panic!("open() should have overflowed. Instead got {}", e),
                        _ => panic!("open() should have overflowed. Instead it succeeded"),
                    }
                }
            }
        };
    }

    /// Tests that `open()` can decrypt things properly encrypted with `seal()`
    #[cfg(any(feature = "alloc", feature = "std"))]
    macro_rules! test_ctx_correctness {
        ($test_name:ident, $aead_ty:ty, $kem_ty:ty) => {
            #[test]
            fn $test_name() {
                type A = $aead_ty;
                type Kdf = HkdfSha256;
                type Kem = $kem_ty;

                let (mut sender_ctx, mut receiver_ctx) = gen_ctx_simple_pair::<A, Kdf, Kem>();

                let msg = b"Love it or leave it, you better gain way";
                let aad = b"You better hit bull's eye, the kid don't play";

                // Encrypt in place with the sender context
                let ciphertext = sender_ctx.seal(msg, aad).expect("seal() failed");

                // Make sure seal() isn't a no-op
                assert_ne!(&ciphertext, msg);

                // Decrypt with the receiver context
                let decrypted = receiver_ctx.open(&ciphertext, aad).expect("open() failed");
                assert_eq!(&decrypted, msg);

                // Now try sending an invalid message followed by a valid message. The valid
                // message should decrypt correctly
                let invalid_ciphertext = [0x00; 32];
                assert!(receiver_ctx.open(&invalid_ciphertext, aad).is_err());

                // Now make sure a round trip succeeds
                let ciphertext = sender_ctx.seal(msg, aad).expect("second seal() failed");

                // Decrypt with the receiver context
                let decrypted = receiver_ctx
                    .open(&ciphertext, aad)
                    .expect("second open() failed");
                assert_eq!(&decrypted, msg);
            }
        };
    }

    test_invalid_nonce!(test_invalid_nonce_aes128, AesGcm128);
    test_invalid_nonce!(test_invalid_nonce_aes256, AesGcm128);
    test_invalid_nonce!(test_invalid_nonce_chacha, ChaCha20Poly1305);

    #[cfg(all(feature = "x25519", any(feature = "alloc", feature = "std")))]
    mod x25519_tests {
        use super::*;

        test_export_idempotence!(test_export_idempotence_x25519, crate::kem::X25519HkdfSha256);
        test_exportonly_panics!(
            test_exportonly_panics_x25519_seal,
            test_exportonly_panics_x25519_open,
            crate::kem::X25519HkdfSha256
        );
        test_overflow!(test_overflow_x25519, crate::kem::X25519HkdfSha256);

        test_ctx_correctness!(
            test_ctx_correctness_aes128_x25519,
            AesGcm128,
            crate::kem::X25519HkdfSha256
        );
        test_ctx_correctness!(
            test_ctx_correctness_aes256_x25519,
            AesGcm256,
            crate::kem::X25519HkdfSha256
        );
        test_ctx_correctness!(
            test_ctx_correctness_chacha_x25519,
            ChaCha20Poly1305,
            crate::kem::X25519HkdfSha256
        );
    }

    #[cfg(all(feature = "p256", any(feature = "alloc", feature = "std")))]
    mod p256_tests {
        use super::*;

        test_export_idempotence!(test_export_idempotence_p256, crate::kem::DhP256HkdfSha256);
        test_exportonly_panics!(
            test_exportonly_panics_p256_seal,
            test_exportonly_panics_p256_open,
            crate::kem::DhP256HkdfSha256
        );
        test_overflow!(test_overflow_p256, crate::kem::DhP256HkdfSha256);

        test_ctx_correctness!(
            test_ctx_correctness_aes128_p256,
            AesGcm128,
            crate::kem::DhP256HkdfSha256
        );
        test_ctx_correctness!(
            test_ctx_correctness_aes256_p256,
            AesGcm256,
            crate::kem::DhP256HkdfSha256
        );
        test_ctx_correctness!(
            test_ctx_correctness_chacha_p256,
            ChaCha20Poly1305,
            crate::kem::DhP256HkdfSha256
        );
    }

    #[cfg(all(feature = "p384", any(feature = "alloc", feature = "std")))]
    mod p384_tests {
        use super::*;

        test_export_idempotence!(test_export_idempotence_p384, crate::kem::DhP384HkdfSha384);
        test_exportonly_panics!(
            test_exportonly_panics_p384_seal,
            test_exportonly_panics_p384_open,
            crate::kem::DhP384HkdfSha384
        );
        test_overflow!(test_overflow_p384, crate::kem::DhP384HkdfSha384);

        test_ctx_correctness!(
            test_ctx_correctness_aes128_p384,
            AesGcm128,
            crate::kem::DhP384HkdfSha384
        );
        test_ctx_correctness!(
            test_ctx_correctness_aes256_p384,
            AesGcm256,
            crate::kem::DhP384HkdfSha384
        );
        test_ctx_correctness!(
            test_ctx_correctness_chacha_p384,
            ChaCha20Poly1305,
            crate::kem::DhP384HkdfSha384
        );
    }

    /// Tests that Serialize::write_exact() panics when given a buffer of incorrect length
    #[should_panic]
    #[test]
    fn test_write_exact() {
        // Make an AES-GCM-128 tag (16 bytes) and try to serialize it to a buffer of 17 bytes. It
        // shouldn't matter that this is sufficient room, since write_exact needs exactly the write
        // size buffer
        let tag = AeadTag::<AesGcm128>::default();
        let mut buf = [0u8; 17];
        tag.write_exact(&mut buf);
    }
}
