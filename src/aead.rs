use crate::{kdf::Kdf, setup::ExporterSecret, HpkeError};
use aead::{Aead as BaseAead, NewAead as BaseNewAead};
use core::u8;

use digest::generic_array::GenericArray;
use hkdf::Hkdf;

/// Represents authenticated encryption functionality
pub trait Aead {
    /// The underlying AEAD implementation
    type AeadImpl: BaseAead + BaseNewAead;

    /// The algorithm identifier for an AEAD implementation
    const AEAD_ID: u16;
}

/// The implementation of AES-GCM-128
pub struct AesGcm128 {}

impl Aead for AesGcm128 {
    type AeadImpl = aes_gcm::Aes128Gcm;

    // draft02 §7.3: AES-GCM-128
    const AEAD_ID: u16 = 0x0001;
}

/// The implementation of AES-GCM-128
pub struct AesGcm256 {}

impl Aead for AesGcm256 {
    type AeadImpl = aes_gcm::Aes256Gcm;

    // draft02 §7.3: AES-GCM-256
    const AEAD_ID: u16 = 0x0002;
}

/// The implementation of ChaCha20-Poly1305
pub struct ChaCha20Poly1305 {}

impl Aead for ChaCha20Poly1305 {
    type AeadImpl = chacha20poly1305::ChaCha20Poly1305;

    // draft02 §7.3: ChaCha20Poly1305
    const AEAD_ID: u16 = 0x0003;
}

/// Treats the given seq (which is a bytestring) as a big-endian integer, and increments it
///
/// Return Value
/// ============
/// Returns Ok(()) if successful. Returns Err(()) if an overflow occured.
fn increment_seq<A: Aead>(arr: &mut Seq<A>) -> Result<(), ()> {
    let arr = arr.0.as_mut_slice();
    for byte in arr.iter_mut().rev() {
        if *byte < u8::MAX {
            // If the byte is below the max, increment it
            *byte += 1;
            return Ok(());
        } else {
            // Otherwise, it's at the max, and we'll have to increment a more significant byte. In
            // that case, clear this byte.
            *byte = 0;
        }
    }

    // If we got to the end and never incremented a byte, this array was maxed out
    Err(())
}

// From draft02 §5.2
//     def Context.Nonce(seq):
//       encSeq = encode_big_endian(seq, len(self.nonce))
//       return xor(self.nonce, encSeq)
/// Derives a nonce from the given nonce and a "sequence number". The sequence number is treated as
/// a big-endian integer with length equal to the nonce length.
fn mix_nonce<A: Aead>(base_nonce: &AeadNonce<A>, seq: &Seq<A>) -> AeadNonce<A> {
    // `seq` is already a byte string in big-endian order, so no conversion is necessary.

    // XOR the base nonce bytes with the sequence bytes
    let new_nonce_iter = base_nonce
        .iter()
        .zip(seq.0.iter())
        .map(|(nonce_byte, seq_byte)| nonce_byte ^ seq_byte);

    // This cannot fail, as the length of Nonce<A> is precisely the length of Seq<A>
    GenericArray::from_exact_iter(new_nonce_iter).unwrap()
}

// A nonce is the same thing as a sequence counter. But you never increment a nonce.
pub(crate) type AeadNonce<A> = GenericArray<u8, <<A as Aead>::AeadImpl as BaseAead>::NonceSize>;
pub(crate) type AeadKey<A> = GenericArray<u8, <<A as Aead>::AeadImpl as aead::NewAead>::KeySize>;

struct Seq<A: Aead>(AeadNonce<A>);

/// The default sequence counter is all zeros
impl<A: Aead> Default for Seq<A> {
    fn default() -> Seq<A> {
        Seq(<AeadNonce<A> as Default>::default())
    }
}

/// A convenience type for authenticated encryption tags
pub type Tag<A> = GenericArray<u8, <<A as Aead>::AeadImpl as BaseAead>::TagSize>;

/// The HPKE encryption context. This is what you use to `seal` plaintexts and `open` ciphertexts.
pub struct AeadCtx<A: Aead, K: Kdf> {
    /// Records whether the nonce sequence counter has overflowed
    overflowed: bool,
    /// The underlying AEAD instance. This also does decryption.
    encryptor: A::AeadImpl,
    /// The base nonce which we XOR with sequence numbers
    nonce: AeadNonce<A>,
    /// The exporter secret, used in the `export()` method
    exporter_secret: ExporterSecret<K>,
    /// The running sequence number
    seq: Seq<A>,
}

/// Associated data for encryption. This is wrapped in order to distinguish it from the `plaintext`
/// input to `seal()` and `ciphertext` input to `open()`. Relying on argument order for two
/// bytestrings is asking for trouble.
pub struct AssociatedData<'a>(pub &'a [u8]);

// These are the methods defined for Context in draft02 §5.2.
impl<A: Aead, K: Kdf> AeadCtx<A, K> {
    /// Makes an AeadCtx from a raw key and nonce
    pub(crate) fn new(
        key: AeadKey<A>,
        nonce: AeadNonce<A>,
        exporter_secret: ExporterSecret<K>,
    ) -> AeadCtx<A, K> {
        AeadCtx {
            overflowed: false,
            encryptor: <A::AeadImpl as aead::NewAead>::new(key),
            nonce: nonce,
            exporter_secret: exporter_secret,
            seq: <Seq<A> as Default>::default(),
        }
    }
    // def Context.Seal(aad, pt):
    //   ct = Seal(self.key, self.Nonce(self.seq), aad, pt)
    //   self.IncrementSeq()
    //   return ct
    /// Does a "detached seal in place", meaning it overwrites `plaintext` with the resulting
    /// ciphertext, and returns the resulting authentication tag
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(tag)` on success.  If this context has been used for so many encryptions that
    /// the sequence number overflowed, returns `Err(Hpkeerror::SeqOverflow)`. If this happens,
    /// `plaintext` will be unmodified. If an unspecified error happened during encryption, returns
    /// `Err(HpkeError::Encryption)`. If this happens, the contents of `plaintext` is undefined.
    pub fn seal<'a>(
        &mut self,
        plaintext: &mut [u8],
        aad: &AssociatedData<'a>,
    ) -> Result<Tag<A>, HpkeError> {
        if self.overflowed {
            // If the sequence counter overflowed, we've been used for far too long. Shut down.
            Err(HpkeError::SeqOverflow)
        } else {
            // Compute the nonce and do the encryption in place
            let nonce = mix_nonce(&self.nonce, &self.seq);
            let tag_res = self
                .encryptor
                .encrypt_in_place_detached(&nonce, &aad.0, plaintext);

            // Check if an error occurred when encrypting
            let tag = match tag_res {
                Err(_) => return Err(HpkeError::Encryption),
                Ok(t) => t,
            };

            // Try to increment the sequence counter. If it fails, this was our last encryption.
            if increment_seq(&mut self.seq).is_err() {
                self.overflowed = true;
            }

            // Return the tag
            Ok(tag)
        }
    }

    // def Context.Open(aad, ct):
    //   pt = Open(self.key, self.Nonce(self.seq), aad, ct)
    //   if pt == OpenError:
    //     return OpenError
    //   self.IncrementSeq()
    //   return pt
    /// Does a "detached open in place", meaning it overwrites `ciphertext` with the resulting
    /// plaintext, and takes the tag as a separate input.
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(())` on success.  If this context has been used for so many encryptions that
    /// the sequence number overflowed, returns `Err(HpkeError::SeqOverflow)`. If this happens,
    /// `plaintext` will be unmodified. If the tag fails to validate, returns
    /// `Err(HpkeError::InvalidTag)`. If this happens, `plaintext` is in an undefined state.
    pub fn open<'a>(
        &mut self,
        ciphertext: &mut [u8],
        aad: &AssociatedData<'a>,
        tag: &Tag<A>,
    ) -> Result<(), HpkeError> {
        if self.overflowed {
            // If the sequence counter overflowed, we've been used for far too long. Shut down.
            Err(HpkeError::SeqOverflow)
        } else {
            // Compute the nonce and do the encryption in place
            let nonce = mix_nonce(&self.nonce, &self.seq);
            let decrypt_res = self
                .encryptor
                .decrypt_in_place_detached(&nonce, &aad.0, ciphertext, tag);

            if decrypt_res.is_err() {
                // Opening failed due to a bad tag
                return Err(HpkeError::InvalidTag);
            }

            // Opening was a success
            // Try to increment the sequence counter. If it fails, this was our last
            // decryption.
            if increment_seq(&mut self.seq).is_err() {
                self.overflowed = true;
            }

            Ok(())
        }
    }

    // def Context.Export(exporter_context, L):
    //     return Expand(self.exporter_secret, exporter_context, L)
    /// Fills a given buffer with secret bytes derived from this encryption context. This value
    /// does not depend on sequence number, so it is constant for the lifetime of this context.
    ///
    /// Return Value
    /// ============
    /// Returns `Ok(())` on success. If the buffer length is more than 255x the digest size of the
    /// underlying hash function, returns an `Err(InvalidLength)`.
    pub fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Result<(), hkdf::InvalidLength> {
        // Use our exporter secret as the PRK for an HKDF-Expand op. The only time this fails is
        // when the length of the PRK is not the the underlying hash function's digest size. But
        // that's guaranteed by the type system, so we can unwrap().
        let hkdf_ctx = Hkdf::<K::HashImpl>::from_prk(self.exporter_secret.as_slice()).unwrap();

        hkdf_ctx.expand(info, out_buf)
    }
}

#[cfg(test)]
mod test {
    use super::{Aead, AesGcm128, AesGcm256, AssociatedData, ChaCha20Poly1305, Seq, Tag};
    use crate::kdf::HkdfSha256;
    use crate::test_util::gen_ctx_simple_pair;

    use core::u8;

    // Necessary for test_overflow
    impl<A: Aead> Clone for Seq<A> {
        fn clone(&self) -> Seq<A> {
            Seq(self.0.clone())
        }
    }

    /// Tests that encryption context secret export does not change behavior based on the
    /// underlying sequence number
    #[test]
    fn test_export_idempotence() {
        // Set up a context. Logic is algorithm-independent, so we don't care about the types here
        let (mut aead_ctx, _) = gen_ctx_simple_pair::<ChaCha20Poly1305, HkdfSha256>();

        // Get an initial export secret
        let mut secret1 = [0u8; 16];
        aead_ctx
            .export(b"test_export_idempotence", &mut secret1)
            .unwrap();

        // Modify the context by encrypting something
        let mut plaintext = *b"back hand";
        aead_ctx
            .seal(&mut plaintext[..], &AssociatedData(b""))
            .expect("seal() failed");

        // Get a second export secret
        let mut secret2 = [0u8; 16];
        aead_ctx
            .export(b"test_export_idempotence", &mut secret2)
            .unwrap();

        assert_eq!(secret1, secret2);
    }

    /// Tests that sequence overflowing causes an error. This logic is cipher-agnostic, so we don't
    /// bother making this a macro
    #[test]
    fn test_overflow() {
        // Make a sequence number that's at the max
        let big_seq = {
            let mut buf = <Seq<ChaCha20Poly1305> as Default>::default();
            // Set all the values to the max
            for byte in buf.0.iter_mut() {
                *byte = u8::MAX;
            }
            buf
        };

        let (mut aead_ctx1, mut aead_ctx2) = gen_ctx_simple_pair::<ChaCha20Poly1305, HkdfSha256>();
        aead_ctx1.seq = big_seq.clone();
        aead_ctx2.seq = big_seq.clone();

        // These should support precisely one more encryption before it registers an overflow

        let msg = b"draxx them sklounst";
        let aad = AssociatedData(b"with my prayers");

        // Do one round trip and ensure it works
        {
            let mut plaintext = *msg;
            // Encrypt the plaintext
            let tag = aead_ctx1
                .seal(&mut plaintext[..], &aad)
                .expect("seal() failed");
            // Rename for clarity
            let mut ciphertext = plaintext;

            // Now to decrypt on the other side
            aead_ctx2
                .open(&mut ciphertext[..], &aad, &tag)
                .expect("open() failed");
            // Rename for clarity
            let roundtrip_plaintext = ciphertext;

            // Make sure the output message was the same as the input message
            assert_eq!(msg, &roundtrip_plaintext);
        }

        // Try another round trip and ensure that we've overflowed
        {
            let mut plaintext = *msg;
            // Try to encrypt the plaintext
            aead_ctx1
                .seal(&mut plaintext[..], &aad)
                .expect_err("seal() succeeded");
            // Rename for clarity
            let mut ciphertext = plaintext;

            // Now try to decrypt the ciphertext. This isn't a valid ciphertext, but the overflow
            // should fail before the tag check fails.
            let dummy_tag = <Tag<ChaCha20Poly1305> as Default>::default();
            aead_ctx2
                .open(&mut ciphertext[..], &aad, &dummy_tag)
                .expect_err("open() succeeded");
        }
    }

    /// Tests that `open()` can decrypt things properly encrypted with `seal()`
    macro_rules! test_correctness {
        ($test_name:ident, $aead_ty:ty, $kdf_ty:ty) => {
            #[test]
            fn $test_name() {
                let (mut ctx1, mut ctx2) = gen_ctx_simple_pair::<$aead_ty, $kdf_ty>();

                let msg = b"Love it or leave it, you better gain way";
                let aad = AssociatedData(b"You better hit bull's eye, the kid don't play");

                // Encrypt with the first context
                let mut ciphertext = msg.clone();
                let tag = ctx1.seal(&mut ciphertext[..], &aad).expect("seal() failed");

                // Make sure seal() isn't a no-op
                assert!(&ciphertext[..] != &msg[..]);

                // Decrypt with the second context
                ctx2.open(&mut ciphertext[..], &aad, &tag)
                    .expect("open() failed");
                // Change name for clarity
                let decrypted = ciphertext;
                assert_eq!(&decrypted[..], &msg[..]);
            }
        };
    }

    test_correctness!(test_aes128_correctness, AesGcm128, HkdfSha256);
    test_correctness!(test_aes256_correctness, AesGcm256, HkdfSha256);
    test_correctness!(test_chacha_correctness, ChaCha20Poly1305, HkdfSha256);
}
