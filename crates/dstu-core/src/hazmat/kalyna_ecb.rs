//! Kalyna-ECB: DSTU 7624:2014 mode of operation #1 ("Проста заміна" / simple substitution) -
//! each block of `buf` encrypted/decrypted independently under the same key, no chaining state at
//! all. Cited to `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_ecb`/`decrypt_ecb`
//! (lines 2899-2961) and `dstu7624_init_ecb` (lines 3920-3934) - a trivial per-block loop calling
//! the same block-cipher transform `hazmat::kalyna` already implements and dual-oracle-verifies
//! (D-13). `docs/DECISIONS.md` D-53 has the full citation and verification-approach note.
//!
//! # No integrity, and the weakest confidentiality guarantee of any mode in this crate
//!
//! **Do not use this for new designs without a specific, understood reason.** ECB leaks any
//! repeated-plaintext-block structure directly into the ciphertext (identical plaintext blocks
//! under the same key always produce identical ciphertext blocks) - this is the textbook example
//! cited across virtually every "how not to do encryption" guide (the ECB-encrypted-bitmap
//! demonstration). It provides no authentication either. Prefer
//! [`crate::crypto_secretbox`] unless you specifically need raw, unauthenticated, per-block-
//! independent encryption and understand why ECB's pattern leakage is acceptable for your use case
//! (e.g. re-encrypting already-random, block-sized, independent key material one block at a time).

/// `buf`'s length is not a multiple of the block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLength;

macro_rules! kalyna_ecb_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal) => {
        #[doc = concat!(
            "ECB mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation and the misuse warning."
        )]
        pub struct $name {
            key: super::kalyna::$expanded,
        }

        impl $name {
            #[must_use]
            pub fn new(key: &[u8; $key_bytes]) -> Self {
                Self {
                    key: super::kalyna::$expanded::new(key),
                }
            }

            /// Encrypts `buf` in place, one block at a time, independently.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidLength`] if `buf.len()` is not a multiple of the block size -
            /// this mode has no padding of its own (`encrypt_ecb`'s own `in->len % block_len`
            /// check, transcribed as found).
            pub fn encrypt_in_place(&self, buf: &mut [u8]) -> Result<(), InvalidLength> {
                if !buf.len().is_multiple_of($block_bytes) {
                    return Err(InvalidLength);
                }
                for block in buf.chunks_exact_mut($block_bytes) {
                    let mut input = [0u8; $block_bytes];
                    input.copy_from_slice(block);
                    block.copy_from_slice(&self.key.encrypt_block(&input));
                }
                Ok(())
            }

            /// Decrypts `buf` in place, one block at a time, independently.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidLength`] under the same condition as
            /// [`Self::encrypt_in_place`].
            pub fn decrypt_in_place(&self, buf: &mut [u8]) -> Result<(), InvalidLength> {
                if !buf.len().is_multiple_of($block_bytes) {
                    return Err(InvalidLength);
                }
                for block in buf.chunks_exact_mut($block_bytes) {
                    let mut input = [0u8; $block_bytes];
                    input.copy_from_slice(block);
                    block.copy_from_slice(&self.key.decrypt_block(&input));
                }
                Ok(())
            }
        }
    };
}

kalyna_ecb_variant!(Kalyna128_128Ecb, Kalyna128_128ExpandedKey, 16, 16);
kalyna_ecb_variant!(Kalyna128_256Ecb, Kalyna128_256ExpandedKey, 32, 16);
kalyna_ecb_variant!(Kalyna256_256Ecb, Kalyna256_256ExpandedKey, 32, 32);
kalyna_ecb_variant!(Kalyna256_512Ecb, Kalyna256_512ExpandedKey, 64, 32);
kalyna_ecb_variant!(Kalyna512_512Ecb, Kalyna512_512ExpandedKey, 64, 64);
