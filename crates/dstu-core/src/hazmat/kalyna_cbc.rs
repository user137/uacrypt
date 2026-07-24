//! Kalyna-CBC: DSTU 7624:2014 mode of operation #5 ("Зчеплення шифроблоків" / cipher block
//! chaining) - `C_i = E_K(P_i XOR C_{i-1})`, `C_0 = IV`. Cited to
//! `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_cbc`/`decrypt_cbc` (lines 3145-3184,
//! ~3886-3918) and `dstu7624_init_cbc` (lines 3936-3953). `DECISIONS.md` D-53 has the full
//! citation and roadmap context.
//!
//! # No integrity, and no padding of its own
//!
//! **Do not use this for new designs without a specific, understood reason.** Like every raw mode
//! in this crate, CBC provides no authentication - and it is additionally vulnerable to padding-
//! oracle attacks in any protocol that decrypts CBC ciphertext and reveals *whether* padding was
//! valid (the exact failure class behind POODLE/Lucky13, part of why TLS 1.3 dropped CBC entirely).
//! This module does not implement any padding scheme itself - callers must supply block-aligned
//! input (matching `encrypt_cbc`'s own `in->len % block_len` check, transcribed as found); the
//! official self-test vectors used to verify this module apply ISO/IEC 7816-4 padding themselves
//! before calling encrypt, and that padding step is *not* part of what this module does. Prefer
//! [`crate::crypto_secretbox`] unless you specifically need raw, unauthenticated CBC and understand
//! these tradeoffs.
//!
//! # Stateful across calls, like [`super::kalyna_ofb`]
//!
//! The chaining register carries over between calls, so an `IV`-initialized instance can encrypt
//! one logical block-aligned message across multiple [`Kalyna128_128Cbc::encrypt_in_place`] calls,
//! each individually block-aligned - verified by a chunk-invariance test in `tests/kalyna_cbc.rs`.

/// `buf`'s length is not a multiple of the block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLength;

macro_rules! kalyna_cbc_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal) => {
        #[doc = concat!(
            "CBC mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation and the misuse warning."
        )]
        pub struct $name {
            key: super::kalyna::$expanded,
            gamma: [u8; $block_bytes],
        }

        impl $name {
            #[must_use]
            pub fn new(key: &[u8; $key_bytes], iv: &[u8; $block_bytes]) -> Self {
                Self {
                    key: super::kalyna::$expanded::new(key),
                    gamma: *iv,
                }
            }

            /// Encrypts `buf` in place, chaining each block against the previous ciphertext
            /// block (or `iv` for the first block since construction).
            ///
            /// # Errors
            ///
            /// Returns [`InvalidLength`] if `buf.len()` is not a multiple of the block size -
            /// this mode has no padding of its own (see the module doc comment).
            pub fn encrypt_in_place(&mut self, buf: &mut [u8]) -> Result<(), InvalidLength> {
                if !buf.len().is_multiple_of($block_bytes) {
                    return Err(InvalidLength);
                }
                for block in buf.chunks_exact_mut($block_bytes) {
                    for (g, b) in self.gamma.iter_mut().zip(block.iter()) {
                        *g ^= *b;
                    }
                    self.gamma = self.key.encrypt_block(&self.gamma);
                    block.copy_from_slice(&self.gamma);
                }
                Ok(())
            }

            /// Decrypts `buf` in place, chaining each block against the previous *ciphertext*
            /// block (or `iv` for the first block since construction) - note this is the
            /// ciphertext read from `buf` itself, not the plaintext being produced.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidLength`] under the same condition as
            /// [`Self::encrypt_in_place`].
            pub fn decrypt_in_place(&mut self, buf: &mut [u8]) -> Result<(), InvalidLength> {
                if !buf.len().is_multiple_of($block_bytes) {
                    return Err(InvalidLength);
                }
                for block in buf.chunks_exact_mut($block_bytes) {
                    let mut ciphertext_block = [0u8; $block_bytes];
                    ciphertext_block.copy_from_slice(block);
                    let decrypted = self.key.decrypt_block(&ciphertext_block);
                    for (b, (d, g)) in block
                        .iter_mut()
                        .zip(decrypted.iter().zip(self.gamma.iter()))
                    {
                        *b = *d ^ *g;
                    }
                    self.gamma = ciphertext_block;
                }
                Ok(())
            }
        }
    };
}

kalyna_cbc_variant!(Kalyna128_128Cbc, Kalyna128_128ExpandedKey, 16, 16);
kalyna_cbc_variant!(Kalyna128_256Cbc, Kalyna128_256ExpandedKey, 32, 16);
kalyna_cbc_variant!(Kalyna256_256Cbc, Kalyna256_256ExpandedKey, 32, 32);
kalyna_cbc_variant!(Kalyna256_512Cbc, Kalyna256_512ExpandedKey, 64, 32);
kalyna_cbc_variant!(Kalyna512_512Cbc, Kalyna512_512ExpandedKey, 64, 64);
