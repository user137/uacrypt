//! Kalyna-XTS: DSTU 7624:2014 mode of operation #9 (indexed substitution / disk-sector mode) - the
//! 10th and last official mode, closing out this crate's full DSTU 7624 mode-of-operation coverage
//! (`TASKS.md` T-96). Reuses [`super::gf2m_wide`]'s field arithmetic (same `f[]` reduction
//! polynomials as [`super::kalyna_gcm`]/[`super::kalyna_gmac`], confirmed byte-for-byte identical
//! in `dstu7624_init_xts` - no new field module needed). Cited to
//! `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_xts`/`decrypt_xts` (lines 3003-3141)
//! and `dstu7624_init_xts` (lines 4089-4132). `DECISIONS.md` D-58 has the full citation, the
//! `InvalidLength` finding below, and the oracle-coverage breakdown.
//!
//! # Confidentiality only - and that is the *correct* choice here, not a compromise
//!
//! Unlike every confidentiality-only mode elsewhere in this crate (ECB/OFB/CBC/CFB/CTR), XTS's
//! lack of built-in integrity is not a misuse trap to warn callers away from - it is the standard,
//! recognized design for disk-sector encryption, where integrity is deliberately the filesystem
//! layer's responsibility, not the cipher's (`docs/release-readiness.md`'s use-case table already
//! states this explicitly for the "full-disk encryption" row). **Do not use this for a new design
//! outside that specific case** without understanding why every other confidentiality-only mode in
//! this crate carries a stronger warning than this one does.
//!
//! # Ciphertext stealing - transcribed as found, not simplified by analogy to textbook XTS-AES
//!
//! For a buffer whose length is not a multiple of the block size, the standard IEEE P1619/NIST SP
//! 800-38E ciphertext-stealing trick applies: the last full block and the short final block are
//! encrypted out of their "natural" order and swapped, so the final block's shortfall is padded
//! with bytes borrowed from the other one instead of a padding scheme of its own. This module's
//! `k`/`r`-indexed derivation (`k = buffer.len() / block_bytes`, `r = buffer.len() % block_bytes`)
//! was re-derived by hand-tracing `encrypt_xts`/`decrypt_xts` against two different official
//! vectors (`k = 1` and `k = 2`) to confirm it generalizes, rather than assumed from the textbook
//! algorithm's shape - see D-58 for the full trace.
//!
//! # A real gap found in the reference, not ported: unchecked-length underflow
//!
//! `encrypt_xts`'s C source computes `loop_len = plain_size - block_len` using unsigned (`size_t`)
//! arithmetic, with no guard for `plain_size < block_len` - such an input underflows to a huge
//! value and the main loop would read/write far past the buffer. `decrypt_xts` has a partial guard
//! (`plain_size < 2*block_len ? 0 : ...`) but at a different threshold, and does not save the
//! encrypt side either. Matching this crate's established posture for this exact class of gap
//! (`hazmat::kalyna_kw`'s non-aligned branch, D-55; `hazmat::kalyna_cfb`'s multi-call panic,
//! resolved to a checked error, `TASKS.md` T-101), `encrypt_in_place`/`decrypt_in_place` reject
//! `buffer.len() < block_bytes` with [`XtsError::InvalidLength`] instead of inheriting the
//! underflow - XTS's own ciphertext-stealing scheme requires at least one full block by
//! construction, so this is not a scope cut relative to the construction's real domain, only a
//! guard against feeding it something the construction was never meant to accept.

use super::gf2m_wide::{Gf2m128, Gf2m256, Gf2m512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XtsError {
    InvalidLength,
}

fn xor_block(buf: &mut [u8], other: &[u8]) {
    for (b, o) in buf.iter_mut().zip(other) {
        *b ^= *o;
    }
}

macro_rules! kalyna_xts_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal, $gf:ty, $two:expr) => {
        #[doc = concat!(
            "XTS mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation, the ciphertext-stealing derivation, and the misuse note."
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

            /// Encrypts `buffer` in place under `iv` (one block, the "data unit" tweak seed).
            ///
            /// # Errors
            ///
            /// Returns [`XtsError::InvalidLength`] if `buffer.len() < ` one block - XTS's
            /// ciphertext-stealing scheme has no meaning below that length.
            pub fn encrypt_in_place(
                &self,
                iv: &[u8; $block_bytes],
                buffer: &mut [u8],
            ) -> Result<(), XtsError> {
                let n = buffer.len();
                if n < $block_bytes {
                    return Err(XtsError::InvalidLength);
                }
                let two: $gf = $two;
                let mut gamma = <$gf>::from_le_bytes(&self.key.encrypt_block(iv));

                let k = n / $block_bytes;
                let r = n % $block_bytes;

                if r == 0 {
                    let mut off = 0usize;
                    while off < n {
                        gamma = gamma.multiply(two);
                        let block = &mut buffer[off..off + $block_bytes];
                        xor_block(block, &gamma.to_le_bytes());
                        let mut tmp = [0u8; $block_bytes];
                        tmp.copy_from_slice(block);
                        let enc = self.key.encrypt_block(&tmp);
                        block.copy_from_slice(&enc);
                        xor_block(block, &gamma.to_le_bytes());
                        off += $block_bytes;
                    }
                } else {
                    // Blocks 0..k-1 get sequential tweaks 1..k, encrypted normally in place.
                    for i in 0..k {
                        gamma = gamma.multiply(two);
                        let off = i * $block_bytes;
                        let block = &mut buffer[off..off + $block_bytes];
                        xor_block(block, &gamma.to_le_bytes());
                        let mut tmp = [0u8; $block_bytes];
                        tmp.copy_from_slice(block);
                        let enc = self.key.encrypt_block(&tmp);
                        block.copy_from_slice(&enc);
                        xor_block(block, &gamma.to_le_bytes());
                    }

                    let last_off = (k - 1) * $block_bytes;
                    let tail_off = k * $block_bytes;

                    let mut scratch = [0u8; $block_bytes];
                    scratch.copy_from_slice(&buffer[last_off..last_off + $block_bytes]);

                    let mut combined = [0u8; $block_bytes];
                    combined[..r].copy_from_slice(&buffer[tail_off..tail_off + r]);
                    combined[r..].copy_from_slice(&scratch[r..]);

                    gamma = gamma.multiply(two);
                    xor_block(&mut combined, &gamma.to_le_bytes());
                    let enc = self.key.encrypt_block(&combined);
                    combined = enc;
                    xor_block(&mut combined, &gamma.to_le_bytes());

                    buffer[last_off..last_off + $block_bytes].copy_from_slice(&combined);
                    buffer[tail_off..tail_off + r].copy_from_slice(&scratch[..r]);
                }

                Ok(())
            }

            /// Decrypts `buffer` in place under `iv` - the exact inverse of [`Self::encrypt_in_place`].
            ///
            /// # Errors
            ///
            /// Returns [`XtsError::InvalidLength`] if `buffer.len() < ` one block.
            pub fn decrypt_in_place(
                &self,
                iv: &[u8; $block_bytes],
                buffer: &mut [u8],
            ) -> Result<(), XtsError> {
                let n = buffer.len();
                if n < $block_bytes {
                    return Err(XtsError::InvalidLength);
                }
                let two: $gf = $two;
                let mut gamma = <$gf>::from_le_bytes(&self.key.encrypt_block(iv));

                let k = n / $block_bytes;
                let r = n % $block_bytes;

                if r == 0 {
                    let mut off = 0usize;
                    while off < n {
                        gamma = gamma.multiply(two);
                        let block = &mut buffer[off..off + $block_bytes];
                        xor_block(block, &gamma.to_le_bytes());
                        let mut tmp = [0u8; $block_bytes];
                        tmp.copy_from_slice(block);
                        let dec = self.key.decrypt_block(&tmp);
                        block.copy_from_slice(&dec);
                        xor_block(block, &gamma.to_le_bytes());
                        off += $block_bytes;
                    }
                } else {
                    for i in 0..(k - 1) {
                        gamma = gamma.multiply(two);
                        let off = i * $block_bytes;
                        let block = &mut buffer[off..off + $block_bytes];
                        xor_block(block, &gamma.to_le_bytes());
                        let mut tmp = [0u8; $block_bytes];
                        tmp.copy_from_slice(block);
                        let dec = self.key.decrypt_block(&tmp);
                        block.copy_from_slice(&dec);
                        xor_block(block, &gamma.to_le_bytes());
                    }

                    gamma = gamma.multiply(two); // tweak_k
                    let gamma_k = gamma;
                    let gamma_k_plus_1 = gamma.multiply(two);

                    let last_off = (k - 1) * $block_bytes;
                    let tail_off = k * $block_bytes;

                    let mut combined = [0u8; $block_bytes];
                    combined.copy_from_slice(&buffer[last_off..last_off + $block_bytes]);
                    xor_block(&mut combined, &gamma_k_plus_1.to_le_bytes());
                    combined = self.key.decrypt_block(&combined);
                    xor_block(&mut combined, &gamma_k_plus_1.to_le_bytes());

                    let mut reconstructed = [0u8; $block_bytes];
                    reconstructed[..r].copy_from_slice(&buffer[tail_off..tail_off + r]);
                    reconstructed[r..].copy_from_slice(&combined[r..]);
                    xor_block(&mut reconstructed, &gamma_k.to_le_bytes());
                    reconstructed = self.key.decrypt_block(&reconstructed);
                    xor_block(&mut reconstructed, &gamma_k.to_le_bytes());

                    buffer[last_off..last_off + $block_bytes].copy_from_slice(&reconstructed);
                    buffer[tail_off..tail_off + r].copy_from_slice(&combined[..r]);
                }

                Ok(())
            }
        }
    };
}

kalyna_xts_variant!(
    Kalyna128_128Xts,
    Kalyna128_128ExpandedKey,
    16,
    16,
    Gf2m128,
    Gf2m128([2u64, 0])
);
kalyna_xts_variant!(
    Kalyna128_256Xts,
    Kalyna128_256ExpandedKey,
    32,
    16,
    Gf2m128,
    Gf2m128([2u64, 0])
);
kalyna_xts_variant!(
    Kalyna256_256Xts,
    Kalyna256_256ExpandedKey,
    32,
    32,
    Gf2m256,
    Gf2m256([2u64, 0, 0, 0])
);
kalyna_xts_variant!(
    Kalyna256_512Xts,
    Kalyna256_512ExpandedKey,
    64,
    32,
    Gf2m256,
    Gf2m256([2u64, 0, 0, 0])
);
kalyna_xts_variant!(
    Kalyna512_512Xts,
    Kalyna512_512ExpandedKey,
    64,
    64,
    Gf2m512,
    Gf2m512([2u64, 0, 0, 0, 0, 0, 0, 0])
);
