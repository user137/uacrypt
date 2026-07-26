//! Kalyna-GMAC: DSTU 7624:2014 mode of operation #7's MAC-only sibling - a single Horner-style
//! GHASH-like accumulation over one message stream (no AAD/ciphertext split, no encryption), built
//! on the same [`super::gf2m_wide`] field arithmetic [`super::kalyna_gcm`] uses. Cited to
//! `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_gmac` (lines 3572-3620) and
//! `dstu7624_init_gmac` (lines 4015-4063). `DECISIONS.md` D-57 has the full citation, the found
//! reference bug (below), and the oracle-coverage breakdown.
//!
//! # Ported from `encrypt_gmac`, not `gmac_update`/`gmac_final` - a real bug found, not assumed
//!
//! `dstu7624.c` has **two** GMAC code paths, and they disagree on multi-block input given in one
//! call. `encrypt_gmac`'s loop is a textbook Horner chain: for each padded block,
//! `B = (B XOR block) * H`. The streaming pair `gmac_update`/`gmac_final` (reachable via
//! `dstu7624_update_mac`/`dstu7624_final_mac`, what the self-test actually calls) has a stale-index
//! bug instead: `kalyna_xor(&data_buf[i], B, block_len, B)` inside the post-multiply loop reuses the
//! *current* loop index `i`, not `i + block_len` - so on a single call carrying more than one full
//! block, later blocks' bytes are never read into the accumulator at all (confirmed by hand-tracing
//! a 2-block input: block 2's content drops out of the final `B` entirely). Fed one block per
//! `update` call instead, the same streaming code *does* reduce to the correct Horner chain
//! (traced: first call leaves `B = block1*H`; second leaves `B = (block1*H XOR block2)*H`, matching
//! `encrypt_gmac` exactly) - so this is a genuine single-call bug in the streaming path, not an
//! intended alternate construction, and not something this module reproduces. This module ports
//! `encrypt_gmac`'s coherent one-shot loop; see D-57 for why none of the 5 official vectors can
//! settle this by themselves (every one is exactly one block long - `advisor()` caught this before
//! any code was written).
//!
//! # One-shot, not streaming
//!
//! Same rationale as [`super::kalyna_cmac`]: nothing in this crate consumes an incremental MAC yet,
//! and the only streaming code path available to transcribe from is the buggy one above.
//!
//! # Padding, and a length-block placement distinct from GCM's
//!
//! Non-block-aligned messages get the same `0x80`-then-zeros marker [`super::kalyna_cmac`]/
//! [`super::kalyna_kw`]/[`super::kalyna_gcm`] already use (`padding()` in the C source) - unlike
//! [`super::kalyna_kw`]'s block-aligned-only restriction, `encrypt_gmac`'s padding step is a
//! self-contained one-shot allocation with no analogous OOB risk, so this module supports arbitrary
//! lengths. The final length block holds the **padded** message bit-length (little-endian `u64`)
//! always at a fixed low-8-byte offset, with every other byte zero - **not**
//! [`super::kalyna_gcm`]'s two-value, half-block-offset-scaled layout (there is only one stream
//! here, no AAD/ciphertext split to keep separate).
//!
//! # No key separation from any encryption key
//!
//! **Do not use this for new designs without a specific, understood reason.** Same misuse warning
//! as [`super::kalyna_cmac`]: no key derivation or domain separation is provided by this API.

use subtle::ConstantTimeEq;

use super::gf2m_wide::{Gf2m128, Gf2m256, Gf2m512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmacError {
    InvalidLength,
    TagMismatch,
}

macro_rules! kalyna_gmac_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal, $gf:ty) => {
        #[doc = concat!(
            "GMAC over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation, the found reference bug, and the misuse warning."
        )]
        pub struct $name;

        impl $name {
            /// Computes the full-block-length GMAC tag of `message` under `key` - expands the key
            /// schedule fresh on every call. Prefer [`Self::mac_with_cipher`] for a caller that
            /// computes a MAC for more than one message under the same key. Callers truncate to their chosen `q`
            /// (between 8 and one full block) themselves, per the source construction - matching
            /// [`super::kalyna_gcm`]'s own tag-truncation convention.
            #[must_use]
            pub fn mac(key: &[u8; $key_bytes], message: &[u8]) -> [u8; $block_bytes] {
                let cipher = super::kalyna::$expanded::new(key);
                Self::mac_with_cipher(&cipher, message)
            }

            /// Computes the full-block-length GMAC tag of `message` using an already-expanded key
            /// schedule - the cached-schedule counterpart to [`Self::mac`]. Same rationale as
            /// [`super::kalyna_cmac`]'s own `mac_with_cipher` (`DECISIONS.md` D-76 / `TASKS.md`
            /// T-127): `mac` re-derives the full Kalyna round-key schedule on every call, an
            /// avoidable cost for any caller computing a MAC for more than one message under the same key.
            #[must_use]
            pub fn mac_with_cipher(
                cipher: &super::kalyna::$expanded,
                message: &[u8],
            ) -> [u8; $block_bytes] {
                let h_key = <$gf>::from_le_bytes(&cipher.encrypt_block(&[0u8; $block_bytes]));

                let msg_len = message.len();
                let rem = msg_len % $block_bytes;
                let padded_len = if rem == 0 {
                    msg_len
                } else {
                    msg_len + ($block_bytes - rem)
                };

                let mut acc = <$gf>::ZERO;
                let mut off = 0usize;
                while off < padded_len {
                    let end = (off + $block_bytes).min(msg_len);
                    let mut block = [0u8; $block_bytes];
                    if end > off {
                        block[..end - off].copy_from_slice(&message[off..end]);
                    }
                    if rem != 0 && msg_len >= off && msg_len < off + $block_bytes {
                        block[msg_len - off] = 0x80;
                    }
                    acc = acc.add(<$gf>::from_le_bytes(&block)).multiply(h_key);
                    off += $block_bytes;
                }

                let mut length_block = [0u8; $block_bytes];
                #[allow(clippy::cast_possible_truncation)] // realistic lengths fit u64 trivially
                let padded_len_bits = (padded_len as u64) * 8;
                length_block[..8].copy_from_slice(&padded_len_bits.to_le_bytes());

                let acc_bytes = acc.to_le_bytes();
                let mut combined = [0u8; $block_bytes];
                for i in 0..$block_bytes {
                    combined[i] = length_block[i] ^ acc_bytes[i];
                }

                cipher.encrypt_block(&combined)
            }

            /// Recomputes the GMAC tag and compares its first `tag.len()` bytes against `tag` in
            /// constant time (`subtle::ConstantTimeEq`, per `SECURITY.md`'s hard constraint on
            /// secret comparisons) - matching [`super::kalyna_gcm`]'s tag-verify discipline, and,
            /// like it, a deliberate departure from `dstu7624.c`'s own raw `memcmp` (`DECISIONS.md`
            /// D-57).
            ///
            /// # Errors
            ///
            /// Returns [`GmacError::InvalidLength`] if `tag.len()` is outside 8 bytes to one full
            /// block, or [`GmacError::TagMismatch`] if authentication fails.
            pub fn verify(
                key: &[u8; $key_bytes],
                message: &[u8],
                tag: &[u8],
            ) -> Result<(), GmacError> {
                let cipher = super::kalyna::$expanded::new(key);
                Self::verify_with_cipher(&cipher, message, tag)
            }

            /// The cached-schedule counterpart to [`Self::verify`] - see
            /// [`Self::mac_with_cipher`]'s doc comment for why this exists.
            ///
            /// # Errors
            ///
            /// Returns [`GmacError::InvalidLength`] if `tag.len()` is outside 8 bytes to one full
            /// block, or [`GmacError::TagMismatch`] if authentication fails.
            pub fn verify_with_cipher(
                cipher: &super::kalyna::$expanded,
                message: &[u8],
                tag: &[u8],
            ) -> Result<(), GmacError> {
                if !(8..=$block_bytes).contains(&tag.len()) {
                    return Err(GmacError::InvalidLength);
                }
                let expected = Self::mac_with_cipher(cipher, message);
                if bool::from(expected[..tag.len()].ct_eq(tag)) {
                    Ok(())
                } else {
                    Err(GmacError::TagMismatch)
                }
            }
        }
    };
}

kalyna_gmac_variant!(Kalyna128_128Gmac, Kalyna128_128ExpandedKey, 16, 16, Gf2m128);
kalyna_gmac_variant!(Kalyna128_256Gmac, Kalyna128_256ExpandedKey, 32, 16, Gf2m128);
kalyna_gmac_variant!(Kalyna256_256Gmac, Kalyna256_256ExpandedKey, 32, 32, Gf2m256);
kalyna_gmac_variant!(Kalyna256_512Gmac, Kalyna256_512ExpandedKey, 64, 32, Gf2m256);
kalyna_gmac_variant!(Kalyna512_512Gmac, Kalyna512_512ExpandedKey, 64, 64, Gf2m512);
