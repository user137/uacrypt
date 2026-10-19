//! Kalyna-KW-p: DSTU 7624:2014 §15.4/15.5, key wrap with padding, for a message whose length is not
//! a multiple of the block (T-253, `docs/DECISIONS.md` D-241/D-243). A block-aligned message is
//! plain KW's case (§15.1), [`super::kalyna_kw`].
//!
//! Wrap (§15.4): `M || μ_{l/2}(|M|)` - the bit length as a half-block little-endian field - then
//! annex Б.2's padding (a 1 bit, here the byte `0x80`, then zeros up to a block; Б.2 always pads,
//! a full block when the data is already aligned), then KW (§15.2), which appends the all-zero
//! checksum block. Unwrap (§15.5): KW, then Б.3 (drop the trailing zeros and the 1 bit), then the
//! last half block must equal `μ_{l/2}` of the length that remains.
//!
//! # Deviations from the reference implementations, not from the text
//!
//! UAPKI's `padding()` pads only unaligned data, so for `|M| + l/2` a multiple of the block it
//! produces a different ciphertext from §15.4 (this is the DSTU 9041 `l(p)=384` case, D-241); its
//! `decrypt_kw` strips trailing zero bytes and never checks the length field. Bouncy Castle has no
//! padded mode. This module follows the text.
//!
//! Unwrap is strict and constant-time over the recovered block: the 1 bit must be the byte `0x80`
//! (this is a byte API), the length field must be exactly `μ_{l/2}(8·L)` with its unused top bytes
//! zero, the padding must be the minimal Б.2 padding, and `L` must be a length `wrap` accepts
//! (`L > l`, not a multiple of `l`). Any failure, the KW checksum's included, is the one
//! [`KwError::ChecksumMismatch`], and `out` is zeroed: no padding oracle, one encoding per message.
//!
//! **Do not use this for new designs without a specific, understood reason** - the same raw key-wrap
//! caveat as [`super::kalyna_kw`]. No heap allocation; inputs are bounded by KW's 20-block limit.

use super::kalyna_kw::{KwError, MAX_R};
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
};

/// Checks the padded block `p` (a multiple of `block` bytes, at least two blocks) against §15.4's
/// layout without a branch on its bytes; returns whether it holds and the message length `L`.
#[allow(clippy::cast_possible_truncation)] // every length here is <= MAX_R * 64 = 1280
fn unpad(p: &[u8], block: usize, half: usize) -> (Choice, usize) {
    let total = p.len() as u64;
    let block = block as u64;
    let half = half as u64;

    // Б.3: the last nonzero byte holds the 1 bit.
    let mut marker_at = 0u64;
    let mut found = Choice::from(0);
    for (i, &b) in p.iter().enumerate() {
        let nonzero = !b.ct_eq(&0);
        marker_at = u64::conditional_select(&marker_at, &(i as u64), nonzero);
        found |= nonzero;
    }
    let mut marker = 0u8;
    for (i, &b) in p.iter().enumerate() {
        marker = u8::conditional_select(&marker, &b, (i as u64).ct_eq(&marker_at));
    }
    let len = marker_at.wrapping_sub(half);

    let mut ok = found & marker.ct_eq(&0x80);
    // L > l: the marker sits past the length field of a message longer than one block.
    ok &= marker_at.ct_gt(&(half + block));
    // L not a multiple of l (l is a power of two).
    ok &= !(len & (block - 1)).ct_eq(&0);
    // Minimal Б.2 padding: the marker is in the last block.
    ok &= marker_at.ct_gt(&(total - block - 1));

    // §15.5: the half block before the marker is μ_{l/2}(8·L), little-endian.
    let expected_field = len.wrapping_mul(8).to_le_bytes();
    for (i, &b) in p.iter().enumerate() {
        let i = i as u64;
        let in_field = !i.ct_lt(&len) & i.ct_lt(&marker_at);
        let k = i.wrapping_sub(len);
        let mut expected = 0u8;
        for (j, &e) in expected_field.iter().enumerate() {
            expected = u8::conditional_select(&expected, &e, k.ct_eq(&(j as u64)));
        }
        ok &= !in_field | b.ct_eq(&expected);
    }
    (ok, len as usize)
}

macro_rules! kalyna_kw_p_variant {
    ($name:ident, $kw:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal, $half_bytes:literal) => {
        #[doc = concat!(
            "KW-p over [`super::kalyna::", stringify!($expanded), "`] - see the module doc for the ",
            "citation, the strict unwrap and the misuse warning."
        )]
        #[derive(Debug)]
        pub struct $name;

        impl $name {
            /// The wrapped length for a `plaintext_len`-byte message, or `None` if KW-p does not
            /// take it: not longer than one block, a multiple of the block (plain KW's case), or
            /// over KW's 20-block limit once padded.
            #[must_use]
            pub const fn wrapped_len(plaintext_len: usize) -> Option<usize> {
                if plaintext_len <= $block_bytes || plaintext_len % $block_bytes == 0 {
                    return None;
                }
                let padded = (plaintext_len + $half_bytes + 1).div_ceil($block_bytes) * $block_bytes;
                if padded / $block_bytes > MAX_R {
                    return None;
                }
                Some(padded + $block_bytes)
            }

            /// Wraps `plaintext` into `out`, which must be exactly
            /// [`Self::wrapped_len`]`(plaintext.len())` long - expands the key schedule on every
            /// call; prefer [`Self::wrap_with_cipher`] to wrap more than once under one key.
            ///
            /// # Errors
            ///
            /// [`KwError::InvalidLength`] if `wrapped_len` is `None` or `out` has another length.
            pub fn wrap(
                key: &[u8; $key_bytes],
                plaintext: &[u8],
                out: &mut [u8],
            ) -> Result<(), KwError> {
                let cipher = super::kalyna::$expanded::new(key);
                Self::wrap_with_cipher(&cipher, plaintext, out)
            }

            /// [`Self::wrap`] with an already-expanded key schedule.
            ///
            /// # Errors
            ///
            /// Same cases as [`Self::wrap`].
            pub fn wrap_with_cipher(
                cipher: &super::kalyna::$expanded,
                plaintext: &[u8],
                out: &mut [u8],
            ) -> Result<(), KwError> {
                if Self::wrapped_len(plaintext.len()) != Some(out.len()) {
                    return Err(KwError::InvalidLength);
                }
                let padded_len = out.len() - $block_bytes;
                // Holds the key material being wrapped; wiped on every return path.
                let mut padded = zeroize::Zeroizing::new([0u8; MAX_R * $block_bytes]);
                padded[..plaintext.len()].copy_from_slice(plaintext);
                let bits = (plaintext.len() as u64) * 8;
                padded[plaintext.len()..plaintext.len() + 8].copy_from_slice(&bits.to_le_bytes());
                padded[plaintext.len() + $half_bytes] = 0x80;
                super::kalyna_kw::$kw::wrap_with_cipher(cipher, &padded[..padded_len], out)
            }

            /// Unwraps `ciphertext` into `out`, which must be exactly one block shorter than
            /// `ciphertext`, and returns the message length `n`: the message is `out[..n]`, the
            /// rest of `out` is zero. Expands the key schedule on every call; prefer
            /// [`Self::unwrap_with_cipher`] to unwrap more than once under one key.
            ///
            /// # Errors
            ///
            /// [`KwError::InvalidLength`] if `ciphertext` is not a whole number of blocks, is under
            /// three blocks or over KW's limit, or `out` has another length;
            /// [`KwError::ChecksumMismatch`] for any integrity failure, checksum or padding alike,
            /// with `out` zeroed.
            pub fn unwrap(
                key: &[u8; $key_bytes],
                ciphertext: &[u8],
                out: &mut [u8],
            ) -> Result<usize, KwError> {
                let cipher = super::kalyna::$expanded::new(key);
                Self::unwrap_with_cipher(&cipher, ciphertext, out)
            }

            /// [`Self::unwrap`] with an already-expanded key schedule.
            ///
            /// # Errors
            ///
            /// Same cases as [`Self::unwrap`].
            pub fn unwrap_with_cipher(
                cipher: &super::kalyna::$expanded,
                ciphertext: &[u8],
                out: &mut [u8],
            ) -> Result<usize, KwError> {
                if ciphertext.len() < 3 * $block_bytes
                    || !ciphertext.len().is_multiple_of($block_bytes)
                    || ciphertext.len() / $block_bytes - 1 > MAX_R
                    || out.len() != ciphertext.len() - $block_bytes
                {
                    return Err(KwError::InvalidLength);
                }
                let padded_len = out.len();
                let mut padded = zeroize::Zeroizing::new([0u8; MAX_R * $block_bytes]);
                if let Err(e) = super::kalyna_kw::$kw::unwrap_with_cipher(
                    cipher,
                    ciphertext,
                    &mut padded[..padded_len],
                ) {
                    out.fill(0);
                    return Err(e);
                }
                let (ok, len) = unpad(&padded[..padded_len], $block_bytes, $half_bytes);
                for (i, (o, &p)) in out.iter_mut().zip(padded[..padded_len].iter()).enumerate() {
                    *o = u8::conditional_select(&0, &p, (i as u64).ct_lt(&(len as u64)) & ok);
                }
                if bool::from(ok) {
                    Ok(len)
                } else {
                    Err(KwError::ChecksumMismatch)
                }
            }
        }
    };
}

kalyna_kw_p_variant!(
    Kalyna128_128KwP,
    Kalyna128_128Kw,
    Kalyna128_128ExpandedKey,
    16,
    16,
    8
);
kalyna_kw_p_variant!(
    Kalyna128_256KwP,
    Kalyna128_256Kw,
    Kalyna128_256ExpandedKey,
    32,
    16,
    8
);
kalyna_kw_p_variant!(
    Kalyna256_256KwP,
    Kalyna256_256Kw,
    Kalyna256_256ExpandedKey,
    32,
    32,
    16
);
kalyna_kw_p_variant!(
    Kalyna256_512KwP,
    Kalyna256_512Kw,
    Kalyna256_512ExpandedKey,
    64,
    32,
    16
);
kalyna_kw_p_variant!(
    Kalyna512_512KwP,
    Kalyna512_512Kw,
    Kalyna512_512ExpandedKey,
    64,
    64,
    32
);
