//! Kalyna-KW: DSTU 7624:2014 mode of operation #10 (key wrap) - a half-block Feistel-like network
//! over `B` (one half-block accumulator) and a shifting queue of the remaining half-blocks, plus
//! one appended all-zero "checksum" block. Cited to
//! `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_kw` (lines 3672-3755), `decrypt_kw`
//! (lines 3812-3884), and `dstu7624_init_kw` (lines 3955-3969), cross-read against
//! `oracles/bouncycastle-java/.../engines/DSTU7624WrapEngine.java` and
//! `oracles/bouncycastle-dotnet/.../engines/Dstu7624WrapEngine.cs`. `docs/DECISIONS.md` D-55 has the
//! full citation and two deliberate deviations from `dstu7624.c`, summarized here:
//!
//! # Deviation 1: block-aligned input only, no padding branch
//!
//! `dstu7624.c`'s `encrypt_kw` supports non-block-aligned input via an appended length field plus
//! `0x80`-style padding, and `decrypt_kw` recovers it by scanning backward for the last nonzero
//! byte through the appended checksum block - a heuristic that depends on the real plaintext's own
//! last byte being nonzero, and can silently over-consume real data otherwise (a latent fragility
//! in the reference C itself, not a transcription risk here - see D-55). Both Bouncy Castle ports
//! reject non-aligned input outright (`DataLengthException`/`ArgumentException`). This module
//! follows Bouncy Castle's restriction, matching every other raw mode in this crate
//! ([`super::kalyna_cbc`], [`super::kalyna_cfb`]): **`wrap`/`unwrap` require block-aligned
//! input and return [`KwError::InvalidLength`] otherwise - no padding scheme of this module's own.**
//!
//! # Deviation 2: added checksum verification on `unwrap`
//!
//! `dstu7624.c`'s `decrypt_kw` never checks that the recovered trailing block is actually
//! all-zero; it returns whatever bytes result. Both Bouncy Castle ports do check (KW's only
//! tamper-evidence mechanism) and reject otherwise. This module adds that check too
//! (`subtle::ConstantTimeEq`, per `docs/SECURITY.md`'s constant-time-comparison rule - the checksum
//! block is a function of secret key material through the whole Feistel network) - a deliberate,
//! cited safety addition, not an omission.
//!
//! # The round-counter width fork - resolved by bounding input size, not by picking a side
//!
//! `dstu7624.c` XORs only the low byte of the round counter into the tweak position (`size_t i`
//! implicitly truncated by assignment into a `uint8_t` slot); both Bouncy Castle ports XOR a full
//! 4-byte little-endian encoding. The two conventions are **provably identical whenever the
//! largest round counter used (`v`) is `<= 255`** (the encoding's upper 3 bytes are zero in that
//! range, so `XOR`ing them is a no-op either way) - and genuinely unresolved above that, since no
//! DSTU 7624:2014 primary text exists in this repo to break the tie, and Bouncy Castle's Java and
//! .NET ports are the same lineage, not two independent readings (D-55). This module implements the
//! 4-byte little-endian tweak and **hard-bounds input so `v` can never exceed 255**
//! (`r <= MAX_R = 20`, since `v = 12r + 6`) - the fork is unreachable through this API by
//! construction, not resolved by primary-source proof. `r <= 20` is generous for key-wrapping's
//! actual purpose (up to 320/640/1280 bytes of key material depending on block size).
//!
//! # No integrity beyond the checksum, and no heap allocation
//!
//! **Do not use this for new designs without a specific, understood reason.** This is a raw
//! key-wrap primitive, not a general-purpose AEAD - its only tamper-evidence is the checksum block
//! above, with no associated data support. Operates entirely on caller-supplied buffers with
//! fixed-size stack arrays (bounded by `MAX_R` above) - no `Vec`/`alloc`, matching
//! [`super::kalyna_ccm`]'s no-heap-allocation precedent, the only other multi-block-buffer hazmat
//! module in this crate.

use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KwError {
    InvalidLength,
    ChecksumMismatch,
}

const MAX_R: usize = 20;
const MAX_B_SLOTS: usize = 2 * MAX_R + 1;

macro_rules! kalyna_kw_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal, $half_bytes:literal) => {
        #[doc = concat!(
            "KW mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation, the two deliberate deviations from `dstu7624.c`, and the ",
            "misuse warning."
        )]
        pub struct $name;

        impl $name {
            /// Wraps `plaintext` (block-aligned, `1..=MAX_R` blocks) into `out`, which must be
            /// exactly one block longer than `plaintext` - expands the key schedule fresh on every
            /// call. Prefer [`Self::wrap_with_cipher`] for a caller that wraps more than one
            /// message under the same key.
            ///
            /// # Errors
            ///
            /// Returns [`KwError::InvalidLength`] if `plaintext` is empty, not a multiple of the
            /// block size, longer than `MAX_R` blocks, or `out`'s length doesn't match.
            pub fn wrap(
                key: &[u8; $key_bytes],
                plaintext: &[u8],
                out: &mut [u8],
            ) -> Result<(), KwError> {
                let cipher = super::kalyna::$expanded::new(key);
                Self::wrap_with_cipher(&cipher, plaintext, out)
            }

            /// Wraps `plaintext` using an already-expanded key schedule - the cached-schedule
            /// counterpart to [`Self::wrap`]. `docs/DECISIONS.md` D-76 / `docs/TASKS.md` T-127: `wrap`
            /// re-derives the full Kalyna round-key schedule on every call, which for KW's typically
            /// small (`1..=MAX_R`-block) inputs is not amortized the way it is for a large message -
            /// an avoidable cost for any caller wrapping more than one key under the same
            /// wrapping key.
            ///
            /// # Errors
            ///
            /// Same cases as [`Self::wrap`].
            pub fn wrap_with_cipher(
                cipher: &super::kalyna::$expanded,
                plaintext: &[u8],
                out: &mut [u8],
            ) -> Result<(), KwError> {
                if plaintext.is_empty()
                    || !plaintext.len().is_multiple_of($block_bytes)
                    || plaintext.len() / $block_bytes > MAX_R
                    || out.len() != plaintext.len() + $block_bytes
                {
                    return Err(KwError::InvalidLength);
                }

                let r = plaintext.len() / $block_bytes;
                let n = 2 * (r + 1);
                let v = (n - 1) * 6;

                let mut big_b = [0u8; $half_bytes];
                big_b.copy_from_slice(&plaintext[..$half_bytes]);

                let mut b = [[0u8; $half_bytes]; MAX_B_SLOTS];
                let mut off = $half_bytes;
                let mut idx = 0;
                while off < plaintext.len() {
                    b[idx].copy_from_slice(&plaintext[off..off + $half_bytes]);
                    idx += 1;
                    off += $half_bytes;
                }
                // Remaining slots up to index n - 2 stay zero - the appended checksum block.

                for i in 1..=v {
                    let mut block = [0u8; $block_bytes];
                    block[..$half_bytes].copy_from_slice(&big_b);
                    block[$half_bytes..].copy_from_slice(&b[0]);
                    let r_block = cipher.encrypt_block(&block);

                    let mut tweaked = r_block;
                    #[allow(clippy::cast_possible_truncation)] // i <= v <= 246, fits u32 trivially
                    let tweak = (i as u32).to_le_bytes();
                    for k in 0..4 {
                        tweaked[$half_bytes + k] ^= tweak[k];
                    }
                    big_b.copy_from_slice(&tweaked[$half_bytes..]);

                    for j in 0..(n - 2) {
                        b[j] = b[j + 1];
                    }
                    b[n - 2].copy_from_slice(&r_block[..$half_bytes]);
                }

                out[..$half_bytes].copy_from_slice(&big_b);
                let mut off = $half_bytes;
                for j in 0..(n - 1) {
                    out[off..off + $half_bytes].copy_from_slice(&b[j]);
                    off += $half_bytes;
                }
                Ok(())
            }

            /// Unwraps `ciphertext` (block-aligned, at least 2 blocks) into `out`, which must be
            /// exactly one block shorter than `ciphertext` - expands the key schedule fresh on
            /// every call. Prefer [`Self::unwrap_with_cipher`] for a caller that unwraps more than
            /// one message under the same key.
            ///
            /// # Errors
            ///
            /// Returns [`KwError::InvalidLength`] under the same-shaped conditions as
            /// [`Self::wrap`] (mirrored for `ciphertext`/`out`), or
            /// [`KwError::ChecksumMismatch`] if the recovered trailing checksum block isn't
            /// all-zero (see the module doc comment's "Deviation 2").
            pub fn unwrap(
                key: &[u8; $key_bytes],
                ciphertext: &[u8],
                out: &mut [u8],
            ) -> Result<(), KwError> {
                let cipher = super::kalyna::$expanded::new(key);
                Self::unwrap_with_cipher(&cipher, ciphertext, out)
            }

            /// Unwraps `ciphertext` using an already-expanded key schedule - the cached-schedule
            /// counterpart to [`Self::unwrap`]. Same rationale as [`Self::wrap_with_cipher`].
            ///
            /// # Errors
            ///
            /// Same cases as [`Self::unwrap`].
            pub fn unwrap_with_cipher(
                cipher: &super::kalyna::$expanded,
                ciphertext: &[u8],
                out: &mut [u8],
            ) -> Result<(), KwError> {
                if ciphertext.len() < 2 * $block_bytes
                    || !ciphertext.len().is_multiple_of($block_bytes)
                    || (ciphertext.len() / $block_bytes - 1) > MAX_R
                    || out.len() != ciphertext.len() - $block_bytes
                {
                    return Err(KwError::InvalidLength);
                }

                let r = ciphertext.len() / $block_bytes - 1;
                let n = 2 * (r + 1);
                let v = (n - 1) * 6;

                let mut big_b = [0u8; $half_bytes];
                big_b.copy_from_slice(&ciphertext[..$half_bytes]);

                let mut b = [[0u8; $half_bytes]; MAX_B_SLOTS];
                let mut off = $half_bytes;
                for idx in 0..(n - 1) {
                    b[idx].copy_from_slice(&ciphertext[off..off + $half_bytes]);
                    off += $half_bytes;
                }

                for i in (1..=v).rev() {
                    let last = b[n - 2];
                    let mut block = [0u8; $block_bytes];
                    block[..$half_bytes].copy_from_slice(&last);

                    let mut tweaked_b = big_b;
                    #[allow(clippy::cast_possible_truncation)] // i <= v <= 246, fits u32 trivially
                    let tweak = (i as u32).to_le_bytes();
                    for k in 0..4 {
                        tweaked_b[k] ^= tweak[k];
                    }
                    block[$half_bytes..].copy_from_slice(&tweaked_b);

                    let d = cipher.decrypt_block(&block);
                    big_b.copy_from_slice(&d[..$half_bytes]);

                    for j in (1..=(n - 2)).rev() {
                        b[j] = b[j - 1];
                    }
                    b[0].copy_from_slice(&d[$half_bytes..]);
                }

                // Last two slots are the appended checksum block - verify all-zero before
                // releasing anything into `out` (Deviation 2, module doc comment).
                let zero = [0u8; $half_bytes];
                let checksum_ok = b[n - 3].ct_eq(&zero) & b[n - 2].ct_eq(&zero);
                if !bool::from(checksum_ok) {
                    return Err(KwError::ChecksumMismatch);
                }

                out[..$half_bytes].copy_from_slice(&big_b);
                let mut off = $half_bytes;
                for j in 0..(n - 3) {
                    out[off..off + $half_bytes].copy_from_slice(&b[j]);
                    off += $half_bytes;
                }
                Ok(())
            }
        }
    };
}

kalyna_kw_variant!(Kalyna128_128Kw, Kalyna128_128ExpandedKey, 16, 16, 8);
kalyna_kw_variant!(Kalyna128_256Kw, Kalyna128_256ExpandedKey, 32, 16, 8);
kalyna_kw_variant!(Kalyna256_256Kw, Kalyna256_256ExpandedKey, 32, 32, 16);
kalyna_kw_variant!(Kalyna256_512Kw, Kalyna256_512ExpandedKey, 64, 32, 16);
kalyna_kw_variant!(Kalyna512_512Kw, Kalyna512_512ExpandedKey, 64, 64, 32);
