//! Kalyna-CMAC: DSTU 7624:2014 mode of operation #4 - CBC-MAC over all blocks but the last, then a
//! final block `XOR`ed against a subkey and encrypted once more. **Not** GF-doubling-subkey
//! CMAC/OMAC the way AES-CMAC derives its subkeys - transcribed as found, not by analogy to that
//! more familiar construction. Cited to `oracles/uapki/library/uapkic/src/dstu7624.c`'s
//! `cmac_update`/`cmac_final` (lines 4221-4310), `padding` (lines 2572-2592), and
//! `dstu7624_init_cmac` (lines 4070-4087); `Dstu7624Ctx` is confirmed zero-initialized
//! (`dstu7624_alloc`'s `CALLOC_CHECKED`), so the running state starts at the zero block, not an
//! IV. `DECISIONS.md` D-54 has the full citation, oracle-coverage breakdown, and roadmap context.
//!
//! # One-shot, not streaming
//!
//! Unlike [`super::kalyna_cbc`]/[`super::kalyna_cfb`]/etc., this module takes the whole message in
//! one call rather than exposing incremental `update`. Nothing in this crate consumes an
//! incremental MAC yet (the same position [`super::kupyna_kmac`] was in before any `crypto_auth`
//! wrapper existed) - this module follows that module's shape directly rather than re-deriving the
//! C source's own multi-call buffering state machine for no present benefit.
//!
//! # `q` fixed at 16 bytes, not a caller-configurable knob
//!
//! The C source allows a caller-chosen tag length `1..=block_len`, but every available oracle
//! vector (uapki's own KATs and Bouncy Castle's corroborating ones) uses `q = 16` regardless of
//! block size - it is the only value ever exercised by any oracle. Exposing a wider `q` would ship
//! an untested code path, which this project's citation discipline forbids.
//!
//! # No key separation from any encryption key
//!
//! **Do not use this for new designs without a specific, understood reason.** This module provides
//! no key derivation or domain separation - reusing the same key for CMAC and any encryption mode
//! in this crate is a misuse risk, not something this API prevents. Prefer a future `crypto_auth`
//! wrapper once one exists (matching [`super::kupyna_kmac`]'s framing) unless a raw MAC over Kalyna
//! specifically is genuinely needed.

use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmacError {
    TagMismatch,
}

macro_rules! kalyna_cmac_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal) => {
        #[doc = concat!(
            "CMAC over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation and the misuse warning."
        )]
        pub struct $name;

        impl $name {
            /// Computes the 16-byte CMAC tag of `message` under `key` - expands the key schedule
            /// fresh on every call. Prefer [`Self::mac_with_cipher`] for a caller computing a MAC
            /// for more than one message under the same key (see its doc comment for why).
            #[must_use]
            pub fn mac(key: &[u8; $key_bytes], message: &[u8]) -> [u8; 16] {
                let cipher = super::kalyna::$expanded::new(key);
                Self::mac_with_cipher(&cipher, message)
            }

            /// Computes the 16-byte CMAC tag of `message` using an already-expanded key schedule -
            /// the cached-schedule counterpart to [`Self::mac`]. `DECISIONS.md` D-76 / `TASKS.md`
            /// T-127: `mac` re-derives the full Kalyna round-key schedule on every invocation, an
            /// avoidable cost (comparable to several block-cipher calls) for any caller computing a MAC for more
            /// than one message under the same key - this method lets such a caller build the
            /// schedule once and reuse it, exactly like [`super::kalyna_gcm`]/[`super::kalyna_xts`]
            /// already do for their own modes.
            #[must_use]
            pub fn mac_with_cipher(cipher: &super::kalyna::$expanded, message: &[u8]) -> [u8; 16] {
                let len = message.len();
                let chain_len = if len == 0 {
                    0
                } else if len % $block_bytes == 0 {
                    len - $block_bytes
                } else {
                    (len / $block_bytes) * $block_bytes
                };
                let tail = &message[chain_len..];

                let mut state = [0u8; $block_bytes];
                for block in message[..chain_len].chunks_exact($block_bytes) {
                    for (s, b) in state.iter_mut().zip(block) {
                        *s ^= *b;
                    }
                    state = cipher.encrypt_block(&state);
                }

                let mut last_block = [0u8; $block_bytes];
                last_block[..tail.len()].copy_from_slice(tail);
                if tail.len() % $block_bytes != 0 {
                    last_block[tail.len()] = 0x80;
                }

                let mut rkey = [0u8; $block_bytes];
                rkey[0] = u8::from(tail.len() % $block_bytes != 0);
                let rkey = cipher.encrypt_block(&rkey);

                for (s, (l, r)) in state.iter_mut().zip(last_block.iter().zip(rkey.iter())) {
                    *s ^= *l ^ *r;
                }
                let tag_block = cipher.encrypt_block(&state);

                let mut tag = [0u8; 16];
                tag.copy_from_slice(&tag_block[..16]);
                tag
            }

            /// Recomputes the CMAC tag and compares it against `expected` in constant time
            /// (`subtle::ConstantTimeEq`, per `SECURITY.md`'s hard constraint on secret
            /// comparisons - a MAC tag is exactly this category).
            ///
            /// # Errors
            ///
            /// Returns `Err(CmacError::TagMismatch)` if the recomputed tag doesn't match
            /// `expected`.
            pub fn verify(
                key: &[u8; $key_bytes],
                message: &[u8],
                expected: &[u8; 16],
            ) -> Result<(), CmacError> {
                let cipher = super::kalyna::$expanded::new(key);
                Self::verify_with_cipher(&cipher, message, expected)
            }

            /// The cached-schedule counterpart to [`Self::verify`] - see
            /// [`Self::mac_with_cipher`]'s doc comment for why this exists.
            ///
            /// # Errors
            ///
            /// Returns `Err(CmacError::TagMismatch)` if the recomputed tag doesn't match
            /// `expected`.
            pub fn verify_with_cipher(
                cipher: &super::kalyna::$expanded,
                message: &[u8],
                expected: &[u8; 16],
            ) -> Result<(), CmacError> {
                let tag = Self::mac_with_cipher(cipher, message);
                if tag.ct_eq(expected).into() {
                    Ok(())
                } else {
                    Err(CmacError::TagMismatch)
                }
            }
        }
    };
}

kalyna_cmac_variant!(Kalyna128_128Cmac, Kalyna128_128ExpandedKey, 16, 16);
kalyna_cmac_variant!(Kalyna128_256Cmac, Kalyna128_256ExpandedKey, 32, 16);
kalyna_cmac_variant!(Kalyna256_256Cmac, Kalyna256_256ExpandedKey, 32, 32);
kalyna_cmac_variant!(Kalyna256_512Cmac, Kalyna256_512ExpandedKey, 64, 32);
kalyna_cmac_variant!(Kalyna512_512Cmac, Kalyna512_512ExpandedKey, 64, 64);
