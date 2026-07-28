//! Kalyna-GCM: DSTU 7624:2014 mode of operation #7 (galois/counter mode) - CTR-mode encryption
//! plus a GHASH-like authentication tag, built on [`super::gf2m_wide`]'s field arithmetic. Cited to
//! `oracles/uapki/library/uapkic/src/dstu7624.c`'s `dstu7624_encrypt_gcm`/`dstu7624_decrypt_gcm`
//! (lines 3236-3440), `gf2m_mul` (lines 2963-3001), `dstu7624_init_gcm` (lines 4167-4219).
//! `docs/DECISIONS.md` D-56 has the full citation, the byte/bit representation derivation, and the
//! oracle-coverage breakdown.
//!
//! # Not textbook AES-GCM - transcribed as found, not completed from memory
//!
//! Three real divergences from the familiar NIST construction, all deliberate transcriptions:
//!
//! 1. **Double-encrypted counter.** `gamma_old = E_K(iv)` once; each keystream block is
//!    `E_K(gamma_old_incremented)`, not `E_K(iv_incremented)` directly. The increment touches only
//!    the low 64 bits of `gamma_old` (as a little-endian integer), never the rest of the block -
//!    independent of [`super::kalyna_ctr`]'s own counter convention, not shared code with it (same
//!    "three similar lines beats a premature abstraction across an already-verified boundary"
//!    reasoning applied to every other mode in this roadmap).
//! 2. **Horner-accumulate over AAD then ciphertext, no length block folded into the multiply
//!    chain.** `H = E_K(0)` once; `B = 0`, then for each AAD block (zero-padded, no `0x80` marker,
//!    if the last one is partial) and then each ciphertext block (**`0x80`-then-zeros padded** -
//!    the same `padding()` construction [`super::kalyna_cmac`]/[`super::kalyna_kw`] use, not plain
//!    zero-padding, and *not* symmetric with AAD's plain zero-padding - a real, easy-to-miss
//!    asymmetry confirmed by reading the C source line by line): `B = (B XOR block) * H`.
//! 3. **Tag = block-cipher-encrypt of `(accumulator XOR length block)`, not XOR with a keystream
//!    block.** The length block holds the AAD bit-length (little-endian) in the low half-block and
//!    the *padded* ciphertext bit-length (not the true, unpadded plaintext length - a direct
//!    consequence of `dstu7624.c` reusing the same mutated length variable after its own padding
//!    step) in the high half-block.
//!
//! **None of the 6 official test vectors have non-block-aligned plaintext** - the `0x80` padding
//! marker in divergence 2 is transcribed as found but not oracle-exercised; see `docs/DECISIONS.md`
//! D-56 and the `proptest` round-trip in `tests/kalyna_gcm.rs`, which does cover it generically.
//!
//! # Byte/bit representation
//!
//! Field elements are **little-endian** ([`super::gf2m_wide`]'s own convention, distinct from
//! [`super::dstu4145::gf2m163`]'s big-endian one - see that module's doc comment) - forced by
//! `uint8_to_uint64`'s plain little-endian `memcpy` reinterpretation, which is what `gf2m_mul`'s
//! byte-array wrapper actually uses.
//!
//! # No integrity without a tag, and nonce reuse is catastrophic
//!
//! **Do not use this for new designs without a specific, understood reason.** A fresh,
//! unpredictable `iv` per message under a given key is required - reusing one produces an
//! identical keystream (trivially recoverable via XOR of the two ciphertexts, same failure mode as
//! [`super::kalyna_ctr`]/[`super::kalyna_ofb`]) *and* reuses the same GHASH key `H`, which can leak
//! enough to forge tags. `decrypt`'s tag check uses `subtle::ConstantTimeEq`, **not** `dstu7624.c`'s
//! raw `memcmp` - a deliberate, cited safety fix (`docs/DECISIONS.md` D-56), matching the same pattern
//! already applied to [`super::kalyna_kw`]'s checksum check and [`super::kalyna_cmac`]'s tag verify.
//!
//! # Warning: the tag does not cover `iv`
//!
//! Unlike NIST AES-GCM (whose tag derives from `E_K(J0)`, `J0` being IV-derived), divergence 3
//! above means this construction's tag is a function of AAD and ciphertext only - `iv` never
//! enters the accumulator, only the keystream. Tampering `iv` alone, with `aad`/`ciphertext`/`tag`
//! left untouched, does **not** fail `decrypt`'s tag check; it silently produces different
//! (wrong) plaintext instead. Any caller who transmits `iv` alongside the ciphertext (as opposed
//! to deriving it from an already-authenticated channel state) and needs tampering of that
//! transmitted `iv` to be detected **must** pass it as (or fold it into) `aad` - it is not
//! authenticated for free. [`crate::crypto_secretbox`] does exactly this (`docs/DECISIONS.md` D-63);
//! see `tests/kalyna_gcm.rs`'s `tampered_iv_alone_does_not_fail_the_tag_check` for the property
//! pinned directly at this layer.

use subtle::ConstantTimeEq;

use super::gf2m_wide::{Gf2m128, Gf2m256, Gf2m512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcmError {
    InvalidLength,
    TagMismatch,
}

macro_rules! kalyna_gcm_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal, $half_bytes:literal, $gf:ty) => {
        #[doc = concat!(
            "GCM mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation, the three AES-GCM divergences, and the misuse warning."
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

            /// XORs the double-encrypted CTR keystream into `data`, writing the result to `out`
            /// (same length as `data`) - self-inverse, used for both encrypt and decrypt.
            fn apply_keystream(&self, iv: &[u8; $block_bytes], data: &[u8], out: &mut [u8]) {
                let mut gamma_old = self.key.encrypt_block(iv);

                let mut off = 0usize;
                while off < data.len() {
                    let mut low = u64::from_le_bytes(gamma_old[..8].try_into().unwrap());
                    low = low.wrapping_add(1);
                    gamma_old[..8].copy_from_slice(&low.to_le_bytes());

                    let gamma = self.key.encrypt_block(&gamma_old);
                    let end = (off + $block_bytes).min(data.len());
                    for i in off..end {
                        out[i] = data[i] ^ gamma[i - off];
                    }
                    off += $block_bytes;
                }
            }

            /// Computes the full-block-length authentication tag over `aad` and `ciphertext` -
            /// see the module doc comment's divergences 2 and 3. Callers truncate to their chosen
            /// `q` themselves (a pure truncation of this value, per the source construction).
            fn compute_tag(&self, aad: &[u8], ciphertext: &[u8]) -> [u8; $block_bytes] {
                let h_key = <$gf>::from_le_bytes(&self.key.encrypt_block(&[0u8; $block_bytes]));
                let mut acc = <$gf>::ZERO;

                // AAD: plain zero-padded (no 0x80 marker) - divergence 2.
                let mut off = 0usize;
                while off < aad.len() {
                    let end = (off + $block_bytes).min(aad.len());
                    let mut block = [0u8; $block_bytes];
                    block[..end - off].copy_from_slice(&aad[off..end]);
                    acc = acc.add(<$gf>::from_le_bytes(&block)).multiply(h_key);
                    off += $block_bytes;
                }

                // Ciphertext: 0x80-then-zeros padded (ISO/IEC 7816-4 style) - divergence 2.
                let ct_len = ciphertext.len();
                let rem = ct_len % $block_bytes;
                let padded_ct_len = if rem == 0 { ct_len } else { ct_len + ($block_bytes - rem) };
                let mut off = 0usize;
                while off < padded_ct_len {
                    let end = (off + $block_bytes).min(ct_len);
                    let mut block = [0u8; $block_bytes];
                    if end > off {
                        block[..end - off].copy_from_slice(&ciphertext[off..end]);
                    }
                    if rem != 0 && ct_len >= off && ct_len < off + $block_bytes {
                        block[ct_len - off] = 0x80;
                    }
                    acc = acc.add(<$gf>::from_le_bytes(&block)).multiply(h_key);
                    off += $block_bytes;
                }

                // Length block: AAD bit-length (low half), padded-ciphertext bit-length (high
                // half), both little-endian u64 - divergence 3.
                let mut length_block = [0u8; $block_bytes];
                #[allow(clippy::cast_possible_truncation)] // realistic lengths fit u64 trivially
                let auth_len_bits = (aad.len() as u64) * 8;
                #[allow(clippy::cast_possible_truncation)]
                let padded_ct_len_bits = (padded_ct_len as u64) * 8;
                length_block[..8].copy_from_slice(&auth_len_bits.to_le_bytes());
                length_block[$half_bytes..$half_bytes + 8]
                    .copy_from_slice(&padded_ct_len_bits.to_le_bytes());

                let acc_bytes = acc.to_le_bytes();
                let mut combined = [0u8; $block_bytes];
                for i in 0..$block_bytes {
                    combined[i] = length_block[i] ^ acc_bytes[i];
                }

                self.key.encrypt_block(&combined)
            }

            /// Encrypts `plaintext` into `ciphertext_out` (same length) and returns the
            /// full-block-length authentication tag over `aad` and the ciphertext - truncate to
            /// your chosen `q` (between 8 and one full block) yourself when transmitting/storing
            /// it.
            ///
            /// `iv` must never repeat under the same key - see the module doc comment's misuse
            /// warning.
            ///
            /// # Errors
            ///
            /// Returns [`GcmError::InvalidLength`] if `ciphertext_out.len() != plaintext.len()`.
            pub fn encrypt(
                &self,
                iv: &[u8; $block_bytes],
                aad: &[u8],
                plaintext: &[u8],
                ciphertext_out: &mut [u8],
            ) -> Result<[u8; $block_bytes], GcmError> {
                if ciphertext_out.len() != plaintext.len() {
                    return Err(GcmError::InvalidLength);
                }
                self.apply_keystream(iv, plaintext, ciphertext_out);
                Ok(self.compute_tag(aad, ciphertext_out))
            }

            /// Verifies `tag` (the caller's chosen `q` bytes, between 8 and one full block) over
            /// `aad` and `ciphertext`, then decrypts into `plaintext_out` (same length as
            /// `ciphertext`) only if it verifies.
            ///
            /// # Errors
            ///
            /// Returns [`GcmError::InvalidLength`] if `tag.len()` is outside `8..=`[`$block_bytes`]
            /// or `plaintext_out.len() != ciphertext.len()`, or [`GcmError::TagMismatch`] if
            /// authentication fails - `plaintext_out` is left all-zero on failure, never unverified
            /// plaintext.
            pub fn decrypt(
                &self,
                iv: &[u8; $block_bytes],
                aad: &[u8],
                ciphertext: &[u8],
                tag: &[u8],
                plaintext_out: &mut [u8],
            ) -> Result<(), GcmError> {
                if !(8..=$block_bytes).contains(&tag.len()) || plaintext_out.len() != ciphertext.len()
                {
                    return Err(GcmError::InvalidLength);
                }

                let expected = self.compute_tag(aad, ciphertext);
                if !bool::from(expected[..tag.len()].ct_eq(tag)) {
                    plaintext_out.fill(0);
                    return Err(GcmError::TagMismatch);
                }

                self.apply_keystream(iv, ciphertext, plaintext_out);
                Ok(())
            }
        }
    };
}

kalyna_gcm_variant!(
    Kalyna128_128Gcm,
    Kalyna128_128ExpandedKey,
    16,
    16,
    8,
    Gf2m128
);
kalyna_gcm_variant!(
    Kalyna128_256Gcm,
    Kalyna128_256ExpandedKey,
    32,
    16,
    8,
    Gf2m128
);
kalyna_gcm_variant!(
    Kalyna256_256Gcm,
    Kalyna256_256ExpandedKey,
    32,
    32,
    16,
    Gf2m256
);
kalyna_gcm_variant!(
    Kalyna256_512Gcm,
    Kalyna256_512ExpandedKey,
    64,
    32,
    16,
    Gf2m256
);
kalyna_gcm_variant!(
    Kalyna512_512Gcm,
    Kalyna512_512ExpandedKey,
    64,
    64,
    32,
    Gf2m512
);
