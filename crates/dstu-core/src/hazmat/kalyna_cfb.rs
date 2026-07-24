//! Kalyna-CFB: DSTU 7624:2014 mode of operation #3 ("Гамування зі зворотним зв'язком за
//! шифротекстом" / cipher feedback) - a keystream `gamma` seeded from the IV, self-updating by
//! re-encrypting a `feed` register that always absorbs the **ciphertext** `q` bytes at a time
//! (`q` is a caller-chosen feedback width, one of 1/8/16/32/64 bytes). Cited to
//! `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_cfb` (lines 3186-3234), `decrypt_cfb`
//! (lines 3762-3810), and `dstu7624_init_cfb` (lines 3971-3994). `DECISIONS.md` D-53 has the full
//! citation and roadmap context.
//!
//! # Not a textbook shift register - transcribed exactly, not simplified by analogy
//!
//! This construction's `feed` register does **not** literally shift old ciphertext bytes out as
//! new ones come in the way NIST SP 800-38A's CFB is often diagrammed. Each round, `feed` is
//! rebuilt as (the just-generated `gamma` block's leading `block_len - q` bytes) with its last `q`
//! bytes overwritten by the newest `q` ciphertext bytes, then `gamma = E_K(feed)` - `CLAUDE.md`'s
//! "don't simplify by analogy to textbook X" lesson applies directly here, so this was transcribed
//! from the C source exactly, verified against 8 official vectors spanning both partial (`q` <
//! block size) and full (`q` == block size) feedback widths, not assumed correct by inspection.
//!
//! # No integrity, and no padding
//!
//! **Do not use this for new designs without a specific, understood reason.** Like every raw mode
//! in this crate, CFB provides no authentication. Prefer [`crate::crypto_secretbox`] unless you
//! specifically need raw CFB and understand these tradeoffs.
//!
//! # Stateful, streaming API, and *not* self-inverse
//!
//! Unlike [`super::kalyna_ofb`], `encrypt_in_place` and `decrypt_in_place` are genuinely different
//! operations here (the C source has two separate functions, not one shared one) - the `feed`
//! register absorbs the produced output on encrypt but the raw input on decrypt, which happen to
//! be the same bytes (ciphertext) in both directions, but are read from different sources. Both
//! methods take `&mut self` and may be called repeatedly over successive chunks of one message -
//! **but unlike [`super::kalyna_ofb`]/[`super::kalyna_cbc`], call boundaries are not arbitrary.**
//! Every call except the last must supply a length that is a multiple of `q` - a call boundary
//! landing mid-way through a `q`-sized group leaves the internal state referencing a position a
//! later call's own bookkeeping cannot correctly resume from, **and will panic (an out-of-bounds
//! slice index), not silently produce wrong output** - this is a transcribed property of
//! `dstu7624.c`'s own construction (its self-test never exercises multi-call chaining with a
//! non-`q`-aligned boundary either), confirmed directly (not assumed) by `tests/kalyna_cfb.rs`'s
//! `proptest`, which restricts intermediate chunk lengths to multiples of `q` for exactly this
//! reason.

/// `q` is not one of the DSTU-defined feedback widths (1, 8, 16, 32, or 64 bytes), or exceeds the
/// block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidFeedbackWidth;

macro_rules! kalyna_cfb_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal) => {
        #[doc = concat!(
            "CFB mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation and the misuse warning."
        )]
        pub struct $name {
            key: super::kalyna::$expanded,
            gamma: [u8; $block_bytes],
            feed: [u8; $block_bytes],
            q: usize,
            used_gamma_len: usize,
        }

        impl $name {
            /// `q` (the feedback width) must be one of 1, 8, 16, 32, or 64 bytes, and at most the
            /// block size - matching `dstu7624_init_cfb`'s own `CHECK_PARAM`s exactly.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidFeedbackWidth`] if `q` fails either check.
            pub fn new(
                key: &[u8; $key_bytes],
                iv: &[u8; $block_bytes],
                q: usize,
            ) -> Result<Self, InvalidFeedbackWidth> {
                if q == 0 || q > $block_bytes || !matches!(q, 1 | 8 | 16 | 32 | 64) {
                    return Err(InvalidFeedbackWidth);
                }
                Ok(Self {
                    key: super::kalyna::$expanded::new(key),
                    gamma: *iv,
                    feed: *iv,
                    q,
                    used_gamma_len: $block_bytes,
                })
            }

            /// Encrypts `buf` in place. See the module doc comment for the `feed`/`gamma`
            /// bookkeeping this transcribes.
            pub fn encrypt_in_place(&mut self, buf: &mut [u8]) {
                let mut data_off = 0usize;
                let mut offset = self.used_gamma_len;

                if offset != 0 {
                    while offset < self.q && data_off < buf.len() {
                        buf[data_off] ^= self.gamma[offset];
                        self.feed[offset] = buf[data_off];
                        offset += 1;
                        data_off += 1;
                    }
                    if offset == $block_bytes {
                        self.gamma = self.key.encrypt_block(&self.feed);
                        offset = $block_bytes - self.q;
                    }
                }

                while data_off + self.q <= buf.len() {
                    for (b, g) in buf[data_off..data_off + self.q]
                        .iter_mut()
                        .zip(&self.gamma[offset..offset + self.q])
                    {
                        *b ^= *g;
                    }
                    self.feed[..$block_bytes].copy_from_slice(&self.gamma);
                    self.feed[offset..offset + self.q].copy_from_slice(&buf[data_off..data_off + self.q]);
                    self.gamma = self.key.encrypt_block(&self.feed);
                    data_off += self.q;
                }
                while data_off < buf.len() {
                    buf[data_off] ^= self.gamma[$block_bytes - (buf.len() - data_off)];
                    self.feed[offset] = buf[data_off];
                    offset += 1;
                    data_off += 1;
                }

                self.used_gamma_len = offset;
            }

            /// Decrypts `buf` in place. See the module doc comment for why this is not simply
            /// [`Self::encrypt_in_place`] run again - the `feed` register absorbs the raw
            /// ciphertext bytes read from `buf`, not the just-computed plaintext.
            pub fn decrypt_in_place(&mut self, buf: &mut [u8]) {
                let mut data_off = 0usize;
                let mut offset = self.used_gamma_len;

                if offset != 0 {
                    while offset < self.q && data_off < buf.len() {
                        let ciphertext_byte = buf[data_off];
                        buf[data_off] ^= self.gamma[offset];
                        self.feed[offset] = ciphertext_byte;
                        offset += 1;
                        data_off += 1;
                    }
                    if offset == $block_bytes {
                        self.gamma = self.key.encrypt_block(&self.feed);
                        offset = $block_bytes - self.q;
                    }
                }

                while data_off + self.q <= buf.len() {
                    let mut ciphertext_chunk = [0u8; $block_bytes];
                    ciphertext_chunk[..self.q].copy_from_slice(&buf[data_off..data_off + self.q]);
                    for (b, g) in buf[data_off..data_off + self.q]
                        .iter_mut()
                        .zip(&self.gamma[offset..offset + self.q])
                    {
                        *b ^= *g;
                    }
                    self.feed[..$block_bytes].copy_from_slice(&self.gamma);
                    self.feed[offset..offset + self.q].copy_from_slice(&ciphertext_chunk[..self.q]);
                    self.gamma = self.key.encrypt_block(&self.feed);
                    data_off += self.q;
                }
                while data_off < buf.len() {
                    let ciphertext_byte = buf[data_off];
                    buf[data_off] ^= self.gamma[$block_bytes - (buf.len() - data_off)];
                    self.feed[offset] = ciphertext_byte;
                    offset += 1;
                    data_off += 1;
                }

                self.used_gamma_len = offset;
            }
        }
    };
}

kalyna_cfb_variant!(Kalyna128_128Cfb, Kalyna128_128ExpandedKey, 16, 16);
kalyna_cfb_variant!(Kalyna128_256Cfb, Kalyna128_256ExpandedKey, 32, 16);
kalyna_cfb_variant!(Kalyna256_256Cfb, Kalyna256_256ExpandedKey, 32, 32);
kalyna_cfb_variant!(Kalyna256_512Cfb, Kalyna256_512ExpandedKey, 64, 32);
kalyna_cfb_variant!(Kalyna512_512Cfb, Kalyna512_512ExpandedKey, 64, 64);
