//! Kalyna-CTR: DSTU 7624:2014 mode of operation #2 ("Гамування" / counter/gamma) - a keystream
//! block `E_K(counter)` `XOR`ed into the data, `counter` primed from the IV and incremented before
//! each new keystream block is derived. Cited to
//! `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_ctr` (lines 2739-2790) and
//! `dstu7624_init_ctr` (lines 4397-4421); `dstu7624_decrypt` confirmed routing CTR to the same
//! `encrypt_ctr` function - CTR is self-inverse, one `apply_in_place`, matching
//! [`super::kalyna_ofb`]'s shape. `DECISIONS.md` D-53 has the full citation and roadmap context.
//!
//! **This is exactly the keystream-priming/increment/re-encrypt logic
//! `super::kalyna_ccm`'s internal `Gamma` component already implements** (`hazmat::kalyna_ccm`
//! calls this same `encrypt_ctr` internally, per the C source) - deliberately **not** shared code
//! with that module, even though the logic is nearly identical: `kalyna_ccm` is shipped,
//! dual-oracle-verified, miri-clean AEAD code, and a shared abstraction across that boundary would
//! be a regression risk in already-verified code for a DRY win not worth it (`CLAUDE.md`'s "three
//! similar lines beats a premature abstraction" rule, applied literally here). This module has its
//! own independent implementation and its own tests.
//!
//! # No integrity, and the same IV-reuse failure mode as [`super::kalyna_ofb`]
//!
//! **Do not use this for new designs without a specific, understood reason.** No authentication.
//! Reusing an IV under the same key produces an identical keystream, trivially recoverable via XOR
//! of the two ciphertexts. Prefer [`crate::crypto_secretbox`] unless you specifically need raw CTR
//! and understand these tradeoffs.
//!
//! # Stateful, streaming API
//!
//! Like [`super::kalyna_ofb`], `apply_in_place` takes `&mut self` and may be called repeatedly over
//! successive chunks of one message - verified by `proptest` chunk-invariance in
//! `tests/kalyna_ctr.rs`, at arbitrary (not `q`-restricted, unlike [`super::kalyna_cfb`]) call
//! boundaries, since this construction's counter-increment bookkeeping does not have that mode's
//! partial-feedback-width complication.

macro_rules! kalyna_ctr_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal) => {
        #[doc = concat!(
            "CTR mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation and the misuse warning."
        )]
        pub struct $name {
            key: super::kalyna::$expanded,
            gamma: [u8; $block_bytes],
            feed: [u8; $block_bytes],
            used_gamma_len: usize,
        }

        impl $name {
            /// `iv` seeds the counter - a fresh, unpredictable IV per message under a given key is
            /// required (see the module doc's misuse warning).
            #[must_use]
            pub fn new(key: &[u8; $key_bytes], iv: &[u8; $block_bytes]) -> Self {
                let key = super::kalyna::$expanded::new(key);
                let gamma = key.encrypt_block(iv);
                Self {
                    key,
                    gamma,
                    feed: gamma,
                    used_gamma_len: $block_bytes,
                }
            }

            /// XORs `buf` with the CTR keystream in place - encryption and decryption are the
            /// same operation (see the module doc comment). May be called repeatedly over
            /// successive chunks of one message; continues the keystream from wherever the
            /// previous call left off.
            pub fn apply_in_place(&mut self, buf: &mut [u8]) {
                let mut data_off = 0usize;
                let mut offset = self.used_gamma_len;

                if offset != 0 {
                    while offset < $block_bytes && data_off < buf.len() {
                        buf[data_off] ^= self.gamma[offset];
                        data_off += 1;
                        offset += 1;
                    }
                    if offset == $block_bytes {
                        Self::increment_counter(&mut self.feed);
                        self.gamma = self.key.encrypt_block(&self.feed);
                        offset = 0;
                    }
                }

                while data_off + $block_bytes <= buf.len() {
                    for (b, g) in buf[data_off..data_off + $block_bytes]
                        .iter_mut()
                        .zip(&self.gamma)
                    {
                        *b ^= *g;
                    }
                    Self::increment_counter(&mut self.feed);
                    self.gamma = self.key.encrypt_block(&self.feed);
                    data_off += $block_bytes;
                }
                while data_off < buf.len() {
                    buf[data_off] ^= self.gamma[offset];
                    offset += 1;
                    data_off += 1;
                }

                self.used_gamma_len = offset;
            }

            /// `gamma_gen` (`dstu7624.c:2730`): little-endian increment-with-carry, byte 0 is
            /// least-significant - matching the oracle's own indexing.
            fn increment_counter(counter: &mut [u8; $block_bytes]) {
                for byte in counter.iter_mut() {
                    *byte = byte.wrapping_add(1);
                    if *byte != 0 {
                        return;
                    }
                }
            }
        }
    };
}

kalyna_ctr_variant!(Kalyna128_128Ctr, Kalyna128_128ExpandedKey, 16, 16);
kalyna_ctr_variant!(Kalyna128_256Ctr, Kalyna128_256ExpandedKey, 32, 16);
kalyna_ctr_variant!(Kalyna256_256Ctr, Kalyna256_256ExpandedKey, 32, 32);
kalyna_ctr_variant!(Kalyna256_512Ctr, Kalyna256_512ExpandedKey, 64, 32);
kalyna_ctr_variant!(Kalyna512_512Ctr, Kalyna512_512ExpandedKey, 64, 64);
