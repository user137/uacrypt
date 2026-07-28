//! Kalyna-OFB: DSTU 7624:2014 mode of operation #6 ("Гамування зі зворотним зв'язком за
//! шифрогамою" / output feedback) - a self-updating keystream (`gamma_0 = IV`, `gamma_n =
//! E_K(gamma_{n-1})`) `XOR`ed into the data, with **no dependency on plaintext or ciphertext at
//! all** - the simplest stateful mode in this crate. Cited to
//! `oracles/uapki/library/uapkic/src/dstu7624.c`'s `encrypt_ofb` (lines 3624-3670) and
//! `dstu7624_init_ofb` (lines 3996-4013); `dstu7624_decrypt` routes OFB to the same `encrypt_ofb`
//! function (confirmed in the C source's mode dispatch) - OFB is self-inverse, so this module has
//! one `apply_in_place`, not separate encrypt/decrypt methods. `docs/DECISIONS.md` D-53 has the full
//! citation and roadmap context.
//!
//! # No integrity, and pure confidentiality only
//!
//! **Do not use this for new designs without a specific, understood reason.** Like every raw mode
//! in this crate, OFB provides no authentication - a bit-flip in the ciphertext produces the exact
//! same bit-flip in the recovered plaintext, silently. OFB's keystream is also **plaintext-
//! independent and fully determined by the key and IV alone**, which makes IV reuse under the same
//! key catastrophic (identical keystream, trivially recoverable via XOR of the two ciphertexts) in
//! exactly the way CTR's is. Prefer [`crate::crypto_secretbox`] unless you specifically need raw,
//! unauthenticated keystream encryption and understand these tradeoffs.
//!
//! # Stateful, streaming API
//!
//! Unlike [`super::kalyna_ecb`], this mode carries state across calls (the current keystream block
//! and how much of it is unused) - [`apply_in_place`](Kalyna128_128Ofb::apply_in_place) takes
//! `&mut self` and may be called multiple times over successive chunks of one logical message; the
//! result is identical to calling it once over the whole concatenated buffer (verified by
//! `proptest` in `tests/kalyna_ofb.rs`, the same chunk-invariance property already established for
//! `hazmat::strumok`/`hazmat::kupyna`'s streaming APIs).

macro_rules! kalyna_ofb_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal) => {
        #[doc = concat!(
            "OFB mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the citation and the misuse warning."
        )]
        pub struct $name {
            key: super::kalyna::$expanded,
            gamma: [u8; $block_bytes],
            used_gamma_len: usize,
        }

        impl $name {
            /// `iv` seeds the keystream (`gamma_0 = iv`) - a fresh, unpredictable IV per message
            /// under a given key is required (see the module doc's misuse warning).
            #[must_use]
            pub fn new(key: &[u8; $key_bytes], iv: &[u8; $block_bytes]) -> Self {
                Self {
                    key: super::kalyna::$expanded::new(key),
                    gamma: *iv,
                    used_gamma_len: 0,
                }
            }

            /// XORs `buf` with the OFB keystream in place - encryption and decryption are the same
            /// operation (see the module doc comment). May be called repeatedly over successive
            /// chunks of one message; continues the keystream from wherever the previous call left
            /// off.
            pub fn apply_in_place(&mut self, buf: &mut [u8]) {
                let mut data_off = 0usize;

                if self.used_gamma_len != 0 {
                    let avail = $block_bytes - self.used_gamma_len;
                    let n = avail.min(buf.len());
                    for (b, g) in buf[..n]
                        .iter_mut()
                        .zip(&self.gamma[self.used_gamma_len..])
                    {
                        *b ^= *g;
                    }
                    data_off = n;
                    self.used_gamma_len += n;
                }

                while data_off < buf.len() {
                    self.gamma = self.key.encrypt_block(&self.gamma);
                    let n = $block_bytes.min(buf.len() - data_off);
                    for (b, g) in buf[data_off..data_off + n].iter_mut().zip(&self.gamma) {
                        *b ^= *g;
                    }
                    data_off += n;
                    self.used_gamma_len = n;
                }
            }
        }
    };
}

kalyna_ofb_variant!(Kalyna128_128Ofb, Kalyna128_128ExpandedKey, 16, 16);
kalyna_ofb_variant!(Kalyna128_256Ofb, Kalyna128_256ExpandedKey, 32, 16);
kalyna_ofb_variant!(Kalyna256_256Ofb, Kalyna256_256ExpandedKey, 32, 32);
kalyna_ofb_variant!(Kalyna256_512Ofb, Kalyna256_512ExpandedKey, 64, 32);
kalyna_ofb_variant!(Kalyna512_512Ofb, Kalyna512_512ExpandedKey, 64, 64);
