//! Kalyna-CCM: DSTU 7624:2014 mode of operation "вироблення імітовставки і гамування" (§13).
//!
//! **Follows the standard's text** - DSTU 7624:2014, draft edition (T-234, `docs/DECISIONS.md`
//! D-205), checked against all five annex В.9 examples. First ported from
//! `oracles/uapki/library/uapkic/src/dstu7624.c` (`dstu7624_init_ccm`, `ccm_padd`,
//! `dstu7624_encrypt_ccm`/`dstu7624_decrypt_ccm`, D-41), which matches the annex examples but not the
//! text elsewhere. Three places were corrected to §13.2:
//! - the flag byte's top bit marks a non-empty AAD (table 13.2), not a non-empty plaintext;
//! - with no AAD the CBC-MAC starts from `T(G1)` alone (the draft literally says "B = G1", read as a
//!   drafting slip - see D-205);
//! - `G2` is `lambda_o` in `N_B` bytes LE plus exactly enough zeros to block-align `G1 || G2 || O`,
//!   which can spill into another block.
//!
//! An empty plaintext is rejected ([`CcmError::EmptyPlaintext`]): §13.1 requires `|M| >= 8` bits.
//! UAPKI and Bouncy Castle 1.85 differ from this module on some inputs - see
//! `docs/COMPATIBILITY.md`.
//!
//! This module is a standalone hazmat-level primitive. `crypto_secretbox` was first built on it
//! (T-37, D-51) and moved to Kalyna-GCM in D-63; no `crypto_*` module uses it now.
//!
//! # Hard length limit - sourced, not chosen
//!
//! `dstu7624.c`'s `ccm_padd` wrote the plaintext and AAD lengths as a single byte each, so the
//! port capped **both at 255 bytes**. The standard itself writes them as `N_B`-byte LE fields (this
//! module now does too, D-205), so the cap is a scope limit kept from the port, not a property of
//! the standard. [`MAX_PLAINTEXT_LEN`]/[`MAX_AAD_LEN`] enforce it; longer input is rejected, never
//! truncated.
//!
//! # Nonce
//!
//! The nonce is a full block-size buffer (matching the vectors, which supply a full-block IV even
//! though `G1` only takes a `block_len - ccm_nb - 1`-byte prefix of it - the remaining bytes still
//! feed the CTR keystream, and it is the *full* block that seeds it via `Gamma::new`). §13.1 requires
//! only that **prefix** to be unique per key (11 bytes for a 128-bit block), so the uniqueness
//! margin to plan for is the prefix's, not the full block's (D-205). **Strategy resolved, `docs/DECISIONS.md` D-40/`docs/TASKS.md`
//! T-82**: this module always treats the nonce as caller-supplied, never generating one itself -
//! `no_std` callers may have no OS CSPRNG to call. The recommended pattern for any caller that
//! *does* have one is a fresh, independently-random full-block nonce per message under a given
//! key (a libsodium-style wide random nonce, not a TLS-1.3-style stateful counter - a counter's
//! uniqueness guarantee needs durable cross-reboot state this project can't assume for its
//! embedded targets). For the narrowest variants (128-bit block) a random nonce's 88-bit prefix
//! gives a birthday bound of roughly 2^44 messages under one key, not the 2^48 D-40 first stated
//! for the full 128-bit block (D-205). `increment_counter` carries across the whole block, where
//! §13.3 increments only its low half; the two differ only after 2^64 blocks, unreachable under the
//! 255-byte cap. `uacrypt kalyna-ccm encrypt` (the CLI
//! layer) implements this recommendation by generating the nonce itself via `getrandom` rather
//! than accepting one - the five `(ccm_nb, q)` pairs used here remain exactly what the cross-oracle
//! vectors confirm, not a new choice made by this module.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const MAX_BLOCK: usize = 64;
/// Sourced limit - see the module doc comment's "Hard length limit" section.
pub const MAX_PLAINTEXT_LEN: usize = 255;
/// Sourced limit - see the module doc comment's "Hard length limit" section.
pub const MAX_AAD_LEN: usize = 255;

/// Largest `N_B` (length-field width) any variant uses.
const MAX_CCM_NB: usize = 8;
/// `G1 || G2 || O` at its largest: `G1` is one block, `G2` is `N_B` length bytes plus at most
/// `block_len - 1` zero bytes (§13.2), then up to `MAX_AAD_LEN` bytes of AAD. 512/512 with a 255-byte
/// AAD needs exactly 64 + 65 + 255 = 384 bytes.
const H_BUF_LEN: usize = MAX_BLOCK + (MAX_CCM_NB + MAX_BLOCK - 1) + MAX_AAD_LEN;
/// Plaintext plus at most one block of `padding`'s 0x80-then-zeros pad.
const P_BUF_LEN: usize = MAX_PLAINTEXT_LEN + MAX_BLOCK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcmError {
    /// §13.1 requires `|M| = 8r` with `r >= 1`: an empty plaintext is outside the standard's domain.
    EmptyPlaintext,
    PlaintextTooLong,
    AadTooLong,
    TagMismatch,
}

/// `gamma_gen` (`dstu7624.c:2730`): little-endian increment-with-carry over the first `block_len`
/// bytes only - byte 0 is least-significant, matching the oracle's own indexing.
fn increment_counter(counter: &mut [u8], block_len: usize) {
    for byte in counter.iter_mut().take(block_len) {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

#[allow(clippy::cast_possible_truncation)] // q is always one of {8,16,32,48,64}, never truncated
fn tag_length_code(q: usize) -> u8 {
    match q {
        8 => 2,
        16 => 3,
        32 => 4,
        48 => 5,
        64 => 6,
        _ => 0,
    }
}

/// DSTU 7624:2014 (draft) §13.2 (T-234, `docs/DECISIONS.md` D-205): builds `G1` (table 13.1) and,
/// when the AAD `O` is non-empty, `G2 || O`, and runs the CBC-MAC (repeated XOR-then-encrypt) over
/// them and the Б.2-padded plaintext. Returns a `MAX_BLOCK`-byte buffer whose first `q` bytes are
/// the raw (unmasked) tag.
#[allow(clippy::too_many_arguments)]
fn compute_tag(
    encrypt_block: &dyn Fn(&[u8; MAX_BLOCK]) -> [u8; MAX_BLOCK],
    block_len: usize,
    ccm_nb: usize,
    q: usize,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; MAX_BLOCK] {
    let prefix_len = block_len - ccm_nb - 1;

    // G1 = L(S) || |M|/8 as N_B bytes LE || flags (tables 13.1/13.2).
    let mut g1 = [0u8; MAX_BLOCK];
    g1[..prefix_len].copy_from_slice(&nonce[..prefix_len]);
    let m_len = (plaintext.len() as u64).to_le_bytes();
    g1[prefix_len..prefix_len + ccm_nb].copy_from_slice(&m_len[..ccm_nb]);
    let mut flags = if aad.is_empty() { 0u8 } else { 0x80 };
    flags |= tag_length_code(q) << 4;
    #[allow(clippy::cast_possible_truncation)] // ccm_nb is always one of {4,6,8}, fits easily
    {
        flags |= (ccm_nb - 1) as u8;
    }
    g1[block_len - 1] = flags;

    // |O| > 0: G1 || G2 || O with G2 = lambda_o (N_B bytes LE) || 0^z, z chosen so the whole is
    // block-aligned. |O| = 0: just G1, so B = T(G1) (the text's literal "B = G1" read as a drafting
    // slip - see D-205).
    let mut h_buf = [0u8; H_BUF_LEN];
    h_buf[..block_len].copy_from_slice(&g1[..block_len]);
    let mut h_len = block_len;
    if !aad.is_empty() {
        let o_len = (aad.len() as u64).to_le_bytes();
        h_buf[h_len..h_len + ccm_nb].copy_from_slice(&o_len[..ccm_nb]);
        let zeros = (2 * block_len - aad.len() % block_len - ccm_nb) % block_len;
        h_len += ccm_nb + zeros;
        h_buf[h_len..h_len + aad.len()].copy_from_slice(aad);
        h_len += aad.len();
    }

    // `chunks_exact` would silently drop a remainder; the G2 formula makes one impossible.
    debug_assert_eq!(h_len % block_len, 0);
    let mut b = [0u8; MAX_BLOCK];
    for chunk in h_buf[..h_len].chunks_exact(block_len) {
        for (acc, byte) in b.iter_mut().zip(chunk) {
            *acc ^= byte;
        }
        b = encrypt_block(&b);
    }

    let mut p_buf = [0u8; P_BUF_LEN];
    p_buf[..plaintext.len()].copy_from_slice(plaintext);
    let mut p_len = plaintext.len();
    if !p_len.is_multiple_of(block_len) {
        p_buf[p_len] = 0x80;
        p_len += block_len - (p_len % block_len);
    }
    for chunk in p_buf[..p_len].chunks_exact(block_len) {
        for (acc, byte) in b.iter_mut().zip(chunk) {
            *acc ^= byte;
        }
        b = encrypt_block(&b);
    }

    b
}

/// `dstu7624_init_ctr`/`encrypt_ctr` (`dstu7624.c:4397`/`2739`): the running CTR keystream state.
/// The first block computed at construction (`E_K(nonce)`) is never itself used as keystream - it
/// only seeds the counter that gets incremented before the first real keystream block is derived
/// (`used = block_len` forces regeneration on the very first [`Self::apply`] call) - this doubled
/// indirection is a property of the source, transcribed as-is rather than "simplified" to
/// textbook CTR.
struct Gamma {
    counter: [u8; MAX_BLOCK],
    keystream: [u8; MAX_BLOCK],
    used: usize,
    block_len: usize,
}

impl Gamma {
    fn new(
        block_len: usize,
        nonce_block: &[u8; MAX_BLOCK],
        encrypt_block: &dyn Fn(&[u8; MAX_BLOCK]) -> [u8; MAX_BLOCK],
    ) -> Self {
        let seed = encrypt_block(nonce_block);
        Self {
            counter: seed,
            keystream: seed,
            used: block_len,
            block_len,
        }
    }

    /// XORs `buf` with the keystream in place, continuing from wherever the previous call left
    /// off - callers rely on this to mask the tag with the keystream bytes immediately following
    /// whatever the plaintext/ciphertext call consumed, not a fresh block.
    fn apply(
        &mut self,
        buf: &mut [u8],
        encrypt_block: &dyn Fn(&[u8; MAX_BLOCK]) -> [u8; MAX_BLOCK],
    ) {
        let block_len = self.block_len;
        let mut offset = self.used;
        let mut data_off = 0usize;

        if offset != 0 {
            while offset < block_len && data_off < buf.len() {
                buf[data_off] ^= self.keystream[offset];
                data_off += 1;
                offset += 1;
            }
            if offset == block_len {
                increment_counter(&mut self.counter, block_len);
                self.keystream = encrypt_block(&self.counter);
                offset = 0;
            }
        }

        while data_off + block_len <= buf.len() {
            for i in 0..block_len {
                buf[data_off + i] ^= self.keystream[i];
            }
            data_off += block_len;
            increment_counter(&mut self.counter, block_len);
            self.keystream = encrypt_block(&self.counter);
        }

        while data_off < buf.len() {
            buf[data_off] ^= self.keystream[offset];
            data_off += 1;
            offset += 1;
        }

        self.used = offset;
    }
}

/// Shared core behind every variant's `seal_in_place` (see `kalyna_ccm_variant!`). Encrypts `buf`
/// in place and returns the `q`-byte masked tag (first `q` bytes of the returned buffer).
#[allow(clippy::too_many_arguments)]
fn seal_core(
    encrypt_block: &dyn Fn(&[u8; MAX_BLOCK]) -> [u8; MAX_BLOCK],
    block_len: usize,
    ccm_nb: usize,
    q: usize,
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; MAX_BLOCK], CcmError> {
    if buf.is_empty() {
        return Err(CcmError::EmptyPlaintext);
    }
    if buf.len() > MAX_PLAINTEXT_LEN {
        return Err(CcmError::PlaintextTooLong);
    }
    if aad.len() > MAX_AAD_LEN {
        return Err(CcmError::AadTooLong);
    }

    let raw_tag = compute_tag(encrypt_block, block_len, ccm_nb, q, nonce, aad, buf);

    let mut nonce_block = [0u8; MAX_BLOCK];
    nonce_block[..block_len].copy_from_slice(&nonce[..block_len]);
    let mut gamma = Gamma::new(block_len, &nonce_block, encrypt_block);

    gamma.apply(buf, encrypt_block);

    let mut tag_buf = [0u8; MAX_BLOCK];
    tag_buf[..q].copy_from_slice(&raw_tag[..q]);
    gamma.apply(&mut tag_buf[..q], encrypt_block);

    Ok(tag_buf)
}

/// Shared core behind every variant's `open_in_place`. Decrypts `buf` in place (tentatively),
/// recomputes the tag over the recovered plaintext, and only leaves the recovered plaintext in
/// `buf` if the recomputed tag matches - on mismatch, `buf` is zeroed before returning `Err`, so a
/// caller can never observe unverified plaintext even transiently (`CLAUDE.md`'s "no secret
/// material" discipline, generalized to "no unverified plaintext" for AEAD).
#[allow(clippy::too_many_arguments)]
fn open_core(
    encrypt_block: &dyn Fn(&[u8; MAX_BLOCK]) -> [u8; MAX_BLOCK],
    block_len: usize,
    ccm_nb: usize,
    q: usize,
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), CcmError> {
    if buf.is_empty() {
        return Err(CcmError::EmptyPlaintext);
    }
    if buf.len() > MAX_PLAINTEXT_LEN {
        return Err(CcmError::PlaintextTooLong);
    }
    if aad.len() > MAX_AAD_LEN {
        return Err(CcmError::AadTooLong);
    }

    let mut nonce_block = [0u8; MAX_BLOCK];
    nonce_block[..block_len].copy_from_slice(&nonce[..block_len]);
    let mut gamma = Gamma::new(block_len, &nonce_block, encrypt_block);

    gamma.apply(buf, encrypt_block);

    let mut recovered_tag = [0u8; MAX_BLOCK];
    recovered_tag[..q].copy_from_slice(&tag[..q]);
    gamma.apply(&mut recovered_tag[..q], encrypt_block);

    let expected_tag = compute_tag(encrypt_block, block_len, ccm_nb, q, nonce, aad, buf);

    let ok: bool = recovered_tag[..q].ct_eq(&expected_tag[..q]).into();
    if ok {
        Ok(())
    } else {
        buf.zeroize();
        Err(CcmError::TagMismatch)
    }
}

macro_rules! kalyna_ccm_variant {
    ($name:ident, $expanded:ident, $key_bytes:literal, $block_bytes:literal, $ccm_nb:literal, $q:literal) => {
        #[doc = concat!(
            "CCM mode over [`super::kalyna::", stringify!($expanded), "`] - see the module doc ",
            "comment for the construction citation and its standard alignment (D-205)."
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

            fn encrypt_block_padded(&self, block: &[u8; MAX_BLOCK]) -> [u8; MAX_BLOCK] {
                let mut input = [0u8; $block_bytes];
                input.copy_from_slice(&block[..$block_bytes]);
                let out = self.key.encrypt_block(&input);
                let mut padded = [0u8; MAX_BLOCK];
                padded[..$block_bytes].copy_from_slice(&out);
                padded
            }

            /// Encrypts `buf` in place (plaintext -> ciphertext) and returns the masked
            /// authentication tag. `nonce` must never repeat under the same key - see the module
            /// doc comment's "Nonce" section for the recommended generation strategy
            /// (`docs/DECISIONS.md` D-40) and this variant's safe per-key message-count margin.
            ///
            /// # Errors
            ///
            /// Returns `Err` if `buf` or `aad` exceed the sourced length limit (see the module
            /// doc comment's "Hard length limit" section) - never silently truncates.
            pub fn seal_in_place(
                &self,
                nonce: &[u8; $block_bytes],
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<[u8; $q], CcmError> {
                let encrypt_block = |b: &[u8; MAX_BLOCK]| self.encrypt_block_padded(b);
                let tag = seal_core(
                    &encrypt_block,
                    $block_bytes,
                    $ccm_nb,
                    $q,
                    nonce,
                    aad,
                    buf,
                )?;
                let mut out = [0u8; $q];
                out.copy_from_slice(&tag[..$q]);
                Ok(out)
            }

            /// Decrypts `buf` in place (ciphertext -> plaintext) only if `tag` verifies. On
            /// failure, `buf` is zeroed before returning `Err` - the caller can never observe
            /// unverified plaintext.
            ///
            /// # Errors
            ///
            /// Returns `Err(CcmError::TagMismatch)` if authentication fails, or a length error
            /// under the same conditions as [`Self::seal_in_place`].
            pub fn open_in_place(
                &self,
                nonce: &[u8; $block_bytes],
                aad: &[u8],
                buf: &mut [u8],
                tag: &[u8; $q],
            ) -> Result<(), CcmError> {
                let encrypt_block = |b: &[u8; MAX_BLOCK]| self.encrypt_block_padded(b);
                open_core(
                    &encrypt_block,
                    $block_bytes,
                    $ccm_nb,
                    $q,
                    nonce,
                    aad,
                    buf,
                    tag,
                )
            }
        }
    };
}

kalyna_ccm_variant!(Kalyna128_128Ccm, Kalyna128_128ExpandedKey, 16, 16, 4, 16);
kalyna_ccm_variant!(Kalyna128_256Ccm, Kalyna128_256ExpandedKey, 32, 16, 4, 16);
kalyna_ccm_variant!(Kalyna256_256Ccm, Kalyna256_256ExpandedKey, 32, 32, 4, 16);
kalyna_ccm_variant!(Kalyna256_512Ccm, Kalyna256_512ExpandedKey, 64, 32, 6, 32);
kalyna_ccm_variant!(Kalyna512_512Ccm, Kalyna512_512ExpandedKey, 64, 64, 8, 64);
