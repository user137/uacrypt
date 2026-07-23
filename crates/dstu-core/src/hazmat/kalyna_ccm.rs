//! Kalyna-CCM: a provisional, Kalyna-alone authenticated mode of operation (DSTU 7624:2014 CCM).
//!
//! **Provisional, not confirmed against the primary DSTU 7624:2014 text** - the same posture as
//! Strumok's UAPKI-attributed vectors (`DECISIONS.md` D-15). Ported directly from
//! `oracles/uapki/library/uapkic/src/dstu7624.c` (`dstu7624_init_ccm` at line 4139, `ccm_padd` at
//! line 2621, `dstu7624_encrypt_ccm`/`dstu7624_decrypt_ccm` at lines 2792/2849), cross-checked
//! against `oracles/bouncycastle-java`'s `DSTU7624Test.java` CCM vectors byte-for-byte (BC's own
//! `KCCMBlockCipher` Java source is not present in this project's sparse vendored checkout, so the
//! cross-check is against BC's *vector outputs* only, not a second reading of BC's construction
//! code - a materially weaker claim than "read both implementations", stated explicitly here per
//! `CLAUDE.md`'s citation discipline). See `DECISIONS.md` D-05 (revised) and D-41 for the full
//! citation and the reasoning for choosing this construction over encrypt-then-MAC.
//!
//! This module is a standalone hazmat-level primitive, not the eventual `crypto_secretbox`
//! (`TASKS.md` T-36/T-37, still blocked on D-05's primary-text confirmation).
//!
//! # Hard length limit - sourced, not chosen
//!
//! `ccm_padd`'s authentication header encodes both the plaintext length and the AAD length as a
//! single byte each (`G1[tmp] = (uint8_t) p_data_len`, `G2[0] = (uint8_t) a_data_len`) - so this
//! exact construction, as extracted, only correctly authenticates messages where **both plaintext
//! and AAD are at most 255 bytes**. This is a property of the source, not a design choice made
//! here; [`MAX_PLAINTEXT_LEN`]/[`MAX_AAD_LEN`] enforce it and [`seal`]/[`open`] reject anything
//! longer rather than silently truncating the length field. It is also, concretely, why this is a
//! *short-message* mode.
//!
//! # Nonce
//!
//! The nonce is a full block-size buffer (matching the vectors, which supply a full-block IV even
//! though `ccm_padd` only consumes a `block_len - ccm_nb - 1`-byte prefix of it for the
//! authentication header - the remaining bytes still feed the CTR keystream). **Nonce-generation
//! strategy (internal counter vs. wide random value) and the exact `(ccm_nb, q)` safe-default
//! rationale are deferred to their own follow-up task** (`TASKS.md`, next unused ID after this
//! module's) - the five `(ccm_nb, q)` pairs used here are exactly what the cross-oracle vectors
//! confirm, not a new choice made by this module.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const MAX_BLOCK: usize = 64;
/// Sourced limit - see the module doc comment's "Hard length limit" section.
pub const MAX_PLAINTEXT_LEN: usize = 255;
/// Sourced limit - see the module doc comment's "Hard length limit" section.
pub const MAX_AAD_LEN: usize = 255;

/// `ccm_padd`'s two fixed header blocks (`G1`, `G2`), zero-padded so `G2`'s slice length rounds
/// its length byte + AAD up to a block boundary, plus room for `MAX_AAD_LEN` bytes of AAD.
const H_BUF_LEN: usize = 2 * MAX_BLOCK + MAX_AAD_LEN;
/// Plaintext plus at most one block of `padding`'s 0x80-then-zeros pad.
const P_BUF_LEN: usize = MAX_PLAINTEXT_LEN + MAX_BLOCK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcmError {
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

/// `ccm_padd` (`dstu7624.c:2621`): builds the CBC-MAC authentication header (`G1`/`G2`) and runs
/// the CBC-MAC (repeated XOR-then-encrypt) over header || AAD || padded-plaintext. Returns a
/// `MAX_BLOCK`-byte buffer whose first `q` bytes are the raw (unmasked) tag.
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
    let tmp = block_len - ccm_nb - 1;

    let mut g1 = [0u8; MAX_BLOCK];
    g1[..tmp].copy_from_slice(&nonce[..tmp]);
    #[allow(clippy::cast_possible_truncation)] // sourced limit: plaintext.len() <= 255
    {
        g1[tmp] = plaintext.len() as u8;
    }
    let mut flags = if plaintext.is_empty() { 0u8 } else { 0x80 };
    flags |= tag_length_code(q) << 4;
    #[allow(clippy::cast_possible_truncation)] // ccm_nb is always one of {4,6,8}, fits easily
    {
        flags |= (ccm_nb - 1) as u8;
    }
    g1[block_len - 1] = flags;

    let mut g2 = [0u8; MAX_BLOCK];
    #[allow(clippy::cast_possible_truncation)] // sourced limit: aad.len() <= 255
    {
        g2[0] = aad.len() as u8;
    }

    let aad_rem = aad.len() % block_len;
    let g2_len = block_len - aad_rem;

    let mut h_buf = [0u8; H_BUF_LEN];
    let mut h_len = 0usize;
    h_buf[h_len..h_len + block_len].copy_from_slice(&g1[..block_len]);
    h_len += block_len;
    h_buf[h_len..h_len + g2_len].copy_from_slice(&g2[..g2_len]);
    h_len += g2_len;
    h_buf[h_len..h_len + aad.len()].copy_from_slice(aad);
    h_len += aad.len();

    let mut b = [0u8; MAX_BLOCK];
    let mut offset = 0usize;
    while offset < h_len {
        for i in 0..block_len {
            b[i] ^= h_buf[offset + i];
        }
        b = encrypt_block(&b);
        offset += block_len;
    }

    let mut p_buf = [0u8; P_BUF_LEN];
    p_buf[..plaintext.len()].copy_from_slice(plaintext);
    let mut p_len = plaintext.len();
    if !p_len.is_multiple_of(block_len) {
        p_buf[p_len] = 0x80;
        p_len += block_len - (p_len % block_len);
    }
    offset = 0;
    while offset < p_len {
        for i in 0..block_len {
            b[i] ^= p_buf[offset + i];
        }
        b = encrypt_block(&b);
        offset += block_len;
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
            "comment for the construction citation and its provisional status."
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
            /// authentication tag. `nonce` must never repeat under the same key (see the module
            /// doc comment - nonce-generation strategy is deferred to its own follow-up task).
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
