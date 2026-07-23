//! Kalyna block cipher (DSTU 7624:2014), all five block/key-size variants.
//!
//! Ported from `docs/pseudocode/kalyna.md` (itself transcribed from the designers' paper,
//! `docs/papers/Kalyna.pdf` Sections 3-7) and structurally mirrors
//! `oracles/kalyna-reference/kalyna.c` (Roman Oliynykov et al., verify-only, no license - see
//! `ORACLES.md`) round-for-round and key-schedule-step-for-step. Shares its S-box/MDS tables
//! with `hazmat::kupyna` via `hazmat::tables` (see `DECISIONS.md` D-10 for the byte-identity
//! cross-check). Citation and verification status: `DECISIONS.md` D-13.
//!
//! Only single-block encrypt/decrypt is provided here - no mode of operation, no padding. A mode
//! (`crypto_secretbox`-equivalent) is a separate, higher-level primitive - see `DECISIONS.md` D-05
//! and `docs/dstu-crypto-project.md` "Concrete API shape".

use super::tables::{
    apply_inverse_matrix, forward_sbox_mds, inverse_sbox_mds, ROWS, SBOXES, SBOXES_DEC,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// One 64-bit state/key word, byte-for-byte (index 0 = least-significant byte - see
/// `oracles/kalyna-reference/kalyna.c` `SubBytes`, which reads word bytes low-to-high against
/// `sboxes_enc[0..3]`).
type Column = [u8; ROWS];

/// Largest `nb`/`nk` (64-bit words per block/key) across all five variants - the 512/512 variant.
const MAX_NB: usize = 8;
/// Largest round count (`nr`) across all five variants (256/512 and 512/512, both 18) plus one
/// for the post-whitening key `K_nr`.
const ROUND_KEYS_LEN: usize = 19;

const ZERO_COLUMN: Column = [0u8; ROWS];

/// S-box layer (eta): `state[col][row] <- S_{row mod 4}(state[col][row])`.
///
/// No production code path calls this directly anymore - `encipher_round` fuses this with
/// `shift_rows`/`apply_matrix` via `tables::SBOX_MDS` (D-28). Kept as the independent reference
/// `tests::fused_encipher_round_matches_naive` checks the fused round against (same "kept for the
/// exhaustive/property test, invisible to `cargo clippy`'s default invocation" pattern as
/// `hazmat::tables`' `MDS_MATRIX`/`gf_mul`, D-27).
#[allow(dead_code)]
fn sub_bytes(state: &mut [Column]) {
    for column in state.iter_mut() {
        for (row, byte) in column.iter_mut().enumerate() {
            *byte = SBOXES[row % 4][*byte as usize];
        }
    }
}

/// Inverse of `sub_bytes`, used by decryption.
fn inv_sub_bytes(state: &mut [Column]) {
    for column in state.iter_mut() {
        for (row, byte) in column.iter_mut().enumerate() {
            *byte = SBOXES_DEC[row % 4][*byte as usize];
        }
    }
}

/// Row permutation (pi): row `r` rotated right by `⌊r·nb/8⌋` columns, `nb` = `state.len()`
/// (`docs/pseudocode/kalyna.md` "Building blocks", cross-checked against the oracle's `ShiftRows`
/// group-size derivation).
///
/// No production code path calls this directly anymore - see `sub_bytes`'s doc comment, same
/// "kept for the fused-round reference test" reasoning (D-28).
#[allow(dead_code)]
fn shift_rows(state: &mut [Column]) {
    let nb = state.len();
    let mut shifted = [ZERO_COLUMN; MAX_NB];
    for row in 0..ROWS {
        let shift = row * nb / ROWS;
        for col in 0..nb {
            shifted[(col + shift) % nb][row] = state[col][row];
        }
    }
    state.copy_from_slice(&shifted[..nb]);
}

/// Inverse of `shift_rows`.
fn inv_shift_rows(state: &mut [Column]) {
    let nb = state.len();
    let mut shifted = [ZERO_COLUMN; MAX_NB];
    for row in 0..ROWS {
        let shift = row * nb / ROWS;
        for col in 0..nb {
            shifted[col][row] = state[(col + shift) % nb][row];
        }
    }
    state.copy_from_slice(&shifted[..nb]);
}

/// Round-key addition (kappa): per-column modulo-2^64 add.
fn add_round_key(state: &mut [Column], key: &[Column]) {
    for (s, k) in state.iter_mut().zip(key) {
        let word = u64::from_le_bytes(*s).wrapping_add(u64::from_le_bytes(*k));
        *s = word.to_le_bytes();
    }
}

/// Inverse of `add_round_key` (per-column modulo-2^64 subtract).
fn sub_round_key(state: &mut [Column], key: &[Column]) {
    for (s, k) in state.iter_mut().zip(key) {
        let word = u64::from_le_bytes(*s).wrapping_sub(u64::from_le_bytes(*k));
        *s = word.to_le_bytes();
    }
}

/// Round-key addition (psi): per-column XOR, its own inverse.
fn xor_round_key(state: &mut [Column], key: &[Column]) {
    for (s, k) in state.iter_mut().zip(key) {
        for (b, kb) in s.iter_mut().zip(k) {
            *b ^= kb;
        }
    }
}

/// One encryption round: eta -> pi -> tau (`EncipherRound` in the oracle), fused into a single
/// gather-and-XOR pass over `tables::SBOX_MDS` (D-28) instead of three separate passes
/// (`sub_bytes` -> `shift_rows` -> `apply_matrix`). Valid because `sub_bytes` acts per-row and
/// `shift_rows` preserves row (only permutes columns), so the two commute: substituting a byte
/// then moving it to column `(col + shift) % nb` gives the same result as moving it first then
/// substituting. That means, for output column `out_col`, row `row`'s contribution comes from
/// input column `(out_col + nb - shift) % nb` - a plain gather, cheap arithmetic on `nb`/`shift`,
/// not a table (see `tables::build_sbox_mds`'s doc comment for why no per-`nb` tables are needed).
fn encipher_round(state: &mut [Column]) {
    let nb = state.len();
    debug_assert!(nb.is_power_of_two());
    let nb_mask = nb - 1;
    let mut result = [ZERO_COLUMN; MAX_NB];
    for (out_col, out_word) in result[..nb].iter_mut().enumerate() {
        let mut acc = 0u64;
        // `row` also drives `shift`/`src_col` and is passed to `forward_sbox_mds`, not just a
        // direct single-collection index - not a real `iter().enumerate()` candidate.
        #[allow(clippy::needless_range_loop)]
        for row in 0..ROWS {
            let shift = row * nb / ROWS;
            let src_col = (out_col + nb - shift) & nb_mask;
            let byte = state[src_col][row];
            acc ^= forward_sbox_mds(row, byte);
        }
        *out_word = acc.to_le_bytes();
    }
    state.copy_from_slice(&result[..nb]);
}

/// One decryption round, run in reverse: tau^-1 -> pi^-1 -> eta^-1 (`DecipherRound`).
///
/// No production code path calls this directly anymore - `decrypt_with_schedule` uses
/// `fused_inv_round` instead (D-30). Kept as the independent reference
/// `tests::fused_decrypt_matches_naive` checks the restructured decrypt against, same pattern as
/// `sub_bytes`/`shift_rows` above (D-28).
#[allow(dead_code)]
fn decipher_round(state: &mut [Column]) {
    apply_inverse_matrix(state);
    inv_shift_rows(state);
    inv_sub_bytes(state);
}

/// One *interior* decrypt round, restructured (D-30, `DECISIONS.md`) into the same
/// substitute-then-permute-then-mix shape as `encipher_round`, fused the same way over
/// `tables::SBOX_MDS_DEC`. Valid via the identity `IM(IP(IS(x)) XOR K) = IM(IP(IS(x))) XOR IM(K)`
/// (`IM` = the MDS-inverse mix is GF(2^8)-linear, so it distributes over XOR) combined with
/// `IS`/`IP` commuting (same row-invariance fact `encipher_round` relies on) - see D-30 for the
/// full derivation. The caller must XOR the *transformed* key `DK[j] = apply_matrix(K[j],
/// MDS_INV_TABLE)` afterward, not the original `K[j]` - see `transform_keys_for_decrypt`.
///
/// The gather direction is `inv_shift_rows`'s, not `encipher_round`'s (`shift_rows`) - opposite
/// index arithmetic, since this undoes the permutation rather than performing it: output column
/// `out_col` reads from input column `(out_col + shift) % nb`, not `(out_col - shift) % nb`.
fn fused_inv_round(state: &mut [Column]) {
    let nb = state.len();
    debug_assert!(nb.is_power_of_two());
    let nb_mask = nb - 1;
    let mut result = [ZERO_COLUMN; MAX_NB];
    for (out_col, out_word) in result[..nb].iter_mut().enumerate() {
        let mut acc = 0u64;
        // Same non-enumerate-candidate shape as `encipher_round` above.
        #[allow(clippy::needless_range_loop)]
        for row in 0..ROWS {
            let shift = row * nb / ROWS;
            let src_col = (out_col + shift) & nb_mask;
            let byte = state[src_col][row];
            acc ^= inverse_sbox_mds(row, byte);
        }
        *out_word = acc.to_le_bytes();
    }
    state.copy_from_slice(&result[..nb]);
}

/// Transforms the interior round keys (`K[1..nr]`) for use with `fused_inv_round`: `DK[j] =
/// apply_matrix(K[j], MDS_INV_TABLE)` - see `fused_inv_round`'s doc comment for why. `K[0]`/`K[nr]`
/// (the mod-2^64 whitening keys) are copied through untransformed and unused by the fused loop -
/// mod-add doesn't distribute over XOR the way the GF(2^8)-linear MDS does, so those two stay at
/// the decrypt sequence's two ends, exactly as before (D-30).
fn transform_keys_for_decrypt(round_keys: &RoundKeys, nb: usize, nr: usize) -> RoundKeys {
    let mut dec_keys = *round_keys;
    for key in dec_keys.iter_mut().take(nr).skip(1) {
        apply_inverse_matrix(&mut key[..nb]);
    }
    dec_keys
}

/// `base` sandwiched by two encipher rounds with `tmp` added/XORed/added around them - the shared
/// step used to derive both `Kt` and every even-indexed round key (`docs/pseudocode/kalyna.md`
/// "Round key generation", helper `round_key_from`).
fn round_key_from(base: &[Column], tmp: &[Column]) -> [Column; MAX_NB] {
    let nb = base.len();
    let mut state = [ZERO_COLUMN; MAX_NB];
    state[..nb].copy_from_slice(base);
    add_round_key(&mut state[..nb], tmp);
    encipher_round(&mut state[..nb]);
    xor_round_key(&mut state[..nb], tmp);
    encipher_round(&mut state[..nb]);
    add_round_key(&mut state[..nb], tmp);
    state
}

fn columns_from_bytes(bytes: &[u8], count: usize) -> [Column; MAX_NB] {
    let mut out = [ZERO_COLUMN; MAX_NB];
    for c in 0..count {
        out[c].copy_from_slice(&bytes[c * ROWS..(c + 1) * ROWS]);
    }
    out
}

/// Doubles every column of `state` independently (modulo 2^64 per word, no carry between
/// columns) - the "phi <<= 1" step. Mirrors the oracle's `ShiftLeft`, which shifts each word of
/// the buffer separately, not the buffer as one big integer.
fn shift_left_words(state: &mut [Column]) {
    for column in state.iter_mut() {
        let word = u64::from_le_bytes(*column) << 1;
        *column = word.to_le_bytes();
    }
}

/// Rotates a `count`-word buffer left by one word (`buf[0]` moves to the end). Mirrors the
/// oracle's `Rotate`.
fn rotate_words_left(buf: &mut [Column], count: usize) {
    if count == 0 {
        return;
    }
    let first = buf[0];
    for i in 1..count {
        buf[i - 1] = buf[i];
    }
    buf[count - 1] = first;
}

/// Rotates a byte buffer left by `shift` positions (mirrors the oracle's `RotateLeft`: the first
/// `shift` bytes move to the end, everything else shifts down).
fn rotate_bytes_left(buf: &mut [u8], shift: usize) {
    let len = buf.len();
    let mut rotated = [0u8; MAX_NB * ROWS];
    for (i, slot) in rotated[..len].iter_mut().enumerate() {
        *slot = buf[(i + shift) % len];
    }
    buf.copy_from_slice(&rotated[..len]);
}

/// Intermediate key `Kσ` (`docs/pseudocode/kalyna.md` "Round key generation", `KeyExpandKt` in
/// the oracle).
fn key_expand_kt(key: &[u8], nb: usize, nk: usize) -> [Column; MAX_NB] {
    let mut state = [ZERO_COLUMN; MAX_NB];
    #[allow(clippy::cast_possible_truncation)] // nb+nk+1 <= 17, always fits u64 trivially
    let tmv = (nb + nk + 1) as u64;
    state[0] = tmv.to_le_bytes();

    let k0 = columns_from_bytes(key, nb);
    let k1 = if nk == nb {
        k0
    } else {
        columns_from_bytes(&key[nb * ROWS..], nb)
    };

    add_round_key(&mut state[..nb], &k0[..nb]);
    encipher_round(&mut state[..nb]);
    xor_round_key(&mut state[..nb], &k1[..nb]);
    encipher_round(&mut state[..nb]);
    add_round_key(&mut state[..nb], &k0[..nb]);
    encipher_round(&mut state[..nb]);
    state
}

/// Even-indexed round keys `K_0, K_2, ..., K_nr` (`docs/pseudocode/kalyna.md` "Round key
/// generation", `KeyExpandEven` in the oracle). The `k = 2l` branch (`nk != nb`) produces two
/// round keys per outer step - one from each half of the key buffer - but rotates the combined
/// buffer only once per step; see the pseudocode doc's "Correction on provenance" for how this
/// was cross-checked.
fn key_expand_even(
    key: &[u8],
    kt: &[Column; MAX_NB],
    nb: usize,
    nk: usize,
    nr: usize,
    round_keys: &mut [[Column; MAX_NB]; ROUND_KEYS_LEN],
) {
    let mut initial_data = columns_from_bytes(key, nk);
    let mut tmv = [ZERO_COLUMN; MAX_NB];
    for column in &mut tmv[..nb] {
        *column = 0x0001_0001_0001_0001u64.to_le_bytes();
    }

    let mut round = 0usize;
    loop {
        let kt_round = mod_add_columns(&kt[..nb], &tmv[..nb]);
        let key_a = round_key_from(&initial_data[..nb], &kt_round[..nb]);
        round_keys[round][..nb].copy_from_slice(&key_a[..nb]);
        if round == nr {
            break;
        }

        if nk != nb {
            round += 2;
            shift_left_words(&mut tmv[..nb]);
            let kt_round = mod_add_columns(&kt[..nb], &tmv[..nb]);
            let key_b = round_key_from(&initial_data[nb..nk], &kt_round[..nb]);
            round_keys[round][..nb].copy_from_slice(&key_b[..nb]);
            if round == nr {
                break;
            }
        }

        round += 2;
        shift_left_words(&mut tmv[..nb]);
        rotate_words_left(&mut initial_data[..nk], nk);
    }
}

fn mod_add_columns(a: &[Column], b: &[Column]) -> [Column; MAX_NB] {
    let mut out = [ZERO_COLUMN; MAX_NB];
    for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b)) {
        let word = u64::from_le_bytes(*x).wrapping_add(u64::from_le_bytes(*y));
        *o = word.to_le_bytes();
    }
    out
}

/// Odd-indexed round keys `K_1, K_3, ..., K_{nr-1}` (`docs/pseudocode/kalyna.md` "Round key
/// generation", `KeyExpandOdd` in the oracle): each is the even key below it, byte-rotated left
/// by `2*nb+3`.
fn key_expand_odd(round_keys: &mut [[Column; MAX_NB]; ROUND_KEYS_LEN], nb: usize, nr: usize) {
    let mut i = 1;
    while i < nr {
        let previous = round_keys[i - 1];
        round_keys[i][..nb].copy_from_slice(&previous[..nb]);

        let mut bytes = [0u8; MAX_NB * ROWS];
        let len = nb * ROWS;
        for c in 0..nb {
            bytes[c * ROWS..(c + 1) * ROWS].copy_from_slice(&round_keys[i][c]);
        }
        rotate_bytes_left(&mut bytes[..len], 2 * nb + 3);
        for c in 0..nb {
            round_keys[i][c].copy_from_slice(&bytes[c * ROWS..(c + 1) * ROWS]);
        }

        i += 2;
    }
}

fn key_expand(key: &[u8], nb: usize, nk: usize, nr: usize) -> RoundKeys {
    let kt = key_expand_kt(key, nb, nk);
    let mut round_keys = [[ZERO_COLUMN; MAX_NB]; ROUND_KEYS_LEN];
    key_expand_even(key, &kt, nb, nk, nr, &mut round_keys);
    key_expand_odd(&mut round_keys, nb, nr);
    round_keys
}

type RoundKeys = [[Column; MAX_NB]; ROUND_KEYS_LEN];

/// Runs the encryption rounds against an already-expanded key schedule - shared by
/// `encrypt_generic` (expands, uses once, zeroizes) and `ExpandedKey::encrypt_block` (reuses a
/// cached schedule across many calls, D-28 stage 3). Returns a `MAX_NB*ROWS`-byte buffer; callers
/// truncate to `nb*ROWS` (the actual block size).
fn encrypt_with_schedule(
    round_keys: &RoundKeys,
    plaintext: &[u8],
    nb: usize,
    nr: usize,
) -> [u8; MAX_NB * ROWS] {
    let mut state = columns_from_bytes(plaintext, nb);

    add_round_key(&mut state[..nb], &round_keys[0][..nb]);
    for round_key in &round_keys[1..nr] {
        encipher_round(&mut state[..nb]);
        xor_round_key(&mut state[..nb], &round_key[..nb]);
    }
    encipher_round(&mut state[..nb]);
    add_round_key(&mut state[..nb], &round_keys[nr][..nb]);

    let mut out = [0u8; MAX_NB * ROWS];
    for c in 0..nb {
        out[c * ROWS..(c + 1) * ROWS].copy_from_slice(&state[c]);
    }
    out
}

/// Runs the decryption rounds against an already-expanded key schedule and its `dec_keys`
/// transform (`transform_keys_for_decrypt`) - the equivalent-inverse-cipher restructuring, D-30.
/// `round_keys[0]`/`round_keys[nr]` (untransformed) are used for the two whitening steps at the
/// ends; `dec_keys[1..nr]` (transformed) are used by the fused interior rounds.
fn decrypt_with_schedule(
    round_keys: &RoundKeys,
    dec_keys: &RoundKeys,
    ciphertext: &[u8],
    nb: usize,
    nr: usize,
) -> [u8; MAX_NB * ROWS] {
    let mut state = columns_from_bytes(ciphertext, nb);

    sub_round_key(&mut state[..nb], &round_keys[nr][..nb]);
    apply_inverse_matrix(&mut state[..nb]);
    for dec_key in dec_keys[1..nr].iter().rev() {
        fused_inv_round(&mut state[..nb]);
        xor_round_key(&mut state[..nb], &dec_key[..nb]);
    }
    inv_shift_rows(&mut state[..nb]);
    inv_sub_bytes(&mut state[..nb]);
    sub_round_key(&mut state[..nb], &round_keys[0][..nb]);

    let mut out = [0u8; MAX_NB * ROWS];
    for c in 0..nb {
        out[c * ROWS..(c + 1) * ROWS].copy_from_slice(&state[c]);
    }
    out
}

/// Shared implementation for all five variants' encryption: expands the key, runs the rounds,
/// zeroizes the one-shot schedule. Returns a `MAX_NB*ROWS`-byte buffer; callers truncate to
/// `nb*ROWS` (the actual block size). See `ExpandedKey` (D-28 stage 3) for callers that need to
/// encrypt/decrypt many blocks under the same key without redoing `key_expand` every time.
fn encrypt_generic(
    key: &[u8],
    plaintext: &[u8],
    nb: usize,
    nk: usize,
    nr: usize,
) -> [u8; MAX_NB * ROWS] {
    let mut round_keys = key_expand(key, nb, nk, nr);
    let out = encrypt_with_schedule(&round_keys, plaintext, nb, nr);
    // Last use of the derived key schedule - clear it rather than leave it for whatever the
    // stack slot holds next (see SECURITY.md's Zeroize/ZeroizeOnDrop hard constraint, DECISIONS.md
    // D-20). A plain overwrite could be optimized away as a dead store since the array is about to
    // go out of scope anyway; `zeroize()` uses a volatile write specifically to prevent that.
    round_keys.zeroize();
    out
}

/// Shared implementation for all five variants' decryption. See `encrypt_generic`.
fn decrypt_generic(
    key: &[u8],
    ciphertext: &[u8],
    nb: usize,
    nk: usize,
    nr: usize,
) -> [u8; MAX_NB * ROWS] {
    let mut round_keys = key_expand(key, nb, nk, nr);
    let mut dec_keys = transform_keys_for_decrypt(&round_keys, nb, nr);
    let out = decrypt_with_schedule(&round_keys, &dec_keys, ciphertext, nb, nr);
    round_keys.zeroize();
    dec_keys.zeroize();
    out
}

macro_rules! kalyna_variant {
    ($name:ident, $expanded_name:ident, $key_bytes:literal, $block_bytes:literal, $nb:literal, $nk:literal, $nr:literal) => {
        #[doc = concat!(
                            stringify!($block_bytes), "-byte block, ", stringify!($key_bytes),
                            "-byte key, ", stringify!($nr), " rounds."
                        )]
        pub struct $name;

        impl $name {
            /// Encrypts one block.
            #[must_use]
            pub fn encrypt(
                key: &[u8; $key_bytes],
                block: &[u8; $block_bytes],
            ) -> [u8; $block_bytes] {
                let out = encrypt_generic(key, block, $nb, $nk, $nr);
                let mut result = [0u8; $block_bytes];
                result.copy_from_slice(&out[..$block_bytes]);
                result
            }

            /// Decrypts one block.
            #[must_use]
            pub fn decrypt(
                key: &[u8; $key_bytes],
                block: &[u8; $block_bytes],
            ) -> [u8; $block_bytes] {
                let out = decrypt_generic(key, block, $nb, $nk, $nr);
                let mut result = [0u8; $block_bytes];
                result.copy_from_slice(&out[..$block_bytes]);
                result
            }
        }

        #[doc = concat!(
            "Cached round-key schedule for [`", stringify!($name), "`] - `key_expand` runs once, ",
            "in [`new`](Self::new), instead of once per [`encrypt`](Self::encrypt_block)/",
            "[`decrypt`](Self::decrypt_block) call. Use this instead of the raw `", stringify!($name),
            "::encrypt`/`decrypt` functions whenever multiple blocks are encrypted/decrypted under ",
            "the same key - `TASKS.md` D-28 stage 3: on this project's own measurements, the ",
            "schedule was ~60-79% of ", stringify!($name), "'s single-call time, so reusing it ",
            "across calls is the largest remaining lever against re-expanding it every time."
        )]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $expanded_name {
            round_keys: RoundKeys,
            /// `transform_keys_for_decrypt`'s output (D-30) - precomputed here, not per
            /// `decrypt_block` call, so caching the schedule doesn't reintroduce `nr - 1`
            /// `apply_matrix` calls into every decrypt.
            dec_keys: RoundKeys,
        }

        impl $expanded_name {
            /// Expands `key` once. Reuse the returned value for as many blocks as needed under
            /// this key; drop it (or let it go out of scope) once done, which zeroizes the cached
            /// schedule the same way the raw `encrypt`/`decrypt` functions already zeroize theirs.
            #[must_use]
            pub fn new(key: &[u8; $key_bytes]) -> Self {
                let round_keys = key_expand(key, $nb, $nk, $nr);
                let dec_keys = transform_keys_for_decrypt(&round_keys, $nb, $nr);
                Self {
                    round_keys,
                    dec_keys,
                }
            }

            /// Encrypts one block using the cached schedule - no `key_expand` call.
            #[must_use]
            pub fn encrypt_block(&self, block: &[u8; $block_bytes]) -> [u8; $block_bytes] {
                let out = encrypt_with_schedule(&self.round_keys, block, $nb, $nr);
                let mut result = [0u8; $block_bytes];
                result.copy_from_slice(&out[..$block_bytes]);
                result
            }

            /// Decrypts one block using the cached schedule - no `key_expand` call.
            #[must_use]
            pub fn decrypt_block(&self, block: &[u8; $block_bytes]) -> [u8; $block_bytes] {
                let out = decrypt_with_schedule(&self.round_keys, &self.dec_keys, block, $nb, $nr);
                let mut result = [0u8; $block_bytes];
                result.copy_from_slice(&out[..$block_bytes]);
                result
            }
        }
    };
}

kalyna_variant!(Kalyna128_128, Kalyna128_128ExpandedKey, 16, 16, 2, 2, 10);
kalyna_variant!(Kalyna128_256, Kalyna128_256ExpandedKey, 32, 16, 2, 4, 14);
kalyna_variant!(Kalyna256_256, Kalyna256_256ExpandedKey, 32, 32, 4, 4, 14);
kalyna_variant!(Kalyna256_512, Kalyna256_512ExpandedKey, 64, 32, 4, 8, 18);
kalyna_variant!(Kalyna512_512, Kalyna512_512ExpandedKey, 64, 64, 8, 8, 18);

#[cfg(test)]
mod fused_round_tests {
    use super::{encipher_round, shift_rows, sub_bytes, Column, MAX_NB, ZERO_COLUMN};
    use crate::hazmat::tables::apply_forward_matrix;
    use proptest::prelude::*;

    /// The pre-D-28 three-pass form, kept only here as the independent reference the fused
    /// `encipher_round` is checked against.
    fn naive_encipher_round(state: &mut [Column]) {
        sub_bytes(state);
        shift_rows(state);
        apply_forward_matrix(state);
    }

    fn arb_state(nb: usize) -> impl Strategy<Value = Vec<Column>> {
        proptest::collection::vec(proptest::array::uniform8(any::<u8>()), nb)
    }

    proptest! {
        #[test]
        fn fused_encipher_round_matches_naive_nb2(state in arb_state(2)) {
            let mut fused = [ZERO_COLUMN; MAX_NB];
            fused[..2].copy_from_slice(&state);
            let mut naive = fused;
            encipher_round(&mut fused[..2]);
            naive_encipher_round(&mut naive[..2]);
            prop_assert_eq!(fused, naive);
        }

        #[test]
        fn fused_encipher_round_matches_naive_nb4(state in arb_state(4)) {
            let mut fused = [ZERO_COLUMN; MAX_NB];
            fused[..4].copy_from_slice(&state);
            let mut naive = fused;
            encipher_round(&mut fused[..4]);
            naive_encipher_round(&mut naive[..4]);
            prop_assert_eq!(fused, naive);
        }

        #[test]
        fn fused_encipher_round_matches_naive_nb8(state in arb_state(8)) {
            let mut fused = [ZERO_COLUMN; MAX_NB];
            fused[..8].copy_from_slice(&state);
            let mut naive = fused;
            encipher_round(&mut fused[..8]);
            naive_encipher_round(&mut naive[..8]);
            prop_assert_eq!(fused, naive);
        }
    }
}

/// D-30's equivalent-inverse-cipher restructuring is a much less obvious transform than D-28's
/// forward fusion (it moves *where* each round key is applied, not just how a round is computed) -
/// checked here against the untransformed decrypt (`decipher_round`, still `#[allow(dead_code)]`
/// in production) over random round-key schedules and ciphertexts, not just the fixed key
/// schedules real vectors happen to produce.
#[cfg(test)]
mod decrypt_fusion_tests {
    use super::{
        columns_from_bytes, decipher_round, decrypt_with_schedule, sub_round_key,
        transform_keys_for_decrypt, xor_round_key, Column, MAX_NB, ROUND_KEYS_LEN, ROWS,
        ZERO_COLUMN,
    };
    use proptest::prelude::*;

    type RoundKeys = [[Column; MAX_NB]; ROUND_KEYS_LEN];

    /// The pre-D-30 form (three-pass `decipher_round`, untransformed keys), kept only here as the
    /// independent reference the restructured `decrypt_with_schedule` is checked against.
    fn naive_decrypt_with_schedule(
        round_keys: &RoundKeys,
        ciphertext: &[u8],
        nb: usize,
        nr: usize,
    ) -> [u8; MAX_NB * ROWS] {
        let mut state = columns_from_bytes(ciphertext, nb);
        sub_round_key(&mut state[..nb], &round_keys[nr][..nb]);
        for round_key in round_keys[1..nr].iter().rev() {
            decipher_round(&mut state[..nb]);
            xor_round_key(&mut state[..nb], &round_key[..nb]);
        }
        decipher_round(&mut state[..nb]);
        sub_round_key(&mut state[..nb], &round_keys[0][..nb]);

        let mut out = [0u8; MAX_NB * ROWS];
        for c in 0..nb {
            out[c * ROWS..(c + 1) * ROWS].copy_from_slice(&state[c]);
        }
        out
    }

    fn arb_round_key_bytes(nb: usize, nr: usize) -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), (nr + 1) * nb * ROWS)
    }

    fn arb_block(nb: usize) -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), nb * ROWS)
    }

    macro_rules! fusion_matches_naive_test {
        ($test_name:ident, $nb:literal, $nr:literal) => {
            proptest! {
                #[test]
                fn $test_name(
                    key_bytes in arb_round_key_bytes($nb, $nr),
                    ciphertext in arb_block($nb),
                ) {
                    let mut round_keys: RoundKeys = [[ZERO_COLUMN; MAX_NB]; ROUND_KEYS_LEN];
                    for i in 0..=$nr {
                        let start = i * $nb * ROWS;
                        round_keys[i] = columns_from_bytes(&key_bytes[start..start + $nb * ROWS], $nb);
                    }

                    let dec_keys = transform_keys_for_decrypt(&round_keys, $nb, $nr);
                    let naive = naive_decrypt_with_schedule(&round_keys, &ciphertext, $nb, $nr);
                    let fused = decrypt_with_schedule(&round_keys, &dec_keys, &ciphertext, $nb, $nr);
                    prop_assert_eq!(naive, fused);
                }
            }
        };
    }

    fusion_matches_naive_test!(decrypt_fusion_matches_naive_nb2_nr10, 2, 10);
    fusion_matches_naive_test!(decrypt_fusion_matches_naive_nb4_nr14, 4, 14);
    fusion_matches_naive_test!(decrypt_fusion_matches_naive_nb4_nr18, 4, 18);
    fusion_matches_naive_test!(decrypt_fusion_matches_naive_nb8_nr18, 8, 18);
}
