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

use super::tables::{apply_matrix, MDS_INV_MATRIX, MDS_MATRIX, ROWS, SBOXES, SBOXES_DEC};

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

/// One encryption round: eta -> pi -> tau (`EncipherRound` in the oracle).
fn encipher_round(state: &mut [Column]) {
    sub_bytes(state);
    shift_rows(state);
    apply_matrix(state, &MDS_MATRIX);
}

/// One decryption round, run in reverse: tau^-1 -> pi^-1 -> eta^-1 (`DecipherRound`).
fn decipher_round(state: &mut [Column]) {
    apply_matrix(state, &MDS_INV_MATRIX);
    inv_shift_rows(state);
    inv_sub_bytes(state);
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

fn key_expand(key: &[u8], nb: usize, nk: usize, nr: usize) -> [[Column; MAX_NB]; ROUND_KEYS_LEN] {
    let kt = key_expand_kt(key, nb, nk);
    let mut round_keys = [[ZERO_COLUMN; MAX_NB]; ROUND_KEYS_LEN];
    key_expand_even(key, &kt, nb, nk, nr, &mut round_keys);
    key_expand_odd(&mut round_keys, nb, nr);
    round_keys
}

/// Shared implementation for all five variants' encryption. Returns a `MAX_NB*ROWS`-byte buffer;
/// callers truncate to `nb*ROWS` (the actual block size).
fn encrypt_generic(
    key: &[u8],
    plaintext: &[u8],
    nb: usize,
    nk: usize,
    nr: usize,
) -> [u8; MAX_NB * ROWS] {
    let round_keys = key_expand(key, nb, nk, nr);
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

/// Shared implementation for all five variants' decryption. See `encrypt_generic`.
fn decrypt_generic(
    key: &[u8],
    ciphertext: &[u8],
    nb: usize,
    nk: usize,
    nr: usize,
) -> [u8; MAX_NB * ROWS] {
    let round_keys = key_expand(key, nb, nk, nr);
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

macro_rules! kalyna_variant {
    ($name:ident, $key_bytes:literal, $block_bytes:literal, $nb:literal, $nk:literal, $nr:literal) => {
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
    };
}

kalyna_variant!(Kalyna128_128, 16, 16, 2, 2, 10);
kalyna_variant!(Kalyna128_256, 32, 16, 2, 4, 14);
kalyna_variant!(Kalyna256_256, 32, 32, 4, 4, 14);
kalyna_variant!(Kalyna256_512, 64, 32, 4, 8, 18);
kalyna_variant!(Kalyna512_512, 64, 64, 8, 8, 18);
