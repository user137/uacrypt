//! Kupyna hash function (DSTU 7564:2014).
//!
//! Ported from `docs/pseudocode/kupyna.md` (itself transcribed from the designers' paper,
//! `docs/papers/Kupyna.pdf` Sections 4-6) and structurally mirrors
//! `oracles/kupyna-reference/kupyna.c` (Roman Oliynykov) byte-matrix-for-byte-matrix, rather than
//! the T-table-fused optimization Bouncy Castle uses — deliberately, since this port could not be
//! compiled or run locally (no Rust toolchain available; see `.claude.local.md`), and the more
//! literal translation carries less risk of an unverifiable transposition bug. Full citation and
//! verification status: `docs/DECISIONS.md` D-10.
//!
//! Only byte-aligned messages are supported - the public API takes `&[u8]`, which cannot express
//! a bit-level length anyway. This matches the extracted test vectors exactly (see the `note`
//! field in `crates/dstu-core/tests/vectors/kupyna/*.json`).

use super::tables::{apply_forward_matrix, forward_sbox_mds, ROWS, SBOXES};

const MAX_COLUMNS: usize = 16;
const MAX_BLOCK_BYTES: usize = MAX_COLUMNS * ROWS;

/// S-box layer (kappa): `state[col][row] <- S_{row mod 4}(state[col][row])`.
///
/// No production code path calls this directly anymore - `sub_shift_mix` fuses this with
/// `shift_bytes`/`mix_columns` via `tables::SBOX_MDS` (D-28). Kept as the independent reference
/// `tests::fused_sub_shift_mix_matches_naive` checks the fused round against (same pattern as
/// `hazmat::kalyna`'s `sub_bytes`/`shift_rows`, D-28, and `hazmat::tables`' `MDS_MATRIX`/`gf_mul`,
/// D-27).
#[allow(dead_code)]
fn sub_bytes(state: &mut [[u8; ROWS]]) {
    for column in state.iter_mut() {
        for (row, byte) in column.iter_mut().enumerate() {
            *byte = SBOXES[row % 4][*byte as usize];
        }
    }
}

/// Row permutation (pi): row `r` (0..=6) rotated right by `r`; the last row rotated right by
/// `last_row_shift` (7 for Kupyna-256's l=512, 11 for Kupyna-512's l=1024).
///
/// No production code path calls this directly anymore - see `sub_bytes`'s doc comment (D-28).
#[allow(dead_code)]
fn shift_bytes(state: &mut [[u8; ROWS]], last_row_shift: usize) {
    let columns = state.len();
    let mut shifted = [[0u8; ROWS]; MAX_COLUMNS];
    for row in 0..ROWS {
        let shift = if row == ROWS - 1 { last_row_shift } else { row };
        for col in 0..columns {
            shifted[(col + shift) % columns][row] = state[col][row];
        }
    }
    state[..columns].copy_from_slice(&shifted[..columns]);
}

/// Linear layer (tau): each column multiplied by the MDS matrix over GF(2^8).
///
/// No production code path calls this directly anymore - see `sub_bytes`'s doc comment (D-28).
#[allow(dead_code)]
fn mix_columns(state: &mut [[u8; ROWS]]) {
    apply_forward_matrix(state);
}

/// Fused `sub_bytes -> shift_bytes -> mix_columns`, one gather-and-XOR pass over
/// `tables::SBOX_MDS` instead of three separate passes (D-28) - see `hazmat::kalyna::encipher_
/// round`'s doc comment for why this is valid (S-box is row-indexed, the row permutation preserves
/// row, so the two commute) and why it needs no per-`columns` tables, only a cheap gather index.
///
/// No production code path calls this directly anymore as of T-134 (`docs/DECISIONS.md` D-85) -
/// `KupynaCore::compress_block`/`finalize` dispatch to the const-generic `sub_shift_mix_n` instead.
/// Kept as the independent reference `const_shift_mix_tests` checks the const-generic twin against,
/// same pattern as `sub_bytes`/`shift_bytes`/`mix_columns` above.
#[allow(dead_code)]
fn sub_shift_mix(state: &mut [[u8; ROWS]], last_row_shift: usize) {
    let columns = state.len();
    debug_assert!(columns.is_power_of_two());
    let columns_mask = columns - 1;
    let mut result = [[0u8; ROWS]; MAX_COLUMNS];
    for (out_col, out_word) in result[..columns].iter_mut().enumerate() {
        let mut acc = 0u64;
        // `row` also drives `shift`/`src_col` and is passed to `forward_sbox_mds`, not just a
        // direct single-collection index - not a real `iter().enumerate()` candidate.
        #[allow(clippy::needless_range_loop)]
        for row in 0..ROWS {
            let shift = if row == ROWS - 1 { last_row_shift } else { row };
            let src_col = (out_col + columns - shift) & columns_mask;
            let byte = state[src_col][row];
            acc ^= forward_sbox_mds(row, byte);
        }
        *out_word = acc.to_le_bytes();
    }
    state[..columns].copy_from_slice(&result[..columns]);
}

/// Const-generic twin of `sub_shift_mix` (T-134, direct analogue of `hazmat::kalyna`'s
/// `encipher_round_n`, `docs/DECISIONS.md` T-128/D-77) - `COLUMNS` (always 8 or 16, verified against
/// every `KupynaCore::new`/`digest_generic`/`kmac_generic` call site) is known at compile time, so
/// `result` is exactly `COLUMNS` wide (no `MAX_COLUMNS`-oversized zeroing) and every bounds check
/// on `state`/`result` is eliminated by monomorphization.
fn sub_shift_mix_n<const COLUMNS: usize>(state: &mut [[u8; ROWS]; COLUMNS], last_row_shift: usize) {
    debug_assert!(COLUMNS.is_power_of_two());
    let columns_mask = COLUMNS - 1;
    let mut result = [[0u8; ROWS]; COLUMNS];
    for (out_col, out_word) in result.iter_mut().enumerate() {
        let mut acc = 0u64;
        #[allow(clippy::needless_range_loop)]
        for row in 0..ROWS {
            let shift = if row == ROWS - 1 { last_row_shift } else { row };
            let src_col = (out_col + COLUMNS - shift) & columns_mask;
            let byte = state[src_col][row];
            acc ^= forward_sbox_mds(row, byte);
        }
        *out_word = acc.to_le_bytes();
    }
    *state = result;
}

/// XOR-based round-constant addition (psi-xor), used by `T`/`P`. Kupyna.pdf Section 6.2.
///
/// No production code path calls this directly anymore as of T-134 (`docs/DECISIONS.md` D-85) - see
/// `sub_shift_mix`'s doc comment.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)] // col < MAX_COLUMNS (16), always fits u8
fn add_round_constant_xor(state: &mut [[u8; ROWS]], round: u8) {
    for (col, column) in state.iter_mut().enumerate() {
        column[0] ^= (col as u8).wrapping_mul(0x10) ^ round;
    }
}

/// Const-generic twin of `add_round_constant_xor` - see `sub_shift_mix_n`.
#[allow(clippy::cast_possible_truncation)] // col < COLUMNS <= 16, always fits u8
fn add_round_constant_xor_n<const COLUMNS: usize>(state: &mut [[u8; ROWS]; COLUMNS], round: u8) {
    for (col, column) in state.iter_mut().enumerate() {
        column[0] ^= (col as u8).wrapping_mul(0x10) ^ round;
    }
}

/// Modulo-2^64-add round-constant addition (psi-add), used by `T+`/`Q`. Kupyna.pdf Section 6.2.
///
/// No production code path calls this directly anymore as of T-134 (`docs/DECISIONS.md` D-85) - see
/// `sub_shift_mix`'s doc comment.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)] // columns - 1 - col < MAX_COLUMNS (16), always fits u8
fn add_round_constant_add(state: &mut [[u8; ROWS]], round: u8) {
    let columns = state.len();
    for (col, column) in state.iter_mut().enumerate() {
        let top_byte = ((columns - 1 - col) as u8).wrapping_mul(0x10) ^ round;
        let addend = u64::from_le_bytes([0xF3, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, top_byte]);
        let word = u64::from_le_bytes(*column).wrapping_add(addend);
        *column = word.to_le_bytes();
    }
}

/// Const-generic twin of `add_round_constant_add` - see `sub_shift_mix_n`.
#[allow(clippy::cast_possible_truncation)] // COLUMNS - 1 - col < COLUMNS <= 16, always fits u8
fn add_round_constant_add_n<const COLUMNS: usize>(state: &mut [[u8; ROWS]; COLUMNS], round: u8) {
    for (col, column) in state.iter_mut().enumerate() {
        let top_byte = ((COLUMNS - 1 - col) as u8).wrapping_mul(0x10) ^ round;
        let addend = u64::from_le_bytes([0xF3, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, top_byte]);
        let word = u64::from_le_bytes(*column).wrapping_add(addend);
        *column = word.to_le_bytes();
    }
}

/// `T` (Kupyna.pdf Section 6.1): `rounds` iterations of xor-constant -> S-box -> shift -> mix.
///
/// No production code path calls this directly anymore as of T-134 (`docs/DECISIONS.md` D-85) - see
/// `sub_shift_mix`'s doc comment.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)] // rounds is 10 or 14 (Table 1), always fits u8
fn t_transform(state: &mut [[u8; ROWS]], rounds: usize, last_row_shift: usize) {
    for round in 0..rounds {
        add_round_constant_xor(state, round as u8);
        sub_shift_mix(state, last_row_shift);
    }
}

/// `T+` (Kupyna.pdf Section 6.1): same as `T` but with the mod-add constant.
///
/// No production code path calls this directly anymore as of T-134 (`docs/DECISIONS.md` D-85) - see
/// `sub_shift_mix`'s doc comment.
#[allow(dead_code)]
#[allow(clippy::cast_possible_truncation)] // rounds is 10 or 14 (Table 1), always fits u8
fn t_plus_transform(state: &mut [[u8; ROWS]], rounds: usize, last_row_shift: usize) {
    for round in 0..rounds {
        add_round_constant_add(state, round as u8);
        sub_shift_mix(state, last_row_shift);
    }
}

/// Const-generic twin of `t_transform` - see `sub_shift_mix_n`. `ROUNDS` is a second const generic
/// (always 10 or 14, paired one-to-one with `COLUMNS` - verified alongside `COLUMNS` itself) so the
/// round loop itself is a compile-time-known trip count, not just bounds-check elimination.
#[allow(clippy::cast_possible_truncation)] // round < ROUNDS <= 14, always fits u8
fn t_transform_n<const COLUMNS: usize, const ROUNDS: usize>(
    state: &mut [[u8; ROWS]; COLUMNS],
    last_row_shift: usize,
) {
    for round in 0..ROUNDS {
        add_round_constant_xor_n(state, round as u8);
        sub_shift_mix_n(state, last_row_shift);
    }
}

/// Const-generic twin of `t_plus_transform` - see `t_transform_n`.
#[allow(clippy::cast_possible_truncation)] // round < ROUNDS <= 14, always fits u8
fn t_plus_transform_n<const COLUMNS: usize, const ROUNDS: usize>(
    state: &mut [[u8; ROWS]; COLUMNS],
    last_row_shift: usize,
) {
    for round in 0..ROUNDS {
        add_round_constant_add_n(state, round as u8);
        sub_shift_mix_n(state, last_row_shift);
    }
}

/// One compression step: `h <- T+(m) xor T(h xor m) xor h` (Kupyna.pdf Section 4).
///
/// No production code path calls this directly anymore as of T-134 (`docs/DECISIONS.md` D-85) - see
/// `sub_shift_mix`'s doc comment.
#[allow(dead_code)]
fn compress(h: &mut [[u8; ROWS]], block: &[[u8; ROWS]], rounds: usize, last_row_shift: usize) {
    let columns = h.len();
    let mut t_input = [[0u8; ROWS]; MAX_COLUMNS];
    let mut q_input = [[0u8; ROWS]; MAX_COLUMNS];
    for col in 0..columns {
        for row in 0..ROWS {
            t_input[col][row] = h[col][row] ^ block[col][row];
            q_input[col][row] = block[col][row];
        }
    }
    t_transform(&mut t_input[..columns], rounds, last_row_shift);
    t_plus_transform(&mut q_input[..columns], rounds, last_row_shift);
    for col in 0..columns {
        for row in 0..ROWS {
            h[col][row] ^= t_input[col][row] ^ q_input[col][row];
        }
    }
}

/// Const-generic twin of `compress` - see `sub_shift_mix_n`. `t_input`/`q_input` are exactly
/// `COLUMNS` wide here (not `MAX_COLUMNS`), which is the actual "2x wasted zeroing" T-134 names for
/// Kupyna-256 (`COLUMNS=8` against a 16-wide scratch buffer) - the round-loop trip count above is
/// only half of the fix.
fn compress_n<const COLUMNS: usize, const ROUNDS: usize>(
    h: &mut [[u8; ROWS]; COLUMNS],
    block: &[[u8; ROWS]; COLUMNS],
    last_row_shift: usize,
) {
    let mut t_input = [[0u8; ROWS]; COLUMNS];
    let mut q_input = [[0u8; ROWS]; COLUMNS];
    for col in 0..COLUMNS {
        for row in 0..ROWS {
            t_input[col][row] = h[col][row] ^ block[col][row];
            q_input[col][row] = block[col][row];
        }
    }
    t_transform_n::<COLUMNS, ROUNDS>(&mut t_input, last_row_shift);
    t_plus_transform_n::<COLUMNS, ROUNDS>(&mut q_input, last_row_shift);
    for col in 0..COLUMNS {
        for row in 0..ROWS {
            h[col][row] ^= t_input[col][row] ^ q_input[col][row];
        }
    }
}

/// Splits a `block_bytes`-long byte slice into `columns` column-major 8-byte words.
///
/// No production code path calls this directly anymore as of T-134 (`docs/DECISIONS.md` D-85) - see
/// `sub_shift_mix`'s doc comment.
#[allow(dead_code)]
fn bytes_to_columns(bytes: &[u8], columns: usize) -> [[u8; ROWS]; MAX_COLUMNS] {
    let mut out = [[0u8; ROWS]; MAX_COLUMNS];
    for col in 0..columns {
        out[col].copy_from_slice(&bytes[col * ROWS..col * ROWS + ROWS]);
    }
    out
}

/// Const-generic twin of `bytes_to_columns` - see `sub_shift_mix_n`.
fn bytes_to_columns_n<const COLUMNS: usize>(bytes: &[u8]) -> [[u8; ROWS]; COLUMNS] {
    let mut out = [[0u8; ROWS]; COLUMNS];
    for (col, word) in out.iter_mut().enumerate() {
        word.copy_from_slice(&bytes[col * ROWS..col * ROWS + ROWS]);
    }
    out
}

/// Slice-to-array coercion for `KupynaCore::h`'s fixed `MAX_COLUMNS`-wide storage, needed to hand a
/// `&mut [[u8; ROWS]; COLUMNS]` into the const-generic hot path - copies `hazmat::kalyna`'s
/// `state_array_mut::<NB>` shape verbatim (`kalyna.rs:425-430`): `unreachable!` instead of
/// `.unwrap()`/`.expect()` only because `lib.rs` denies both crate-wide (D-19/SECURITY.md), not
/// because this conversion can actually fail - every call site below passes `COLUMNS` in
/// `{8, 16}`, both `<= MAX_COLUMNS`.
fn state_array_mut_kupyna<const COLUMNS: usize>(
    full: &mut [[u8; ROWS]; MAX_COLUMNS],
) -> &mut [[u8; ROWS]; COLUMNS] {
    match (&mut full[..COLUMNS]).try_into() {
        Ok(array) => array,
        Err(_) => unreachable!("KupynaCore only ever constructs COLUMNS <= MAX_COLUMNS"),
    }
}

/// Owned-copy counterpart of `state_array_mut_kupyna`, for `finalize`'s `t_final` scratch (which
/// must be independent of `self.h`, not an alias into it) - same shape, same `unreachable!`
/// rationale.
fn h_to_array<const COLUMNS: usize>(h: &[[u8; ROWS]; MAX_COLUMNS]) -> [[u8; ROWS]; COLUMNS] {
    match h[..COLUMNS].try_into() {
        Ok(array) => array,
        Err(_) => unreachable!("KupynaCore only ever constructs columns=8 or 16"),
    }
}

/// Kupyna's own padding formula (`0x80` || zero bytes || 96-bit little-endian bit-length, sized so
/// the result brings `prefix` up to a whole number of `block_bytes`-byte blocks) applied to an
/// already-buffered `prefix` with a caller-supplied bit-length field. Shared by `KupynaCore::
/// finalize`'s own padding and `hazmat::kupyna_kmac`'s two independent padding points (`PAD(K)`,
/// `PAD(M)`), which each need this formula applied with a length value other than `KupynaCore`'s
/// own running `total_len` - factored out so there is one implementation of this formula, not
/// three. Returns the padding buffer and how many of its bytes are actually used.
pub(crate) fn kupyna_padding(
    prefix: &[u8],
    msg_bits: u64,
    block_bytes: usize,
) -> ([u8; 2 * MAX_BLOCK_BYTES], usize) {
    let mut tail = [0u8; 2 * MAX_BLOCK_BYTES];
    let mut pos = prefix.len();
    tail[..pos].copy_from_slice(prefix);
    tail[pos] = 0x80;
    pos += 1;
    let used = pos + 12;
    let zero_bytes = (block_bytes - (used % block_bytes)) % block_bytes;
    pos += zero_bytes;
    tail[pos..pos + 8].copy_from_slice(&msg_bits.to_le_bytes());
    pos += 12; // upper 4 bytes of the 96-bit length field stay zero (message lengths fit in u64 bits)
    (tail, pos)
}

/// Incremental compression state shared by the one-shot `digest_generic`, the public streaming
/// `Kupyna256Hasher`/`Kupyna512Hasher` below, and `hazmat::kupyna_kmac` - `digest_generic` is now
/// just `new` + one `update` + `finalize`, so there is exactly one implementation of the
/// padding/length-tracking logic, not two. `pub(crate)` (not `pub`) since `kupyna_kmac` needs
/// direct access to feed its two independent padding points into the same running compression
/// state, a lower level of control than the public `Kupyna*Hasher` streaming API exposes.
pub(crate) struct KupynaCore {
    h: [[u8; ROWS]; MAX_COLUMNS],
    /// Bytes not yet folded into `h` - always fewer than `block_bytes()`, per `update`'s invariant.
    buffer: [u8; MAX_BLOCK_BYTES],
    buffer_len: usize,
    /// Total bytes ever passed to `update` - needed for the padding's message-length field, which
    /// `finalize` cannot otherwise recover once earlier blocks have already been compressed away.
    total_len: u64,
    columns: usize,
    /// Never read after construction as of T-134 (`docs/DECISIONS.md` D-85): `compress_block`/`finalize`
    /// now select `ROUNDS` as a const generic via the `columns` match arm instead. Kept as a
    /// stored field (not removed from `new`'s signature) to avoid rippling a breaking-signature
    /// change into `kupyna_kmac.rs`'s `kmac_generic`/`kmac_variant!` call sites, which is out of
    /// this task's scope per its own `advisor()`-reviewed plan (`KupynaCore` stays
    /// runtime-parameterized end-to-end, only its hot path is const-generic).
    #[allow(dead_code)]
    rounds: usize,
    last_row_shift: usize,
}

impl KupynaCore {
    #[allow(clippy::cast_possible_truncation)] // block_bytes is 64 or 128, always fits u8
    pub(crate) fn new(columns: usize, rounds: usize, last_row_shift: usize) -> Self {
        let block_bytes = columns * ROWS;
        let mut h = [[0u8; ROWS]; MAX_COLUMNS];
        h[0][0] = block_bytes as u8; // official IV - see docs/pseudocode/kupyna.md "Initial value"
        Self {
            h,
            buffer: [0u8; MAX_BLOCK_BYTES],
            buffer_len: 0,
            total_len: 0,
            columns,
            rounds,
            last_row_shift,
        }
    }

    pub(crate) fn block_bytes(&self) -> usize {
        self.columns * ROWS
    }

    /// The currently-buffered, not-yet-compressed tail of everything fed to `update` so far -
    /// `kupyna_kmac` needs this to correctly compute `PAD(M)`'s length-field padding relative to
    /// what's actually still buffered, the same way `finalize` below does for its own padding.
    pub(crate) fn buffered(&self) -> &[u8] {
        &self.buffer[..self.buffer_len]
    }

    /// Dispatches into the const-generic hot path (T-134, `docs/DECISIONS.md` D-85) - `self.columns` is
    /// always 8 or 16 (verified against every construction call site: `Kupyna256Hasher`/
    /// `digest_generic`/`kmac_generic` for Kupyna256/Kupyna384/Kupyna512), so this match is a
    /// one-time-per-block branch on a value that's constant for the lifetime of a given `self`, not
    /// a per-round cost - see this task's `advisor()`-reviewed plan for why `KupynaCore` itself
    /// stays runtime-parameterized rather than becoming const-generic end-to-end.
    fn compress_block(&mut self, block: &[u8]) {
        match self.columns {
            8 => {
                let columns_buf = bytes_to_columns_n::<8>(block);
                let h = state_array_mut_kupyna::<8>(&mut self.h);
                compress_n::<8, 10>(h, &columns_buf, self.last_row_shift);
            }
            16 => {
                let columns_buf = bytes_to_columns_n::<16>(block);
                let h = state_array_mut_kupyna::<16>(&mut self.h);
                compress_n::<16, 14>(h, &columns_buf, self.last_row_shift);
            }
            _ => unreachable!("KupynaCore::new only ever constructed with columns=8 or 16"),
        }
    }

    #[allow(clippy::cast_possible_truncation)] // data.len() here is always << u64::MAX
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        let block_bytes = self.block_bytes();

        if self.buffer_len > 0 {
            let take = (block_bytes - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len < block_bytes {
                // Didn't reach a full block - the only way `take` was smaller than the space
                // available is that `data` ran out, so there is nothing left to process this
                // call. Returning here (rather than falling through to the remainder-writing
                // code below) matters: that code unconditionally overwrites `buffer_len` from
                // `data`'s remainder, which would wipe out this still-partial fill.
                debug_assert!(data.is_empty());
                return;
            }
            let block = self.buffer;
            self.compress_block(&block[..block_bytes]);
            self.buffer_len = 0;
        }

        let mut full_blocks = data.chunks_exact(block_bytes);
        for block in &mut full_blocks {
            self.compress_block(block);
        }
        let remainder = full_blocks.remainder();
        self.buffer[..remainder.len()].copy_from_slice(remainder);
        self.buffer_len = remainder.len();
    }

    /// Consumes `self`: pads the buffered tail with the remaining message-length data, runs the
    /// output transformation, and returns a 64-byte buffer - callers truncate to `output_bytes`,
    /// same convention `digest_generic` used to return directly.
    pub(crate) fn finalize(mut self, output_bytes: usize) -> [u8; 64] {
        let block_bytes = self.block_bytes();

        // Padding: buffered tail || 0x80 || zero bytes || 96-bit little-endian length, sized to
        // fill whole block(s) - equivalent to the spec's bit-level `d = (-N-97) mod l` formula for
        // byte-aligned N (see docs/DECISIONS.md D-10 for the derivation).
        let msg_bits: u64 = self.total_len * 8;
        let (tail, pos) = kupyna_padding(&self.buffer[..self.buffer_len], msg_bits, block_bytes);

        let tail_blocks = pos / block_bytes;
        for i in 0..tail_blocks {
            self.compress_block(&tail[i * block_bytes..(i + 1) * block_bytes]);
        }

        // Output transformation: H = R_n(T(h_k) xor h_k) (Kupyna.pdf Section 4). Dispatches into
        // the const-generic `t_transform_n` (T-134, `docs/DECISIONS.md` D-85) - same rationale as
        // `compress_block` above: this runs once per `finalize`, not once per round, but for
        // single-block messages it's a comparable share of total work to one `compress_block`
        // call, so it gets the same treatment rather than being left on the slow path.
        //
        // Two arrays in lockstep by the same index (`self.h`/`t_final`) - same documented false
        // positive as `state_array_mut_kupyna`'s callers, D-39's established pattern.
        #[allow(clippy::needless_range_loop)]
        match self.columns {
            8 => {
                let mut t_final = h_to_array::<8>(&self.h);
                t_transform_n::<8, 10>(&mut t_final, self.last_row_shift);
                for col in 0..8 {
                    for row in 0..ROWS {
                        self.h[col][row] ^= t_final[col][row];
                    }
                }
            }
            16 => {
                let mut t_final = h_to_array::<16>(&self.h);
                t_transform_n::<16, 14>(&mut t_final, self.last_row_shift);
                for col in 0..16 {
                    for row in 0..ROWS {
                        self.h[col][row] ^= t_final[col][row];
                    }
                }
            }
            _ => unreachable!("KupynaCore only ever constructs columns=8 or 16"),
        }

        // Truncate to the `output_bytes` most-significant bytes of the column-major byte stream
        // (mirrors oracles/kupyna-reference/kupyna.c `Trunc`: copies from `state + nbytes -
        // hash_nbytes`).
        let mut flat = [0u8; MAX_BLOCK_BYTES];
        for col in 0..self.columns {
            flat[col * ROWS..(col + 1) * ROWS].copy_from_slice(&self.h[col]);
        }
        let mut out = [0u8; 64];
        out[..output_bytes].copy_from_slice(&flat[block_bytes - output_bytes..block_bytes]);
        out
    }
}

/// Shared implementation for both Kupyna variants' one-shot `digest()` - now just `KupynaCore`'s
/// `new`/`update`/`finalize` with the whole message in one `update` call.
fn digest_generic(
    message: &[u8],
    columns: usize,
    rounds: usize,
    last_row_shift: usize,
    output_bytes: usize,
) -> [u8; 64] {
    let mut core = KupynaCore::new(columns, rounds, last_row_shift);
    core.update(message);
    core.finalize(output_bytes)
}

/// Kupyna-256: 512-bit internal state, 10 rounds, 256-bit (32-byte) output.
pub struct Kupyna256;

impl Kupyna256 {
    /// Hashes `message` (byte-aligned only) and returns the 256-bit digest.
    #[must_use]
    pub fn digest(message: &[u8]) -> [u8; 32] {
        let full = digest_generic(message, 8, 10, 7, 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&full[..32]);
        out
    }
}

/// Kupyna-512: 1024-bit internal state, 14 rounds, 512-bit (64-byte) output.
pub struct Kupyna512;

impl Kupyna512 {
    /// Hashes `message` (byte-aligned only) and returns the 512-bit digest.
    #[must_use]
    pub fn digest(message: &[u8]) -> [u8; 64] {
        digest_generic(message, 16, 14, 11, 64)
    }
}

/// Streaming Kupyna-256: same construction as [`Kupyna256`], for messages fed incrementally
/// (e.g. from a reader) instead of available as one contiguous slice up front.
pub struct Kupyna256Hasher(KupynaCore);

impl Kupyna256Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self(KupynaCore::new(8, 10, 7))
    }

    /// Feeds more message bytes in. May be called any number of times, with any chunking -
    /// `Kupyna256Hasher::new().update(a); ...update(b)` is equivalent to one `update(a ++ b)`
    /// call, and both are equivalent to `Kupyna256::digest(a ++ b)`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Consumes the hasher and returns the 256-bit digest of everything fed via `update`.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        let full = self.0.finalize(32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&full[..32]);
        out
    }
}

impl Default for Kupyna256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming Kupyna-512 - see [`Kupyna256Hasher`].
pub struct Kupyna512Hasher(KupynaCore);

impl Kupyna512Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self(KupynaCore::new(16, 14, 11))
    }

    /// Feeds more message bytes in - see [`Kupyna256Hasher::update`].
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Consumes the hasher and returns the 512-bit digest of everything fed via `update`.
    #[must_use]
    pub fn finalize(self) -> [u8; 64] {
        self.0.finalize(64)
    }
}

impl Default for Kupyna512Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod fused_round_tests {
    use super::{mix_columns, shift_bytes, sub_bytes, sub_shift_mix, MAX_COLUMNS, ROWS};
    use proptest::prelude::*;

    /// The pre-D-28 three-pass form, kept only here as the independent reference the fused
    /// `sub_shift_mix` is checked against.
    fn naive_sub_shift_mix(state: &mut [[u8; ROWS]], last_row_shift: usize) {
        sub_bytes(state);
        shift_bytes(state, last_row_shift);
        mix_columns(state);
    }

    fn arb_state(columns: usize) -> impl Strategy<Value = Vec<[u8; ROWS]>> {
        proptest::collection::vec(proptest::array::uniform8(any::<u8>()), columns)
    }

    proptest! {
        #[test]
        fn fused_sub_shift_mix_matches_naive_256(state in arb_state(8)) {
            let mut fused = [[0u8; ROWS]; MAX_COLUMNS];
            fused[..8].copy_from_slice(&state);
            let mut naive = fused;
            sub_shift_mix(&mut fused[..8], 7);
            naive_sub_shift_mix(&mut naive[..8], 7);
            prop_assert_eq!(fused, naive);
        }

        #[test]
        fn fused_sub_shift_mix_matches_naive_512(state in arb_state(16)) {
            let mut fused = [[0u8; ROWS]; MAX_COLUMNS];
            fused[..16].copy_from_slice(&state);
            let mut naive = fused;
            sub_shift_mix(&mut fused[..16], 11);
            naive_sub_shift_mix(&mut naive[..16], 11);
            prop_assert_eq!(fused, naive);
        }
    }
}

/// T-134's const-generic specialization (`sub_shift_mix_n`/`compress_n`) is a performance-motivated
/// refactor of the *same* algorithm as the retained runtime-`columns` `sub_shift_mix`/`compress`,
/// not a new derivation - so the check here is new-vs-old equality over random state, for every
/// `COLUMNS` value the crate actually instantiates (8, 16), rather than re-deriving correctness
/// against `naive_sub_shift_mix` again (that's `fused_round_tests`'s job). Mirrors
/// `hazmat::kalyna`'s `const_round_tests` exactly (`docs/DECISIONS.md` T-128/D-77).
#[cfg(test)]
mod const_shift_mix_tests {
    use super::{
        bytes_to_columns, bytes_to_columns_n, compress, compress_n, sub_shift_mix, sub_shift_mix_n,
        ROWS,
    };
    use proptest::prelude::*;

    fn arb_state<const COLUMNS: usize>() -> impl Strategy<Value = [[u8; ROWS]; COLUMNS]> {
        proptest::collection::vec(proptest::array::uniform8(any::<u8>()), COLUMNS).prop_map(|v| {
            let mut out = [[0u8; ROWS]; COLUMNS];
            out.copy_from_slice(&v);
            out
        })
    }

    macro_rules! const_matches_dyn_test {
        ($shift_mix_test:ident, $compress_test:ident, $bytes_test:ident, $columns:literal, $rounds:literal, $last_row_shift:literal) => {
            proptest! {
                #[test]
                fn $shift_mix_test(state in arb_state::<$columns>()) {
                    let mut dynamic = state;
                    let mut constant = state;
                    sub_shift_mix(&mut dynamic[..], $last_row_shift);
                    sub_shift_mix_n::<$columns>(&mut constant, $last_row_shift);
                    prop_assert_eq!(dynamic, constant);
                }

                #[test]
                fn $compress_test(h in arb_state::<$columns>(), block in arb_state::<$columns>()) {
                    let mut dynamic = h;
                    let mut constant = h;
                    compress(&mut dynamic[..], &block[..], $rounds, $last_row_shift);
                    compress_n::<$columns, $rounds>(&mut constant, &block, $last_row_shift);
                    prop_assert_eq!(dynamic, constant);
                }

                #[test]
                fn $bytes_test(bytes in proptest::collection::vec(any::<u8>(), $columns * ROWS)) {
                    let dynamic = bytes_to_columns(&bytes, $columns);
                    let constant = bytes_to_columns_n::<$columns>(&bytes);
                    prop_assert_eq!(&dynamic[..$columns], &constant[..]);
                }
            }
        };
    }

    const_matches_dyn_test!(
        sub_shift_mix_n_matches_dyn_columns8,
        compress_n_matches_dyn_columns8,
        bytes_to_columns_n_matches_dyn_columns8,
        8,
        10,
        7
    );
    const_matches_dyn_test!(
        sub_shift_mix_n_matches_dyn_columns16,
        compress_n_matches_dyn_columns16,
        bytes_to_columns_n_matches_dyn_columns16,
        16,
        14,
        11
    );
}
