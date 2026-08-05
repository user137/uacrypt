//! Message formatting for DSTU 9041's `l(p)=256` case (clauses 5.7/5.8/Table 1, 11 steps 2-8, 12
//! steps 9-18) - see `docs/pseudocode/dstu9041.md` "Message formatting" for the clause citations
//! and `crates/dstu-core/tests/vectors/dstu9041/g1-worked-example.json` for the worked example this
//! module is verified against (`crates/dstu-core/tests/dstu9041_message.rs`).
//!
//! Byte layout for `l(p)=256`: `M~` is 25 bytes (200 bits, `L_MAX_P`), left-padded with zeros so
//! the caller's own message occupies the low-order tail; `l_M~` is a 2-byte big-endian bit-length
//! field; `M'` is `i_H(1) || H(l_M~||M~) truncated to l_H=32 bits, LOW-order end (4) || l_M~(2) ||
//! M~(25)` = 32 bytes exactly. The Kalyna-KW input is `M' || 0x00×32` (64 bytes) - an empirical
//! fact confirmed against this crate's own `hazmat::kalyna_kw`, not yet explained from a cited
//! clause (`docs/pseudocode/dstu9041.md`'s "Open question", D-165).

use crate::hazmat::kupyna::Kupyna256;
use subtle::ConstantTimeEq;

/// Maximum encryptable message length in bits for `l(p)=256` (Table 1).
pub const L_MAX_P: usize = 200;
/// `M~`'s fixed byte length (`L_MAX_P` bits, whole bytes).
const M_TILDE_BYTES: usize = L_MAX_P / 8;
/// Truncated hash length in bits (Table 1, `l(p)=256` row).
const L_H_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// `message_bits == 0` (clause 11 step 2's `0 < l(M)` requirement).
    ZeroLength,
    /// `message_bits > L_MAX_P`.
    MessageTooLong,
    /// `message`'s byte length didn't match `message_bits.div_ceil(8)` exactly.
    LengthMismatch,
    /// Recomputed hash didn't match the extracted `H'` field (clause 12 step 16).
    HashMismatch,
    /// The zero-padding above `l(M)` bits in the recovered `M~` wasn't all-zero (clause 12 step 17).
    PaddingNotZero,
}

/// The recovered fields from a successfully parsed `M'` (clause 12 steps 9-17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub hash_id: u8,
    pub bit_length: usize,
    pub m_tilde: [u8; M_TILDE_BYTES],
}

/// Clause 11 steps 3-4: left-pad `message` (exactly `message_bits.div_ceil(8)` bytes, big-endian)
/// with zeros to `L_MAX_P` bits.
///
/// # Errors
///
/// See [`MessageError`]'s variants - a zero/oversized `message_bits`, or a `message` slice whose
/// length doesn't match `message_bits.div_ceil(8)` exactly, is rejected rather than panicking.
pub fn format_m_tilde(
    message: &[u8],
    message_bits: usize,
) -> Result<[u8; M_TILDE_BYTES], MessageError> {
    if message_bits == 0 {
        return Err(MessageError::ZeroLength);
    }
    if message_bits > L_MAX_P {
        return Err(MessageError::MessageTooLong);
    }
    let message_bytes = message_bits.div_ceil(8);
    if message.len() != message_bytes {
        return Err(MessageError::LengthMismatch);
    }
    let mut m_tilde = [0u8; M_TILDE_BYTES];
    m_tilde[M_TILDE_BYTES - message_bytes..].copy_from_slice(message);
    Ok(m_tilde)
}

/// Clause 11 steps 5-6: `l(M)` as a fixed 16-bit big-endian field.
#[must_use]
pub fn encode_l_m_tilde(message_bits: usize) -> [u8; 2] {
    #[allow(clippy::cast_possible_truncation)] // message_bits <= L_MAX_P = 200, fits u16 trivially
    (message_bits as u16).to_be_bytes()
}

/// Clause 11 steps 7-8: `M' = i_H || H(l_M~||M~) truncated to l_H bits (low-order end) || l_M~ ||
/// M~`.
#[must_use]
pub fn build_m_prime(hash_id: u8, m_tilde: &[u8; M_TILDE_BYTES], l_m_tilde: &[u8; 2]) -> [u8; 32] {
    let mut hashed_input = [0u8; 2 + M_TILDE_BYTES];
    hashed_input[..2].copy_from_slice(l_m_tilde);
    hashed_input[2..].copy_from_slice(m_tilde);
    let digest = Kupyna256::digest(&hashed_input);

    let mut m_prime = [0u8; 32];
    m_prime[0] = hash_id;
    m_prime[1..=L_H_BYTES].copy_from_slice(&digest[digest.len() - L_H_BYTES..]);
    m_prime[1 + L_H_BYTES..3 + L_H_BYTES].copy_from_slice(l_m_tilde);
    m_prime[3 + L_H_BYTES..].copy_from_slice(m_tilde);
    m_prime
}

/// The empirical Kalyna-KW input quirk: `M'` padded with one additional all-zero 256-bit block -
/// `docs/pseudocode/dstu9041.md`'s "Open question" (D-165): confirmed necessary to reproduce the
/// standard's own worked ciphertext, not yet explained from a cited clause.
#[must_use]
pub fn kw_plaintext_from_m_prime(m_prime: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(m_prime);
    out
}

/// Inverse of [`build_m_prime`] (clause 12 steps 9-17): re-derives `hash_id`/`bit_length`/`m_tilde`
/// from `M'`, verifying the embedded hash and the zero-padding invariant.
///
/// # Errors
///
/// See [`MessageError`]'s variants - a malformed or tampered `m_prime` is rejected, never panics.
pub fn parse_m_prime(m_prime: &[u8; 32]) -> Result<Message, MessageError> {
    let hash_id = m_prime[0];
    let embedded_hash = &m_prime[1..=L_H_BYTES];
    let mut l_m_tilde = [0u8; 2];
    l_m_tilde.copy_from_slice(&m_prime[1 + L_H_BYTES..3 + L_H_BYTES]);
    let mut m_tilde = [0u8; M_TILDE_BYTES];
    m_tilde.copy_from_slice(&m_prime[3 + L_H_BYTES..]);

    let bit_length = usize::from(u16::from_be_bytes(l_m_tilde));
    if bit_length == 0 {
        return Err(MessageError::ZeroLength);
    }
    if bit_length > L_MAX_P {
        return Err(MessageError::MessageTooLong);
    }

    let mut hashed_input = [0u8; 2 + M_TILDE_BYTES];
    hashed_input[..2].copy_from_slice(&l_m_tilde);
    hashed_input[2..].copy_from_slice(&m_tilde);
    let digest = Kupyna256::digest(&hashed_input);
    // Constant-time: this compares secret-key-adjacent (KW-unwrapped, hence caller-secret-derived
    // in the `decrypt` call path) data - `!=` on slices is not a documented constant-time
    // primitive (`docs/SECURITY.md`'s standing rule).
    let hash_ok: bool = digest[digest.len() - L_H_BYTES..]
        .ct_eq(embedded_hash)
        .into();
    if !hash_ok {
        return Err(MessageError::HashMismatch);
    }

    // Constant-time and fixed-iteration: `message_bytes` (hence which bytes count as "padding")
    // is itself derived from `bit_length`, decrypted data an attacker can influence - iterating
    // the full M_TILDE_BYTES buffer every time (rather than a `bit_length`-sized slice) keeps the
    // number of comparisons independent of that value, not just each individual comparison.
    let message_bytes = bit_length.div_ceil(8);
    let padding_len = M_TILDE_BYTES - message_bytes;
    let mut bad_padding = 0u8;
    for (i, &byte) in m_tilde.iter().enumerate() {
        let is_padding_position = u8::from(i < padding_len);
        bad_padding |= is_padding_position & u8::from(byte != 0);
    }
    if bad_padding != 0 {
        return Err(MessageError::PaddingNotZero);
    }

    Ok(Message {
        hash_id,
        bit_length,
        m_tilde,
    })
}
