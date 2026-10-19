//! Message formatting for DSTU 9041's `l(p)=384` case (T-297 - clauses 5.7/5.8/Table 1, 11 steps
//! 2-8, 12 steps 9-18, the clause set `message.rs`/`message512.rs` cite). A third sibling,
//! generated from `message512.rs` by script.
//!
//! Byte layout for `l(p)=384` (Table 1's row: `l_max(p)=296`, `l_H=64` bits): `M~` is 37 bytes,
//! left-padded with zeros; `l_M~` is the 2-byte big-endian bit length (clause 5.2); `M'` is
//! `i_H(1) || H(l_M~||M~) truncated to l_H=64 bits, LOW-order end (8) || l_M~(2) || M~(37)` = 48
//! bytes - not a multiple of Kalyna-256's 32-byte block, so `encryption384` wraps `M'` itself with
//! KW-p (DSTU 7624 §15.4), not `M' || 0^l` with KW as 256/512 do. Додаток Г.2's printed `H` and
//! `M'` match this layout exactly; its `t` does not follow §15.4 (D-241).

use crate::hazmat::kupyna::Kupyna256;
use subtle::ConstantTimeEq;

/// Maximum encryptable message length in bits for `l(p)=384` (Table 1).
pub const L_MAX_P: usize = 296;
/// `M~`'s fixed byte length (`L_MAX_P` bits, whole bytes).
const M_TILDE_BYTES: usize = L_MAX_P / 8;
/// Truncated hash length in bytes (Table 1, `l(p)=384` row: `l_H=64` bits).
const L_H_BYTES: usize = 8;
/// `M'`'s total fixed byte length: `1(i_H) + L_H_BYTES(hash) + 2(l_m_tilde) + M_TILDE_BYTES`.
pub(crate) const M_PRIME_BYTES: usize = 1 + L_H_BYTES + 2 + M_TILDE_BYTES;

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

/// Clause 11 steps 5-6: `l(M)` as a fixed 16-bit big-endian field (clause 5.2 - not size-dependent,
/// same as `message.rs::encode_l_m_tilde`).
#[must_use]
pub fn encode_l_m_tilde(message_bits: usize) -> [u8; 2] {
    #[allow(clippy::cast_possible_truncation)] // message_bits <= L_MAX_P = 296, fits u16 trivially
    (message_bits as u16).to_be_bytes()
}

/// Clause 11 steps 7-8: `M' = i_H || H(l_M~||M~) truncated to l_H bits (low-order end) || l_M~ ||
/// M~`.
#[must_use]
pub fn build_m_prime(
    hash_id: u8,
    m_tilde: &[u8; M_TILDE_BYTES],
    l_m_tilde: &[u8; 2],
) -> [u8; M_PRIME_BYTES] {
    let mut hashed_input = [0u8; 2 + M_TILDE_BYTES];
    hashed_input[..2].copy_from_slice(l_m_tilde);
    hashed_input[2..].copy_from_slice(m_tilde);
    let digest = Kupyna256::digest(&hashed_input);

    let mut m_prime = [0u8; M_PRIME_BYTES];
    m_prime[0] = hash_id;
    m_prime[1..=L_H_BYTES].copy_from_slice(&digest[digest.len() - L_H_BYTES..]);
    m_prime[1 + L_H_BYTES..3 + L_H_BYTES].copy_from_slice(l_m_tilde);
    m_prime[3 + L_H_BYTES..].copy_from_slice(m_tilde);
    m_prime
}

/// Inverse of [`build_m_prime`] (clause 12 steps 9-17): re-derives `hash_id`/`bit_length`/`m_tilde`
/// from `M'`, verifying the embedded hash and the zero-padding invariant.
///
/// # Errors
///
/// See [`MessageError`]'s variants - a malformed or tampered `m_prime` is rejected, never panics.
pub fn parse_m_prime(m_prime: &[u8; M_PRIME_BYTES]) -> Result<Message, MessageError> {
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
