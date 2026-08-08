//! Encrypt/decrypt composition for DSTU 9041's `l(p)=512` case (T-192 Phase 4 - clauses 11/12,
//! same clause set `encryption.rs` cites for `l(p)=256`). Direct sibling of `encryption.rs` at
//! this field's own byte widths.
//!
//! `DecryptError` is deliberately collapsed to one variant (`InvalidCiphertext`) - same
//! padding-oracle reasoning as `encryption.rs`'s own doc comment (`docs/SECURITY.md`'s threat
//! model), not repeated here.
//!
//! **Finding 1/2 guards apply here exactly as in `curve256.rs`/`encryption.rs`** - `point_from_x`
//! (this module's own `curve512::point_from_x`) already rejects `r in {0,1,p-1}` and enforces
//! subgroup membership (`n*R' == NEUTRAL`), independently re-derived for E512/1 in D-176/D-178,
//! not assumed to carry over unchecked.
//!
//! **`kw_plaintext_from_m_prime`'s "append one all-zero block" convention is confirmed against
//! Додаток Г.3** (T-192 Phase 4, D-180) - unlike `l(p)=384`'s still-unimplemented `KW-p` padding
//! case, `l(p)=512` uses plain `Kalyna512_512Kw` with no padding variant needed.

use super::curve512::{base_point, is_valid_scalar, point_from_x, Point};
use super::fp512::from_candidate_bytes;
use super::message512::{
    build_m_prime, encode_l_m_tilde, format_m_tilde, kw_plaintext_from_m_prime, parse_m_prime,
};
use crate::hazmat::kalyna_kw::Kalyna512_512Kw;

/// Hash function identifier for Kupyna-256 (clause 5.7's `i_H` registry - only one value is wired
/// up by this module, matching the worked example's own `hash_function_id_hex: "01"`).
const HASH_ID_KUPYNA256: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptError {
    /// `message_bits` is `0`, exceeds `L_MAX_P`, or `message`'s length doesn't match it.
    InvalidMessage,
    /// `epsilon` is outside the valid scalar range `{2, ..., n-2}`.
    InvalidEphemeralKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    /// Any late-stage failure (bad `r`, KW checksum mismatch, hash mismatch, bad padding) or an
    /// invalid `e` - deliberately collapsed, see this module's own doc comment.
    InvalidCiphertext,
}

/// Clause 11, steps 2-15. `ciphertext_C` is `r || t` (64 + 192 bytes, 256 total for `l(p)=512`).
///
/// # Errors
///
/// See [`EncryptError`]'s variants.
pub fn encrypt(
    message: &[u8],
    message_bits: usize,
    q: Point,
    epsilon: &[u8; 64],
) -> Result<[u8; 256], EncryptError> {
    if !is_valid_scalar(epsilon) {
        return Err(EncryptError::InvalidEphemeralKey);
    }
    let m_tilde =
        format_m_tilde(message, message_bits).map_err(|_| EncryptError::InvalidMessage)?;
    let l_m_tilde = encode_l_m_tilde(message_bits);
    let m_prime = build_m_prime(HASH_ID_KUPYNA256, &m_tilde, &l_m_tilde);

    let r_point = base_point().scalar_multiply(epsilon);
    let r_bytes = r_point.x.to_be_bytes();

    let t_point = q.scalar_multiply(epsilon);
    let kappa = t_point.x.to_be_bytes();

    let kw_plaintext = kw_plaintext_from_m_prime(&m_prime);
    let mut t = [0u8; 192];
    // Unreachable in practice: `kw_plaintext` is always exactly 128 bytes by construction, and `t`
    // is always exactly 192 bytes - the only failure `wrap` can report (`KwError::InvalidLength`)
    // requires a length mismatch this function's own fixed-size arrays can't produce. Handled
    // instead of `.expect()`-ing (this crate denies `unwrap`/`expect` in library code) so this
    // stays provably panic-free rather than "correct by inspection only" - same reasoning
    // `encryption.rs::encrypt` already documents for its own `l(p)=256` case.
    Kalyna512_512Kw::wrap(&kappa, &kw_plaintext, &mut t)
        .map_err(|_| EncryptError::InvalidMessage)?;

    let mut ciphertext = [0u8; 256];
    ciphertext[..64].copy_from_slice(&r_bytes);
    ciphertext[64..].copy_from_slice(&t);
    Ok(ciphertext)
}

/// Clause 12, steps 1-19. Returns the recovered `M~` (53 bytes, left-padded - caller slices the
/// low-order `l(M)` bits out using the returned bit length) and `l(M)`. Takes no public key - same
/// reasoning as `encryption.rs::decrypt`'s own doc comment (`T' = e*R'` needs only the private key
/// and the ciphertext's own `r`).
///
/// # Errors
///
/// Returns [`DecryptError::InvalidCiphertext`] for any tampered ciphertext, invalid `e`, or
/// malformed `r` - deliberately not distinguished, see this module's own doc comment.
pub fn decrypt(ciphertext: &[u8; 256], e: &[u8; 64]) -> Result<([u8; 53], usize), DecryptError> {
    if !is_valid_scalar(e) {
        return Err(DecryptError::InvalidCiphertext);
    }

    let mut r_bytes = [0u8; 64];
    r_bytes.copy_from_slice(&ciphertext[..64]);
    let r_field = from_candidate_bytes(&r_bytes).ok_or(DecryptError::InvalidCiphertext)?;

    // Steps 2-6 (reject r in {0,1,p-1}, reject r^2=a*d^-1, compute v and reject non-residues,
    // y=sqrt(v)) plus the subgroup check beyond clause 12's literal text are all
    // `curve512::point_from_x` - see that function's own doc comment.
    let r_prime = point_from_x(r_field).ok_or(DecryptError::InvalidCiphertext)?;

    // Steps 7-8: T' = e*R'; kappa = x_T'.
    let t_prime = r_prime.scalar_multiply(e);
    let kappa = t_prime.x.to_be_bytes();

    // Step 9: unwrap. kalyna_kw's own checksum (D-55) already constant-time-compares its trailing
    // block.
    let mut recovered = [0u8; 128];
    Kalyna512_512Kw::unwrap(&kappa, &ciphertext[64..], &mut recovered)
        .map_err(|_| DecryptError::InvalidCiphertext)?;

    // The empirical "M' || 0x00*64" quirk, mirrored on decrypt: verify the appended block came
    // back all-zero, in fixed-iteration constant time.
    let mut appended_block_bad = 0u8;
    for &byte in &recovered[64..] {
        appended_block_bad |= u8::from(byte != 0);
    }
    if appended_block_bad != 0 {
        return Err(DecryptError::InvalidCiphertext);
    }

    let mut m_prime = [0u8; 64];
    m_prime.copy_from_slice(&recovered[..64]);

    // Steps 10-17: parsed internally (hash + zero-padding checks, both constant-time - see
    // message512.rs's own doc comment on why).
    let parsed = parse_m_prime(&m_prime).map_err(|_| DecryptError::InvalidCiphertext)?;

    Ok((parsed.m_tilde, parsed.bit_length))
}
