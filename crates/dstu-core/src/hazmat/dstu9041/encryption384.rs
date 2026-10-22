//! Encrypt/decrypt composition for DSTU 9041's `l(p)=384` case (T-297 - clauses 11/12, the clause
//! set `encryption.rs`/`encryption512.rs` cite; `docs/DECISIONS.md` D-241/D-244).
//!
//! Two differences from 256/512, both from the text:
//! - The Kalyna-KW key is `kappa = x_T^(k)`, the low-order `k = 256` bits of `x_T` (clause 5.2;
//!   Table 2 gives Kalyna-256/256 for `l(p)=384`). At 256/512 `k` equals `l(p)`, so all of `x_T`.
//! - `M'` is 48 bytes, not a multiple of the 32-byte block, so `t` is Kalyna-256/256-KW-p over `M'`
//!   itself (DSTU 7624 §15.4, [`crate::hazmat::kalyna_kw_p`]). 256/512 wrap `M' || 0^l` with plain
//!   KW, the convention their worked examples confirmed (D-165/D-180).
//!
//! Додаток Г.2 reproduces here up to `kappa`, `H` and `M'`; its printed `t` does not follow §15.4,
//! so this module neither produces it nor accepts the document's `C` (D-241, the owner's choice).
//!
//! `DecryptError` is collapsed to one variant, and `point_from_x` carries the Finding 1/2 guards
//! (re-derived for E384/1 in D-241), as in `encryption.rs`/`encryption512.rs`.

use super::curve384::{base_point, is_valid_scalar, point_from_x, Point};
use super::fp384::from_candidate_bytes;
use super::message384::{
    build_m_prime, encode_l_m_tilde, format_m_tilde, parse_m_prime, M_PRIME_BYTES,
};
use crate::hazmat::kalyna_kw_p::Kalyna256_256KwP;
use zeroize::Zeroizing;

/// Hash function identifier for Kupyna-256 (clause 5.7's `i_H`), the worked example's `01`.
const HASH_ID_KUPYNA256: u8 = 0x01;

/// `t`'s length: KW-p over the 48-byte `M'` (48 + 16 + the always-present Б.2 block = 96, plus KW's
/// checksum block).
const T_BYTES: usize = 128;
/// `r || t`.
pub const CIPHERTEXT_BYTES: usize = 48 + T_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptError {
    /// `message_bits` is `0`, exceeds `L_MAX_P`, or `message`'s length doesn't match it.
    InvalidMessage,
    /// `epsilon` is outside the valid scalar range `{2, ..., n-2}`.
    InvalidEphemeralKey,
    /// `q` is off the curve or of order 1, 2 or 4 (T-307).
    InvalidPublicKey,
}

/// T-307: `q` is on the curve and its order is not 1, 2 or 4, so `T = eps*q` is not computable
/// without `eps`. `4q` takes two additions; a point at infinity on the way comes out of the
/// projective formula as `(0, 0)`, which is off the curve, so it is refused too. Cheap on purpose:
/// a large-order `q` with a small-order component is the recipient's own problem (it cannot
/// decrypt), not a leak - the full `n*q` check stays in `point_from_x` for keys built from bytes.
fn is_usable_recipient(q: Point) -> bool {
    let q2 = q.add(q);
    let q4 = q2.add(q2);
    q.is_on_curve() && q4 != Point::NEUTRAL && q4.is_on_curve()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    /// Any late-stage failure (bad `r`, KW-p integrity, hash mismatch, bad padding) or an invalid
    /// `e` - deliberately collapsed, see this module's doc comment.
    InvalidCiphertext,
}

/// `kappa = x_T^(k)`: the low-order 32 bytes of the big-endian `x_T`.
fn kappa_from_x(x: [u8; 48]) -> Zeroizing<[u8; 32]> {
    let x = Zeroizing::new(x);
    let mut kappa = Zeroizing::new([0u8; 32]);
    kappa.copy_from_slice(&x[16..]);
    kappa
}

/// Clause 11, steps 2-15. Returns `r || t` (48 + 128 bytes).
///
/// # Errors
///
/// See [`EncryptError`]'s variants.
pub fn encrypt(
    message: &[u8],
    message_bits: usize,
    q: Point,
    epsilon: &[u8; 48],
) -> Result<[u8; CIPHERTEXT_BYTES], EncryptError> {
    if !is_valid_scalar(epsilon) {
        return Err(EncryptError::InvalidEphemeralKey);
    }
    if !is_usable_recipient(q) {
        return Err(EncryptError::InvalidPublicKey);
    }
    // T-302: `m_tilde` is the plaintext (the KEM seed under `crypto_box*`).
    let m_tilde = Zeroizing::new(
        format_m_tilde(message, message_bits).map_err(|_| EncryptError::InvalidMessage)?,
    );
    let l_m_tilde = encode_l_m_tilde(message_bits);
    let m_prime = Zeroizing::new(build_m_prime(HASH_ID_KUPYNA256, &m_tilde, &l_m_tilde));

    let r_point = base_point().scalar_multiply(epsilon);
    let r_bytes = r_point.x.to_be_bytes();

    let t_point = Zeroizing::new(q.scalar_multiply(epsilon));
    let kappa = kappa_from_x(t_point.x.to_be_bytes());

    let mut ciphertext = [0u8; CIPHERTEXT_BYTES];
    ciphertext[..48].copy_from_slice(&r_bytes);
    // `M'` is always 48 bytes and `t` 128, the one shape `wrap` accepts for that length; its only
    // failure (`KwError::InvalidLength`) cannot occur, and is mapped rather than unwrapped so this
    // stays panic-free by construction (the `encryption512.rs` reasoning).
    Kalyna256_256KwP::wrap(&kappa, &m_prime[..], &mut ciphertext[48..])
        .map_err(|_| EncryptError::InvalidMessage)?;
    Ok(ciphertext)
}

/// Clause 12, steps 1-19. Returns the recovered `M~` (37 bytes, left-padded - the caller takes the
/// low-order `l(M)` bits) and `l(M)`. Needs no public key (`T' = e*R'`), as `encryption.rs::decrypt`.
///
/// # Errors
///
/// [`DecryptError::InvalidCiphertext`] for any tampered ciphertext, invalid `e`, or malformed `r` -
/// deliberately not distinguished.
pub fn decrypt(
    ciphertext: &[u8; CIPHERTEXT_BYTES],
    e: &[u8; 48],
) -> Result<([u8; 37], usize), DecryptError> {
    if !is_valid_scalar(e) {
        return Err(DecryptError::InvalidCiphertext);
    }

    let mut r_bytes = [0u8; 48];
    r_bytes.copy_from_slice(&ciphertext[..48]);
    let r_field = from_candidate_bytes(&r_bytes).ok_or(DecryptError::InvalidCiphertext)?;

    // Steps 2-6 plus the subgroup check beyond clause 12's literal text: `curve384::point_from_x`.
    let r_prime = point_from_x(r_field).ok_or(DecryptError::InvalidCiphertext)?;

    // Steps 7-8: T' = e*R'; kappa = x_T'^(k).
    let t_prime = Zeroizing::new(r_prime.scalar_multiply(e));
    let kappa = kappa_from_x(t_prime.x.to_be_bytes());

    // Step 9: KW-p unwrap; its checksum and padding checks are constant-time (D-243).
    let mut recovered = Zeroizing::new([0u8; T_BYTES - 32]);
    let len = Kalyna256_256KwP::unwrap(&kappa, &ciphertext[48..], &mut recovered[..])
        .map_err(|_| DecryptError::InvalidCiphertext)?;
    // A valid KW-p of any other length is not an M' for this curve.
    if len != M_PRIME_BYTES {
        return Err(DecryptError::InvalidCiphertext);
    }
    let mut m_prime = Zeroizing::new([0u8; M_PRIME_BYTES]);
    m_prime.copy_from_slice(&recovered[..M_PRIME_BYTES]);

    // Steps 10-17 (hash and zero-padding checks, both constant-time - see message384.rs).
    let parsed = parse_m_prime(&m_prime).map_err(|_| DecryptError::InvalidCiphertext)?;
    Ok((parsed.m_tilde, parsed.bit_length))
}
