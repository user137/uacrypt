//! Encrypt/decrypt composition for DSTU 9041's `l(p)=256` case (clauses 11/12 - see
//! `docs/pseudocode/dstu9041.md`). `l(p)=256` only (E256/1) - see this module's parent's own doc
//! comment for the scope citation.
//!
//! `DecryptError` is deliberately collapsed to one variant (`InvalidCiphertext`): clause 12's
//! late-stage checks (hash mismatch, padding-not-zero, KW checksum mismatch) all depend on
//! `κ=x_T'`, itself derived from the caller's secret `e` - returning distinguishable
//! errors/timing here is a padding-oracle shape (Manger/Vaudenay-style), squarely in
//! `docs/SECURITY.md`'s threat model. Documented as a deliberate safe deviation from clause 12's
//! literal per-step error naming, same category as D-56/D-63's AEAD-binding fixes.
//!
//! **Security fix beyond clause 12's literal text**: step 2 rejects `r=0`, `r=1`,
//! `r^2=a*d^-1 mod p` - but not `r=p-1`, which reconstructs to `R'=(p-1,0)`, a genuine order-2
//! point OUTSIDE the base point's subgroup `<P>` (proved arithmetically in
//! `tests/dstu9041_curve.rs`'s `r_equals_p_minus_1_reconstructs_the_order_2_point`). Left
//! unrejected, a chosen-ciphertext query with `r=p-1` would leak the private key's parity bit via
//! whether `T'=e*R'` lands on `R'` (e odd) or `NEUTRAL` (e even). Added here as a fourth
//! rejection case, right next to `r=1`.
//!
//! `decrypt` additionally verifies `R'` is actually in `<P>` (`n*R' == NEUTRAL`) before computing
//! `T'`. E256/1 has cofactor 4 (`#E = 4n`); a numerical search (5000 random points via cofactor
//! clearing, cross-checked against the real `7*P==R` fact) found no rational order-4 point on
//! this specific curve - consistent with the order-4 candidates' standard location (`x=0` in this
//! curve's own swapped convention) requiring `a` to be a quadratic residue, which `a=2` is not
//! here (already noted in this plan's own `r=p-1` analysis). So for E256/1 the only non-trivial
//! torsion outside `<P>` is the order-2 point the `r=p-1` check already excludes - but the
//! subgroup check is kept anyway as the general, curve-parameter-independent fix, rather than
//! relying on an invariant ("no order-4 points on this specific curve") a future parameter change
//! could silently invalidate.
//!
//! Step 4 (`if !v.euler_criterion()`) is stricter than clause 12's literal `if δ==p-1`: it also
//! rejects `δ==0` (i.e. `v==0`), which is exactly the `r=p-1` case. The explicit `r=p-1` check in
//! step 2 is therefore not the sole enforcement for that case - kept as an early, explicit,
//! self-documenting rejection rather than relying on step 4's incidental stricter form to carry
//! the argument.

use super::curve256::{base_point, curve_a, curve_d, is_valid_scalar, order, Point};
use super::fp256::{from_candidate_bytes, FieldElement};
use super::message::{
    build_m_prime, encode_l_m_tilde, format_m_tilde, kw_plaintext_from_m_prime, parse_m_prime,
};
use crate::hazmat::kalyna_kw::Kalyna256_256Kw;

/// Hash function identifier for Kupyna-256 (clause 5.7's `i_H` registry - only one value is
/// wired up by this module, matching the worked example's own `hash_function_id_hex: "01"`).
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

/// Clause 11, steps 2-15. `ciphertext_C` is `r || t` (32 + 96 bytes, 128 total for `l(p)=256`).
///
/// # Errors
///
/// See [`EncryptError`]'s variants.
pub fn encrypt(
    message: &[u8],
    message_bits: usize,
    q: Point,
    epsilon: &[u8; 32],
) -> Result<[u8; 128], EncryptError> {
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
    let mut t = [0u8; 96];
    // Unreachable in practice: `kw_plaintext` is always exactly 64 bytes (2 Kalyna blocks) by
    // construction, and `t` is always exactly 96 bytes - the only failure `wrap` can report
    // (`KwError::InvalidLength`) requires a length mismatch this function's own fixed-size arrays
    // can't produce. Handled instead of `.expect()`-ing (this crate denies `unwrap`/`expect` in
    // library code) so this stays provably panic-free rather than "correct by inspection only."
    Kalyna256_256Kw::wrap(&kappa, &kw_plaintext, &mut t)
        .map_err(|_| EncryptError::InvalidMessage)?;

    let mut ciphertext = [0u8; 128];
    ciphertext[..32].copy_from_slice(&r_bytes);
    ciphertext[32..].copy_from_slice(&t);
    Ok(ciphertext)
}

/// Clause 12, steps 1-19. Returns the recovered `M~` (25 bytes, left-padded - caller slices the
/// low-order `l(M)` bits out using the returned bit length) and `l(M)`. Takes no public key: `T' =
/// e*R'` is reconstructed entirely from the private key and the ciphertext's own `r` (`R = eps*P`,
/// `T = eps*Q = eps*(e*P) = e*(eps*P) = e*R` - the whole point of the construction is that `Q`
/// never needs to appear on the decrypt side).
///
/// # Errors
///
/// Returns [`DecryptError::InvalidCiphertext`] for any tampered ciphertext, invalid `e`, or
/// malformed `r` - deliberately not distinguished, see this module's own doc comment.
#[allow(clippy::many_single_char_names)] // a/d/e/v/y mirror clause 12's own step notation
pub fn decrypt(ciphertext: &[u8; 128], e: &[u8; 32]) -> Result<([u8; 25], usize), DecryptError> {
    if !is_valid_scalar(e) {
        return Err(DecryptError::InvalidCiphertext);
    }

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&ciphertext[..32]);
    let r_field = from_candidate_bytes(&r_bytes).ok_or(DecryptError::InvalidCiphertext)?;

    let a = curve_a();
    let d = curve_d();
    let p_minus_1 = FieldElement::ZERO.sub(FieldElement::ONE);
    let r_squared = r_field.square();

    // Step 2: reject r=0, r=1, r=p-1 (this session's own fix - see module doc comment), and
    // r^2 = a*d^-1 mod p (the D_{1,2} singular-point exclusion). Every branch here is on `r`,
    // part of the ciphertext the caller already possesses - no secret-dependent timing concern,
    // unlike the checks further below that depend on `kappa`.
    if r_field == FieldElement::ZERO
        || r_field == FieldElement::ONE
        || r_field == p_minus_1
        || r_squared == a.multiply(d.invert())
    {
        return Err(DecryptError::InvalidCiphertext);
    }

    // Step 3: v = (1-r^2) * (a-d*r^2)^-1 mod p.
    let numerator = FieldElement::ONE.sub(r_squared);
    let denominator = a.sub(d.multiply(r_squared));
    let v = numerator.multiply(denominator.invert());

    // Step 4: if v is not a residue, "Invalid ciphertext", abort.
    if !v.euler_criterion() {
        return Err(DecryptError::InvalidCiphertext);
    }

    // Steps 5-6: y = sqrt(v); R' = (r, y).
    let y = v.sqrt();
    let r_prime = Point { x: r_field, y };

    // Subgroup check (beyond clause 12's literal text - see module doc comment): reject any R'
    // outside <P>, the general fix for a cofactor > 1 curve, not relying on the specific finding
    // that this curve's only outside-<P> torsion happens to be the order-2 point already excluded.
    if r_prime.scalar_multiply(&order()) != Point::NEUTRAL {
        return Err(DecryptError::InvalidCiphertext);
    }

    // Steps 7-8: T' = e*R'; kappa = x_T'.
    let t_prime = r_prime.scalar_multiply(e);
    let kappa = t_prime.x.to_be_bytes();

    // Step 9: unwrap. kalyna_kw's own checksum (Deviation 2, docs/DECISIONS.md D-55) already
    // constant-time-compares its trailing block.
    let mut recovered = [0u8; 64];
    Kalyna256_256Kw::unwrap(&kappa, &ciphertext[32..], &mut recovered)
        .map_err(|_| DecryptError::InvalidCiphertext)?;

    // The empirical "M' || 0x00*32" quirk, mirrored on decrypt: verify the appended block came
    // back all-zero, in fixed-iteration constant time (mirrors message.rs's own padding check -
    // `recovered` is kappa-derived, hence caller-secret-adjacent).
    let mut appended_block_bad = 0u8;
    for &byte in &recovered[32..] {
        appended_block_bad |= u8::from(byte != 0);
    }
    if appended_block_bad != 0 {
        return Err(DecryptError::InvalidCiphertext);
    }

    let mut m_prime = [0u8; 32];
    m_prime.copy_from_slice(&recovered[..32]);

    // Steps 10-17: parsed internally (hash + zero-padding checks, both constant-time - see
    // message.rs's own doc comment on why).
    let parsed = parse_m_prime(&m_prime).map_err(|_| DecryptError::InvalidCiphertext)?;

    Ok((parsed.m_tilde, parsed.bit_length))
}
