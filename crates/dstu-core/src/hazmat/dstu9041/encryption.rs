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
//! `T'` - **not optional hardening**. `#E(F_p) = 4n` (the unique multiple of `2n` inside the Hasse
//! interval - confirmed by checking every `k` up to 20, only `k=2` lands `2n*k` in
//! `[p+1-2*sqrt(p), p+1+2*sqrt(p)]`). The curve equation's only `y=0` solutions are `x^2=1`, i.e.
//! `x in {1, p-1}` - exactly `NEUTRAL` and the order-2 point, no third one. A finite abelian group
//! of order `4n` (`n` odd prime) has its 2-Sylow subgroup either cyclic (`Z/4`, one non-trivial
//! order-2 element) or Klein four (`Z/2 x Z/2`, three) - since there is provably only one, the
//! 2-Sylow subgroup is `Z/4`, making `E(F_p)` cyclic of order `4n` overall. **A cyclic group of
//! order `4n` has genuine order-4 elements** - so an `r` reconstructing to an order-4 point is a
//! real, reachable ciphertext, not a hypothetical: it would leak `e mod 4` (not just `e`'s parity)
//! through which of the 3 distinguishable `kappa` values (`x` of `NEUTRAL`/the order-2
//! point/the order-4 point pair, the latter two sharing an `x` by `x_T=x_{-T}`) `T'=e*R'` lands
//! on. The subgroup check closes this generally, independent of locating a concrete order-4 point
//! by coordinates.
//!
//! Step 4 (`if !v.euler_criterion()`) is stricter than clause 12's literal `if δ==p-1`: it also
//! rejects `δ==0` (i.e. `v==0`), which is exactly the `r=p-1` case. The explicit `r=p-1` check in
//! step 2 is therefore not the sole enforcement for that case - kept as an early, explicit,
//! self-documenting rejection rather than relying on step 4's incidental stricter form to carry
//! the argument.

use super::curve256::{base_point, is_valid_scalar, point_from_x, Point};
use super::fp256::from_candidate_bytes;
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
pub fn decrypt(ciphertext: &[u8; 128], e: &[u8; 32]) -> Result<([u8; 25], usize), DecryptError> {
    if !is_valid_scalar(e) {
        return Err(DecryptError::InvalidCiphertext);
    }

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&ciphertext[..32]);
    let r_field = from_candidate_bytes(&r_bytes).ok_or(DecryptError::InvalidCiphertext)?;

    // Steps 2-6 (reject r in {0,1,p-1}, reject r^2=a*d^-1, compute v and reject non-residues,
    // y=sqrt(v)) plus the subgroup check beyond clause 12's literal text are all
    // `curve256::point_from_x` now - see that function's own doc comment, shared with
    // `crate::crypto_box::PublicKey::from_bytes` rather than duplicated here.
    let r_prime = point_from_x(r_field).ok_or(DecryptError::InvalidCiphertext)?;

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
