//! DSTU 4145-2002 sign/verify for `m=257` - same algorithm and structure as `signature::{sign,
//! verify}` for `m=163` (see that module's own doc comment for the full citation and the
//! `Q = -d*G` convention, which applies identically here), built on `gf2m257`/`curve257`/
//! `scalar257` instead. `docs/TASKS.md` T-199, `docs/DECISIONS.md` D-185/D-186.
//!
//! **`verify`'s public-key validation uses the general (`SP 800-56A`-style) check, not
//! `signature::verify`'s `m=163`-specific `x == 0` rejection** - `curve257`'s cofactor is `4`, not
//! `2` (D-185's Bouncy Castle cross-check, `h_s[6] = FOUR`), so `m=163`'s fix (reject the curve's
//! one order-2 point directly by its known `x = 0` coordinate) does not carry over: a cofactor-4
//! curve's small subgroup also contains order-4 points, whose `x`-coordinates are not `0` and
//! would slip past that specific check. Instead: reject `q` unless `q.scalar_multiply(&order())
//! == Point::Infinity` - `q` lies in the prime-order subgroup if and only if this holds, true for
//! *any* cofactor without needing to enumerate the small subgroup's actual points (`advisor()`
//! review, `docs/TASKS.md` T-199) - one extra full scalar multiplication per `verify` call, public
//! data throughout, same cost class as the two multiplications `verify` already pays. Tested
//! against the curve's genuine order-2 point (`x = 0`, same construction `signature.rs`'s own
//! `t189_public_key_validation` test uses) in `tests/dstu4145_signature257.rs` - sufficient to
//! prove the general check actually rejects a real small-subgroup point, not just the `m=163`-style
//! one this module deliberately does *not* special-case.
//!
//! `verify` is public-data-only throughout, same posture as `signature::verify` - ordinary
//! branches and `==` are fine here. No `verify_combine`-style projective fast path exists for
//! `curve257` yet (`curve257`'s own module doc) - `verify` pays three full `scalar_multiply` calls
//! now (the subgroup check, plus the original two).

use super::curve257::{self, Point};
use super::gf2m257::FieldElement;
use super::scalar257::Scalar;

/// Same construction as `signature::hash_to_field`, widened to `m=257`/33 bytes: keep the hash's
/// last `min(len, 33)` bytes, masking the top byte to its low 1 bit if a full 33 were taken (257
/// bits total - `33*8 - 257 = 7` padding bits, so only bit 0 of the top byte is meaningful).
#[must_use]
pub fn hash_to_field(hash: &[u8]) -> FieldElement {
    let take = hash.len().min(33);
    let mut bytes = [0u8; 33];
    bytes[33 - take..].copy_from_slice(&hash[hash.len() - take..]);
    if take == 33 {
        bytes[0] &= 0x01; // low 257 bits: the top byte holds only bit 256
    }
    FieldElement::from_be_bytes(&bytes)
}

/// `truncate(y, n.bit_length() - 1)`: keeps the low `n.bit_length() - 1` bits of a field element's
/// integer value. **`n.bit_length()` is 256 here, not 257** - `curve257::order()`'s own top byte
/// is `0x80` (no leading-zero slack, `docs/DECISIONS.md` D-185), so `n.bit_length() == m` does
/// *not* hold the way it happens to for `m=163` (whose `n` has bit-length 163, coincidentally
/// matching `m`) - `signature::truncate_162`'s `m - 1 == n.bit_length() - 1` equivalence was a
/// coincidence of that curve's specific order, not a general rule, and does not carry over here.
/// This keeps the low **255** bits: byte 0 (global bits 256-263) cleared entirely, byte 1's top
/// bit (global bit 255) also cleared (`0x7F` mask) - found and fixed via the BC-generated
/// `signature_cases` oracle failing `verify` despite `sign` matching exactly (`docs/TASKS.md`
/// T-199): `sign`'s own `r` output was correct either way (`Scalar::from_be_bytes` doesn't reduce,
/// so an over-wide `r` still round-tripped through `sign`'s own output), but was never actually
/// `< n` as `verify`'s domain check requires - a real correctness bug, not just a naming slip.
///
/// **This makes `r < n` (and `s < n`, since `s` is a `scalar257::Scalar` and therefore always
/// reduced) provable, not just empirically likely**: this function's output is always `< 2^255`
/// (255 bits kept), and `n >= 2^255` unconditionally (`n.bit_length() == 256` means `n` occupies
/// `[2^255, 2^256)`) - so `r < 2^255 <= n` holds for *every* input `y`, not just the ones a random
/// BC-oracle sample happened to cover. See `truncate_255_output_is_always_below_n` in
/// `tests/dstu4145_signature257.rs` for the boundary case that pins this down directly (`y` with
/// every bit set - the function's own maximum possible output).
fn truncate_255(y: FieldElement) -> [u8; 33] {
    let mut bytes = y.to_be_bytes();
    bytes[0] = 0;
    bytes[1] &= 0x7F;
    bytes
}

fn is_zero(bytes: &[u8; 33]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Big-endian byte-array comparison - public magnitude check (`r < n`, `s < n`).
fn less_than(a: &[u8; 33], b: &[u8; 33]) -> bool {
    a < b
}

/// `verifySignature`, `m=257`. `hash` is an already-computed message digest.
#[must_use]
#[allow(clippy::many_single_char_names)] // r, s, q, g, h, n match the pseudocode doc's own names
pub fn verify(hash: &[u8], r: &[u8; 33], s: &[u8; 33], q: Point, g: Point) -> bool {
    let n = curve257::order();
    if is_zero(r) || is_zero(s) || !less_than(r, &n) || !less_than(s, &n) {
        return false;
    }

    // Full public-key validation (on-curve, non-identity, in the prime-order subgroup) - see the
    // module doc for why the general `n*q == Infinity` check is used here instead of `m=163`'s
    // `x == 0` shortcut (cofactor 4, not 2 - that shortcut doesn't cover this curve's order-4
    // points).
    if !q.is_on_curve() || q.scalar_multiply(&n) != Point::Infinity {
        return false;
    }

    let mut h = hash_to_field(hash);
    if h == FieldElement::ZERO {
        h = FieldElement::ONE;
    }

    let s_point = g.scalar_multiply(s);
    let r_point = q.scalar_multiply(r);
    let big_r = s_point + r_point;
    let (rx, _) = match big_r {
        Point::Affine(x, y) => (x, y),
        Point::Infinity => return false,
    };

    let y = h.multiply(rx);
    &truncate_255(y) == r
}

/// `generateSignature`, `m=257`. `e` is the caller-supplied ephemeral scalar - see
/// `signature::sign`'s own doc comment for the freshness/secrecy requirement, identical here.
#[must_use]
#[allow(clippy::many_single_char_names)] // r, s, d, e, h match the pseudocode doc's own names
pub fn sign(hash: &[u8], d: Scalar, e: Scalar, g: Point) -> Option<([u8; 33], [u8; 33])> {
    let mut h = hash_to_field(hash);
    if h == FieldElement::ZERO {
        h = FieldElement::ONE;
    }

    let (fe_x, _) = match g.scalar_multiply(&e.to_be_bytes()) {
        Point::Affine(x, y) => (x, y),
        Point::Infinity => return None,
    };
    if fe_x == FieldElement::ZERO {
        return None;
    }

    let y = h.multiply(fe_x);
    let r_bytes = truncate_255(y);
    if is_zero(&r_bytes) {
        return None;
    }

    let r = Scalar::from_be_bytes(&r_bytes);
    let s = r.multiply(d) + e;
    if s.is_zero() {
        return None;
    }

    Some((r_bytes, s.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves `truncate_255`'s output is always `< n`, not just empirically likely (see its own
    /// doc comment for the bit-count argument) - the boundary case, `y` with every representable
    /// bit set (the function's own maximum possible output), is the one input that actually
    /// exercises that bound; a random `y` from the BC oracle only demonstrates it by chance.
    #[test]
    fn truncate_255_output_is_always_below_n() {
        let all_ones = FieldElement::from_be_bytes(&[0xFFu8; 33]);
        let r_bytes = truncate_255(all_ones);
        assert!(
            less_than(&r_bytes, &curve257::order()),
            "truncate_255's own maximum output must stay below n"
        );
    }
}
