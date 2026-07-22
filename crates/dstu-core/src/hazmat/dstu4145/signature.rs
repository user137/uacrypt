//! DSTU 4145-2002 sign/verify, transcribed from Bouncy Castle's `DSTU4145Signer`
//! (`DECISIONS.md` D-02/D-14, `docs/pseudocode/dstu4145.md`) - built on `gf2m163`'s field
//! arithmetic, `curve163`'s point arithmetic, and `scalar`'s mod-`n` integer arithmetic.
//!
//! **The public key is `Q = -d*G`, not `d*G`** - see `docs/pseudocode/dstu4145.md`'s 2026-07-22
//! note and `DECISIONS.md` D-25's follow-up entry for how this was found (Bouncy Castle's own
//! `DSTU4145KeyPairGenerator` negates explicitly; the sign/verify identity only closes under this
//! convention). Callers deriving `Q` from `d` (e.g. `g.scalar_multiply(d)`) must negate via
//! `Point::negate` - this module takes `Q` as given rather than computing it, so it can't enforce
//! that for you.
//!
//! `verify` is public-data-only throughout (`r`, `s`, `Q`, `G` are all public in DSTU 4145
//! verification) - ordinary branches and `==` are fine here, same posture as `curve163`'s
//! `double`/`add`.

use super::curve163::{self, Point};
use super::gf2m163::FieldElement;
use super::scalar::Scalar;

/// Official text §5.9 ("Перетворення геш-коду на елемент основного поля"): given a hash-code
/// `(h_{L_H-1},...,h_0)`, compute `k = min(m, L_H)`, take `x_i = h_i` for `i = 0..k-1`, and zero
/// the rest. In byte terms (§5.1/§5.6's own big-endian convention, `h_0` is the *last* bit of the
/// hash's last byte): keep the hash's **last** `min(len, 21)` bytes as-is, masking the top byte to
/// its low 3 bits if a full 21 were taken (163 bits total) - **no byte reversal**, contrary to
/// what an earlier version of this function did (see `DECISIONS.md` D-25's follow-up-of-a-
/// follow-up entry: re-deriving this against the official text is what caught it - the previous
/// version only produced the right answer when its caller manually pre-reversed the hash first,
/// an easy-to-forget, undocumented API footgun that happened to cancel out against how the
/// `gf2m163.json` vector's own source test constructs its input).
#[must_use]
pub fn hash_to_field(hash: &[u8]) -> FieldElement {
    let take = hash.len().min(21);
    let mut bytes = [0u8; 21];
    bytes[21 - take..].copy_from_slice(&hash[hash.len() - take..]);
    if take == 21 {
        bytes[0] &= 0x07; // low 163 bits: the top byte holds only bits 160-162
    }
    FieldElement::from_be_bytes(&bytes)
}

/// `truncate(y, n.bit_length() - 1)`: keeps the low 162 bits of a field element's integer value,
/// as `r`/`r'` (an ordinary integer from here on, not a field element - see the module doc).
fn truncate_162(y: FieldElement) -> [u8; 21] {
    let mut bytes = y.to_be_bytes();
    bytes[0] &= 0x03; // 162 bits: the top byte holds only bits 160-161
    bytes
}

fn is_zero(bytes: &[u8; 21]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Big-endian byte-array comparison - public magnitude check (`r < n`, `s < n`), fine as ordinary
/// branches per the module doc.
fn less_than(a: &[u8; 21], b: &[u8; 21]) -> bool {
    a < b
}

/// `verifySignature` (see the pseudocode doc). `hash` is an already-computed message digest (not
/// hashed again here - DSTU 4145 is digest-agnostic, see the pseudocode doc's note on this).
#[must_use]
#[allow(clippy::many_single_char_names)] // r, s, q, g, h, n match the pseudocode doc's own names
pub fn verify(hash: &[u8], r: &[u8; 21], s: &[u8; 21], q: Point, g: Point) -> bool {
    let n = curve163::order();
    if is_zero(r) || is_zero(s) || !less_than(r, &n) || !less_than(s, &n) {
        return false;
    }

    let mut h = hash_to_field(hash);
    if h == FieldElement::ZERO {
        h = FieldElement::ONE;
    }

    let big_r = g.scalar_multiply(s) + q.scalar_multiply(r);
    let (rx, _) = match big_r {
        Point::Affine(x, y) => (x, y),
        Point::Infinity => return false,
    };

    let y = h.multiply(rx);
    &truncate_162(y) == r
}

/// `generateSignature` (see the pseudocode doc). `e` is the caller-supplied ephemeral scalar - a
/// nonce, like the IV/key parameters other `hazmat` primitives take explicitly (see the `hazmat`
/// module doc: no forced RNG dependency here). **`e` must be freshly random and secret for every
/// real signature** - reusing it, like reusing an IV, breaks the scheme (a fixed `e` is only
/// valid for reproducing the `gf2m163.json` KAT, per that vector's own note).
///
/// Returns `None` on any of the pseudocode's three degenerate-value rejections (`F_e == 0`,
/// `r == 0`, `s == 0`) - each has probability roughly `2^-163`, the same accepted-exception class
/// as ECDSA's own nonce-rejection loops, not a realistic caller path. Since `hazmat` cannot
/// generate a replacement `e` itself, the caller must retry with a fresh one.
#[must_use]
#[allow(clippy::many_single_char_names)] // r, s, d, e, h match the pseudocode doc's own names
pub fn sign(hash: &[u8], d: Scalar, e: Scalar, g: Point) -> Option<([u8; 21], [u8; 21])> {
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
    let r_bytes = truncate_162(y);
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
