//! DSTU 4145-2002's m=257 curve: `y^2 + xy = x^3 + a*x^2 + b` over GF(2^257), `a = 0` (unlike
//! `curve163`'s `a = 1`) - domain parameters extracted from two independent real DSTU 4145
//! certificates, byte-order-corrected and cross-checked against Bouncy Castle's
//! `DSTU4145NamedCurves.java` `curves[6]` (`ECCurve.F2m(257, 12, ZERO, ...)`, cofactor `h = 4`,
//! not `curve163`'s `h = 2`) - see `docs/DECISIONS.md` D-185/D-186 for the full provenance.
//!
//! `a = 0` removes the `+a`/`+a*x^2` terms `curve163`'s `double`/`add`/`is_on_curve` carry for
//! `a = 1` - the Montgomery-ladder core of `scalar_multiply` and the y-coordinate recovery formula
//! are both `a`-independent (a known property of the López-Dahab projective ladder and its
//! standard recovery formula - `Guide to Elliptic Curve Cryptography`, Algorithm 3.40/3.41), so
//! only those three functions actually differ in shape from `curve163`'s.
//!
//! Same public/secret-data split as `curve163` (see its own module doc): `double`/`add`/
//! `is_on_curve` below branch on public data only, never on a secret scalar's intermediate state;
//! `scalar_multiply` is the sole constant-time path, used for both secret (signing) and public
//! (verification) scalars here - `curve163`'s `verify_combine` projective fast path (D-108) is not
//! reproduced yet, T-199's own scope is `add`/`double`/`scalar_multiply`/`negate` only.

use super::gf2m257::FieldElement;

fn b() -> FieldElement {
    FieldElement::from_be_bytes(&[
        0x01, 0xCE, 0xF4, 0x94, 0x72, 0x01, 0x15, 0x65, 0x7E, 0x18, 0xF9, 0x38, 0xD7, 0xA7, 0x94,
        0x23, 0x94, 0xFF, 0x94, 0x25, 0xC1, 0x45, 0x8C, 0x57, 0x86, 0x1F, 0x9E, 0xEA, 0x6A, 0xDB,
        0xE3, 0xBE, 0x10,
    ])
}

fn gx() -> FieldElement {
    FieldElement::from_be_bytes(&[
        0x00, 0x2A, 0x29, 0xEF, 0x20, 0x7D, 0x0E, 0x9B, 0x6C, 0x55, 0xCD, 0x26, 0x0B, 0x30, 0x6C,
        0x7E, 0x00, 0x7A, 0xC4, 0x91, 0xCA, 0x1B, 0x10, 0xC6, 0x23, 0x34, 0xA9, 0xE8, 0xDC, 0xD8,
        0xD2, 0x0F, 0xB7,
    ])
}

fn gy() -> FieldElement {
    FieldElement::from_be_bytes(&[
        0x01, 0x06, 0x86, 0xD4, 0x1F, 0xF7, 0x44, 0xD4, 0x44, 0x9F, 0xCC, 0xF6, 0xD8, 0xEE, 0xA0,
        0x31, 0x02, 0xE6, 0x81, 0x2C, 0x93, 0xA9, 0xD6, 0x0B, 0x97, 0x8B, 0x70, 0x2C, 0xF1, 0x56,
        0xD8, 0x14, 0xEF,
    ])
}

/// The curve's group order `n` (big-endian, 33 bytes) - `gf2m257_arith.json`'s `order_n`, matching
/// Bouncy Castle's `n_s[6]` verbatim (no byte-order correction needed - `n` is a DER `INTEGER`,
/// standard big-endian, unlike `b`/the base point which needed reversal - `docs/DECISIONS.md`
/// D-185). Not a `FieldElement`: an ordinary integer modulus for scalar arithmetic, unrelated to
/// this curve's `GF(2^257)` polynomial field.
#[must_use]
pub fn order() -> [u8; 33] {
    [
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x67, 0x59, 0x21, 0x3A, 0xF1, 0x82, 0xE9, 0x87, 0xD3, 0xE1, 0x77, 0x14, 0x90,
        0x7D, 0x47, 0x0D,
    ]
}

/// An affine point on the curve, or the point at infinity (the group identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    Infinity,
    Affine(FieldElement, FieldElement),
}

impl Point {
    #[must_use]
    pub fn generator() -> Self {
        Point::Affine(gx(), gy())
    }

    /// `-P`: `(x, y) -> (x, x + y)` (char-2 identity, `a`-independent - same as `curve163::negate`).
    #[must_use]
    pub fn negate(self) -> Self {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine(x, y) => Point::Affine(x, x + y),
        }
    }

    /// Checks `y^2 + xy == x^3 + b` (`a = 0` for this curve - no `x^2` term, unlike `curve163`'s
    /// `a = 1`). `Infinity` is not a solution and returns `false` - same convention as
    /// `curve163::is_on_curve`. Public-data check, never called on a secret-dependent point.
    #[must_use]
    pub fn is_on_curve(self) -> bool {
        match self {
            Point::Infinity => false,
            Point::Affine(x, y) => {
                let lhs = y.square() + x.multiply(y);
                let rhs = x.multiply(x.square()) + b();
                lhs == rhs
            }
        }
    }

    /// Affine point doubling for `y^2 + xy = x^3 + b` (`a = 0`): `x3 = lambda^2 + lambda` (no `+a`
    /// term, unlike `curve163::double`'s `+ FieldElement::ONE`). Same formula family (`Guide to
    /// Elliptic Curve Cryptography` §3.1.2) and the same public-data-only caveat as `curve163`.
    #[must_use]
    pub fn double(self) -> Self {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine(x1, y1) => {
                if x1 == FieldElement::ZERO {
                    return Point::Infinity;
                }
                let lambda = x1 + y1.multiply(x1.invert());
                let x3 = lambda.square() + lambda;
                let y3 = x1.square() + (lambda + FieldElement::ONE).multiply(x3);
                Point::Affine(x3, y3)
            }
        }
    }

    /// Constant-time scalar multiplication: `k * self`, `k` a big-endian 257-bit scalar (top 7
    /// bits of `k[0]` must be zero - values are always < the curve order, which is < `2^257`).
    /// Same Montgomery-ladder shape as `curve163::scalar_multiply` (`Guide to Elliptic Curve
    /// Cryptography`, Algorithm 3.40) - the ladder's per-iteration formulas and the final
    /// y-recovery step are both `a`-independent (see module doc), so only the loop bound (257, not
    /// 163) and field/byte widths differ from `curve163`. See `curve163::scalar_multiply`'s own
    /// doc comment for the full derivation and the `z1`/`z2`-zero boundary-case handling this
    /// mirrors exactly (`docs/DECISIONS.md` D-110/T-152) - not re-derived here, this curve's own
    /// cofactor (`h = 4`, vs. `curve163`'s `h = 2`) has not yet been re-checked against those
    /// boundary cases specifically, flagged for T-199's own active-attack test pass (step 6).
    #[must_use]
    pub fn scalar_multiply(self, k: &[u8; 33]) -> Self {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine(x, y) => {
                let mut x1 = FieldElement::ONE;
                let mut z1 = FieldElement::ZERO; // (x1 : z1) = Infinity
                let mut x2 = x;
                let mut z2 = FieldElement::ONE; // (x2 : z2) = P

                for i in (0..257u32).rev() {
                    let bit = bit_at(k, i);
                    let swap = bit ^ 1;
                    cswap(swap, &mut x1, &mut x2);
                    cswap(swap, &mut z1, &mut z2);

                    let t1 = z1;
                    z1 = (x1.multiply(z2) + x2.multiply(z1)).square();
                    x1 = x.multiply(z1) + x1.multiply(x2).multiply(t1).multiply(z2);
                    let t2 = x2;
                    x2 = x2.square().square() + b().multiply(z2.square().square());
                    z2 = t2.square().multiply(z2.square());

                    cswap(swap, &mut x1, &mut x2);
                    cswap(swap, &mut z1, &mut z2);
                }

                // See `curve163::scalar_multiply`'s own comment for the full rationale - identical
                // boundary-case handling, only the field width differs.
                if is_zero_mask(z1) != 0 {
                    return Point::Infinity;
                }

                let x1_affine = x1.multiply(z1.invert());
                let x2_affine = x2.multiply(z2.invert());
                let t1 = x1_affine + x;
                let t2 = x2_affine + x;
                let inner = t1.multiply(t2) + x.square() + y;
                let y1_affine_formula = x.invert().multiply(t1).multiply(inner) + y;

                let y1_affine = select(is_zero_mask(z2), x + y, y1_affine_formula);

                Point::Affine(x1_affine, y1_affine)
            }
        }
    }
}

impl core::ops::Add for Point {
    type Output = Self;

    /// Affine point addition, `a = 0`: `x3 = lambda^2 + lambda + x1 + x2` (no `+a` term, unlike
    /// `curve163::add`'s `+ FieldElement::ONE`). Same public-data-only caveat as `double`.
    fn add(self, other: Self) -> Self {
        match (self, other) {
            (Point::Infinity, q) => q,
            (p, Point::Infinity) => p,
            (Point::Affine(x1, y1), Point::Affine(x2, y2)) => {
                if x1 == x2 {
                    if y1 == y2 {
                        return self.double();
                    }
                    return Point::Infinity;
                }
                let lambda = (y1 + y2).multiply((x1 + x2).invert());
                let x3 = lambda.square() + lambda + x1 + x2;
                let y3 = lambda.multiply(x1 + x3) + x3 + y1;
                Point::Affine(x3, y3)
            }
        }
    }
}

fn bit_at(bytes: &[u8; 33], i: u32) -> u64 {
    let byte_index = 32 - (i / 8) as usize;
    let bit_in_byte = i % 8;
    u64::from((bytes[byte_index] >> bit_in_byte) & 1)
}

/// Constant-time conditional swap - same shape as `curve163::cswap`, widened to 5 limbs.
fn cswap(swap: u64, a: &mut FieldElement, b: &mut FieldElement) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// Constant-time "is this field element zero" test - same shape as `curve163::is_zero_mask`,
/// widened to 5 limbs.
fn is_zero_mask(a: FieldElement) -> u64 {
    let combined = a.0[0] | a.0[1] | a.0[2] | a.0[3] | a.0[4];
    let is_nonzero = (combined | combined.wrapping_neg()) >> 63;
    0u64.wrapping_sub(1 ^ is_nonzero)
}

/// Constant-time select - same shape as `curve163::select`, widened to 5 limbs.
fn select(mask: u64, if_mask: FieldElement, otherwise: FieldElement) -> FieldElement {
    let mut out = [0u64; 5];
    for ((out_limb, a), b) in out.iter_mut().zip(if_mask.0.iter()).zip(otherwise.0.iter()) {
        *out_limb = b ^ (mask & (a ^ b));
    }
    FieldElement(out)
}
