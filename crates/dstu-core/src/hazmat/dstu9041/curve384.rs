//! Twisted Edwards point arithmetic over E384/1 (T-297 - `docs/pseudocode/dstu9041.md`,
//! `docs/DECISIONS.md` D-241/D-244). Curve equation (the x/y-swapped form of `curve256.rs`):
//! `x^2 + a*y^2 = d*x^2*y^2 + 1 (mod p)`, `a=2`, `d=0x214`. A third sibling of `curve256.rs`/
//! `curve512.rs`, generated from `curve512.rs` by script with the constants computed from
//! `curve-E384-1.json` - same addition law (Додаток Б.4), same complete-formula reasoning (`d` a
//! non-square, re-checked for E384/1 in D-241).
//!
//! **Finding 1/2 re-derived for E384/1, not copied (D-241)**: cofactor 4 (Hasse interval), and
//! `x=p-1` reconstructs an order-2 point outside `<P>` - checked in `tests/dstu9041_curve_384.rs`.
//! [`point_from_x`] closes both as `curve256.rs`'s does: `x in {0,1,p-1}`/`x^2=a*d^-1` excluded,
//! plus the subgroup check `n*candidate == NEUTRAL`.

use super::fp384::FieldElement;
use crate::hazmat::limb::sbb;

const BASE_X: [u8; 48] = [
    0xF5, 0xFC, 0x15, 0x1B, 0x62, 0x64, 0xCB, 0x53, 0xA4, 0xB8, 0x79, 0xAA, 0x9A, 0x1F, 0x4A, 0x51,
    0x56, 0xBB, 0xF0, 0x63, 0xB5, 0x6A, 0xAA, 0x91, 0x26, 0x17, 0xC0, 0xE4, 0xCE, 0xFF, 0x15, 0xD2,
    0xDF, 0x49, 0x7D, 0x9A, 0xEF, 0x12, 0x37, 0x4A, 0x22, 0xD2, 0x2C, 0x3B, 0x40, 0x2B, 0x2C, 0x71,
];

const BASE_Y: [u8; 48] = [
    0xA9, 0x02, 0x72, 0x07, 0xE8, 0x80, 0x74, 0xF4, 0xAF, 0xA3, 0xD4, 0x4D, 0x45, 0x90, 0xDD, 0x04,
    0xBA, 0xFB, 0xF6, 0xAE, 0x3D, 0x32, 0x10, 0x91, 0xF5, 0x00, 0xC7, 0x83, 0xF4, 0x70, 0x79, 0x40,
    0xB7, 0xF5, 0xEB, 0xDD, 0x93, 0x32, 0x5C, 0x53, 0x91, 0x84, 0x3F, 0x9A, 0x78, 0x52, 0x6B, 0xB1,
];

/// The base point's order `n` (E384/1's prime order, D-241).
const ORDER_N: [u8; 48] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0xF9, 0x05, 0xB7, 0x36, 0x74, 0xAC, 0x7D,
    0x4A, 0xF3, 0x8C, 0x53, 0x33, 0x1D, 0xC2, 0x08, 0xA5, 0x17, 0xDC, 0xB3, 0xF3, 0x40, 0xEE, 0xCF,
];

/// `a * d^-1 mod p`, the `x^2` value [`point_from_x`] excludes (`D_{1,2}`), precomputed
/// instead of one `invert` per call (T-287); `a_div_d_matches_curve_constants` re-derives it.
const A_DIV_D: [u8; 48] = [
    0x3E, 0x8E, 0x6F, 0xA3, 0x9B, 0xE8, 0xE6, 0xFA, 0x39, 0xBE, 0x8E, 0x6F, 0xA3, 0x9B, 0xE8, 0xE6,
    0xFA, 0x39, 0xBE, 0x8E, 0x6F, 0xA3, 0x9B, 0xE8, 0xE6, 0xFA, 0x39, 0xBE, 0x8E, 0x6F, 0xA3, 0x9B,
    0xE8, 0xE6, 0xFA, 0x39, 0xBE, 0x8E, 0x6F, 0xA3, 0x9B, 0xE8, 0xE6, 0xFA, 0x39, 0xBE, 0x8C, 0x63,
];

pub(crate) fn curve_a() -> FieldElement {
    let mut bytes = [0u8; 48];
    bytes[47] = 2;
    FieldElement::from_be_bytes(&bytes)
}

pub(crate) fn curve_d() -> FieldElement {
    let mut bytes = [0u8; 48];
    bytes[46] = 0x02;
    bytes[47] = 0x14;
    FieldElement::from_be_bytes(&bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, zeroize::Zeroize)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
}

impl Point {
    /// The neutral element `(1, 0)`.
    pub const NEUTRAL: Self = Self {
        x: FieldElement::ONE,
        y: FieldElement::ZERO,
    };

    /// Checks `x^2 + a*y^2 == d*x^2*y^2 + 1 (mod p)`. Public-data check, matches `curve256.rs`'s
    /// own reasoning for why an ordinary branch is fine here.
    #[must_use]
    pub fn is_on_curve(self) -> bool {
        let x2 = self.x.square();
        let y2 = self.y.square();
        let lhs = x2.add(curve_a().multiply(y2));
        let rhs = curve_d().multiply(x2).multiply(y2).add(FieldElement::ONE);
        lhs == rhs
    }

    /// Point addition (also correct for doubling and the neutral element - the formula is
    /// complete). A convenience wrapper around `ProjectivePoint::add`.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Self {
        ProjectivePoint::from_affine(self)
            .add(ProjectivePoint::from_affine(other))
            .to_affine()
    }

    /// Constant-time scalar multiplication, fixed 384 iterations MSB-first, `scalar` big-endian.
    #[must_use]
    pub fn scalar_multiply(self, scalar: &[u8; 48]) -> Self {
        let base = ProjectivePoint::from_affine(self);
        let mut acc = ProjectivePoint::from_affine(Self::NEUTRAL);
        for &byte in scalar {
            for bit_idx in (0..8).rev() {
                acc = acc.add(acc);
                let bit = u64::from((byte >> bit_idx) & 1);
                let candidate = acc.add(base);
                acc = ProjectivePoint::select(bit, candidate, acc);
            }
        }
        acc.to_affine()
    }
}

#[derive(Clone, Copy, Debug)]
struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl ProjectivePoint {
    fn from_affine(p: Point) -> Self {
        Self {
            x: p.x,
            y: p.y,
            z: FieldElement::ONE,
        }
    }

    /// The one inversion point in the whole scalar-multiplication ladder - see
    /// `curve256.rs::ProjectivePoint::to_affine`'s identical doc comment on the traced
    /// constant-time dependency this composes into.
    fn to_affine(self) -> Point {
        let z_inv = self.z.invert();
        Point {
            x: self.x.multiply(z_inv),
            y: self.y.multiply(z_inv),
        }
    }

    /// Додаток Б.4's complete addition law - identical to `curve256.rs`'s own, just over the
    /// 384-bit field.
    #[allow(clippy::many_single_char_names)]
    fn add(self, other: Self) -> Self {
        let a = curve_a();
        let d = curve_d();

        let zz = self.z.multiply(other.z);
        let b = zz.square();
        let c = self.x.multiply(other.x);
        let dd = self.y.multiply(other.y);
        let e = d.multiply(c).multiply(dd);
        let f = b.sub(e);
        let g = b.add(e);

        let x_sum = self.x.add(self.y);
        let y_sum = other.x.add(other.y);
        let cross = x_sum.multiply(y_sum);

        let x_r = zz.multiply(g).multiply(c.sub(a.multiply(dd)));
        let y_r = zz.multiply(f).multiply(cross.sub(c).sub(dd));
        let z_r = f.multiply(g);

        Self {
            x: x_r,
            y: y_r,
            z: z_r,
        }
    }

    fn select(bit: u64, a: Self, b: Self) -> Self {
        Self {
            x: FieldElement::select(bit, a.x, b.x),
            y: FieldElement::select(bit, a.y, b.y),
            z: FieldElement::select(bit, a.z, b.z),
        }
    }
}

/// Reconstructs a point on the curve from just its `x`-coordinate - direct sibling of
/// `curve256.rs::point_from_x`, same rejection gauntlet: `x in {0, 1, p-1}`, `x^2 = a*d^-1`, `v`
/// not a quadratic residue, or the reconstructed candidate outside `<P>`.
#[must_use]
pub fn point_from_x(x: FieldElement) -> Option<Point> {
    let a = curve_a();
    let d = curve_d();
    let a_div_d = FieldElement::from_be_bytes(&A_DIV_D);
    let p_minus_1 = FieldElement::ZERO.sub(FieldElement::ONE);
    let x_squared = x.square();

    if x == FieldElement::ZERO || x == FieldElement::ONE || x == p_minus_1 || x_squared == a_div_d {
        return None;
    }

    let numerator = FieldElement::ONE.sub(x_squared);
    let denominator = a.sub(d.multiply(x_squared));
    let v = numerator.multiply(denominator.invert());

    if !v.euler_criterion() {
        return None;
    }

    let candidate = Point { x, y: v.sqrt() };

    if candidate.scalar_multiply(&order()) != Point::NEUTRAL {
        return None;
    }

    Some(candidate)
}

#[must_use]
pub fn base_point() -> Point {
    Point {
        x: FieldElement::from_be_bytes(&BASE_X),
        y: FieldElement::from_be_bytes(&BASE_Y),
    }
}

#[must_use]
pub fn order() -> [u8; 48] {
    ORDER_N
}

#[allow(clippy::needless_range_loop)]
fn bytes_be_to_limbs(bytes: &[u8; 48]) -> [u64; 6] {
    let mut limbs = [0u64; 6];
    let mut limb_bytes = [0u8; 8];
    for i in 0..6 {
        limb_bytes.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        limbs[5 - i] = u64::from_be_bytes(limb_bytes);
    }
    limbs
}

/// `true` iff `a < b`, both interpreted as big-endian unsigned 384-bit integers. Branchless
/// (fixed 6-limb `sbb` chain), no data-dependent control flow.
#[allow(clippy::needless_range_loop)]
fn is_less_than(a: &[u8; 48], b: &[u8; 48]) -> bool {
    let al = bytes_be_to_limbs(a);
    let bl = bytes_be_to_limbs(b);
    let mut borrow = 0u64;
    for i in 0..6 {
        let (_, bw) = sbb(al[i], bl[i], borrow);
        borrow = bw;
    }
    borrow == 1
}

/// `1 < scalar < n-1`, constant-time - same precondition `curve256.rs::is_valid_scalar` enforces.
#[must_use]
pub fn is_valid_scalar(scalar: &[u8; 48]) -> bool {
    let mut one = [0u8; 48];
    one[47] = 1;
    let mut n_minus_1 = ORDER_N;
    // n is odd (prime) - decrementing its last byte alone never borrows across bytes.
    n_minus_1[47] -= 1;

    let scalar_gt_one = is_less_than(&one, scalar);
    let scalar_lt_n_minus_1 = is_less_than(scalar, &n_minus_1);
    scalar_gt_one & scalar_lt_n_minus_1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-287: the precomputed constant is exactly `a * d^-1` for this curve's `a` and `d`.
    #[test]
    fn a_div_d_matches_curve_constants() {
        assert_eq!(
            A_DIV_D,
            curve_a().multiply(curve_d().invert()).to_be_bytes()
        );
    }
}
