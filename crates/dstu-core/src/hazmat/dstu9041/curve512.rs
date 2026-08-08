//! Twisted Edwards point arithmetic over E512/1 (T-192 Phase 2 - see
//! `docs/pseudocode/dstu9041.md`, `docs/DECISIONS.md` D-176/D-177). Curve equation (same
//! x/y-swapped form as `curve256.rs`, per the primary text): `x^2 + a*y^2 = d*x^2*y^2 (mod p)`,
//! `a=2`, `d=0x10D`. Direct sibling of `curve256.rs` at the 512-bit field width - same addition
//! law (Додаток Б.4), same complete-formula reasoning (`d` non-square, guaranteed by 3.18/7.2 for
//! every recommended curve), same `Point{x,y}`-with-no-`Infinity`-variant shape.
//!
//! **Finding 1/2 re-derived for E512/1 specifically, not copied from E256/1 (D-176)**: cofactor 4
//! (independently re-checked via the Hasse-interval method), and `x=p-1` reconstructs a genuine
//! order-2 point outside `<P>` (pure algebra from the curve's own `y=0` cross-section, so it
//! recurs structurally - still verified here, in `tests/dstu9041_curve_512.rs`, not assumed).
//! [`point_from_x`] below closes both the same way `curve256.rs`'s does: explicit exclusion of
//! `x in {0,1,p-1}`/`x^2=a*d^-1`, plus a general subgroup-membership check
//! (`n*candidate == NEUTRAL`) that catches order-4 points too, independent of locating one by
//! coordinates.

use super::fp512::{sbb, FieldElement};

const BASE_X: [u8; 64] = [
    0x52, 0x30, 0xA1, 0xEE, 0x74, 0x70, 0x50, 0xA0, 0x72, 0xBD, 0x73, 0x19, 0x74, 0x15, 0x86, 0xEA,
    0x52, 0x03, 0x88, 0xB6, 0xB5, 0x30, 0x94, 0x57, 0x1C, 0x82, 0x1A, 0x2F, 0xC9, 0xA9, 0xE8, 0x3D,
    0x56, 0x66, 0x53, 0x46, 0xB5, 0xDB, 0x04, 0xC4, 0x3E, 0x75, 0x26, 0x1D, 0xBD, 0xA5, 0x12, 0x72,
    0x8F, 0xAA, 0xFA, 0xC4, 0x8A, 0xE9, 0x26, 0x0A, 0x5A, 0x18, 0x4E, 0x29, 0x33, 0xE3, 0xA4, 0x00,
];

const BASE_Y: [u8; 64] = [
    0x05, 0x3A, 0x0D, 0x50, 0xCC, 0x63, 0xC9, 0x21, 0x97, 0x62, 0xF4, 0x51, 0x97, 0x8A, 0xEF, 0x21,
    0x4D, 0xBC, 0xFC, 0xC3, 0xA5, 0xCB, 0x5E, 0xF2, 0x71, 0x24, 0x99, 0x1A, 0x86, 0xB4, 0x2B, 0x3A,
    0x1A, 0x83, 0x27, 0x24, 0xA0, 0xE6, 0xB9, 0x30, 0xFD, 0xD1, 0xDA, 0x2E, 0x27, 0xA5, 0x40, 0xD6,
    0xB6, 0x75, 0xE4, 0x42, 0x2C, 0x44, 0x4F, 0x52, 0x9C, 0x50, 0x8F, 0x0B, 0xAE, 0x7D, 0x0A, 0x85,
];

/// The base point's order `n` (also `E512/1`'s recommended curve prime order, D-176).
const ORDER_N: [u8; 64] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x28, 0xA3, 0xCE, 0x52, 0x20, 0x9E, 0x2B, 0xD4, 0x95, 0x28, 0x82, 0xD5, 0x57, 0x41, 0x65, 0x19,
    0x2C, 0x46, 0xC0, 0xD0, 0x31, 0x1F, 0xEA, 0x6B, 0xF9, 0xFE, 0xCE, 0x70, 0xEE, 0x63, 0xB5, 0x9F,
];

pub(crate) fn curve_a() -> FieldElement {
    let mut bytes = [0u8; 64];
    bytes[63] = 2;
    FieldElement::from_be_bytes(&bytes)
}

pub(crate) fn curve_d() -> FieldElement {
    let mut bytes = [0u8; 64];
    bytes[62] = 0x01;
    bytes[63] = 0x0D;
    FieldElement::from_be_bytes(&bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

    /// Constant-time scalar multiplication, fixed 512 iterations MSB-first, `scalar` big-endian.
    #[must_use]
    pub fn scalar_multiply(self, scalar: &[u8; 64]) -> Self {
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
    /// 512-bit field.
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
    let p_minus_1 = FieldElement::ZERO.sub(FieldElement::ONE);
    let x_squared = x.square();

    if x == FieldElement::ZERO
        || x == FieldElement::ONE
        || x == p_minus_1
        || x_squared == a.multiply(d.invert())
    {
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
pub fn order() -> [u8; 64] {
    ORDER_N
}

#[allow(clippy::needless_range_loop)]
fn bytes_be_to_limbs(bytes: &[u8; 64]) -> [u64; 8] {
    let mut limbs = [0u64; 8];
    let mut limb_bytes = [0u8; 8];
    for i in 0..8 {
        limb_bytes.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        limbs[7 - i] = u64::from_be_bytes(limb_bytes);
    }
    limbs
}

/// `true` iff `a < b`, both interpreted as big-endian unsigned 512-bit integers. Branchless
/// (fixed 8-limb `sbb` chain), no data-dependent control flow.
#[allow(clippy::needless_range_loop)]
fn is_less_than(a: &[u8; 64], b: &[u8; 64]) -> bool {
    let al = bytes_be_to_limbs(a);
    let bl = bytes_be_to_limbs(b);
    let mut borrow = 0u64;
    for i in 0..8 {
        let (_, bw) = sbb(al[i], bl[i], borrow);
        borrow = bw;
    }
    borrow == 1
}

/// `1 < scalar < n-1`, constant-time - same precondition `curve256.rs::is_valid_scalar` enforces.
#[must_use]
pub fn is_valid_scalar(scalar: &[u8; 64]) -> bool {
    let mut one = [0u8; 64];
    one[63] = 1;
    let mut n_minus_1 = ORDER_N;
    // n is odd (prime) - decrementing its last byte alone never borrows across bytes.
    n_minus_1[63] -= 1;

    let scalar_gt_one = is_less_than(&one, scalar);
    let scalar_lt_n_minus_1 = is_less_than(scalar, &n_minus_1);
    scalar_gt_one & scalar_lt_n_minus_1
}
