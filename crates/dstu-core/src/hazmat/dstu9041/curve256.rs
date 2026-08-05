//! Twisted Edwards point arithmetic over E256/1 (clauses 3.18/7.2/Додаток Б.4 - see
//! `docs/pseudocode/dstu9041.md`, `docs/DECISIONS.md` D-163/D-165/D-166). Curve equation
//! (x/y-swapped relative to the textbook Bernstein-Lange form, per the primary text):
//! `x^2 + a*y^2 = d*x^2*y^2 + 1 (mod p)`, `a=2`, `d=0x18`.
//!
//! `Point{x,y}` has no `Infinity` variant - not because Edwards curves lack one (they don't,
//! clause 3.18 counts `D_{1,2}=(+-sqrt(a/d),inf)` in the curve's order), but because every point
//! this code ever produces or accepts is unreachable from those two singular points: the random-
//! point generator (clause 6.9, not implemented here) retries around them, and ciphertext
//! reconstruction excludes them via the `r^2=a*d^-1` check (plus the `r=p-1` check this module's
//! sibling `encryption.rs` adds - a genuine additional bad value found by advisor review, not
//! covered by the standard's literal clause 12 text; see `r_equals_p_minus_1_reconstructs_the_order_2_point`
//! in `tests/dstu9041_curve.rs` for the arithmetic proof).
//!
//! Scalar multiplication uses the complete Edwards addition law (Додаток Б.4) for both doubling
//! and adding - `d` non-square (guaranteed by 3.18/7.2 for every recommended curve) means this
//! formula has no exceptional/branching cases, so `scalar_multiply` is a fixed 256-iteration
//! double-and-select loop with no early exit and no add/double distinction.

use super::fp256::{sbb, FieldElement};

const BASE_X: [u8; 32] = [
    0x91, 0xF5, 0xD0, 0xE7, 0xE2, 0xD4, 0x17, 0xE3, 0x10, 0x8B, 0x13, 0xB0, 0x75, 0xCD, 0xC7, 0x75,
    0x60, 0x45, 0xF8, 0x42, 0x44, 0x79, 0xFC, 0xFE, 0x8F, 0x23, 0xD2, 0x72, 0x50, 0xA0, 0x88, 0x3F,
];

const BASE_Y: [u8; 32] = [
    0x74, 0x2F, 0x27, 0xA2, 0x68, 0x64, 0x1C, 0x9D, 0x7D, 0xDF, 0x69, 0x89, 0x2B, 0xE3, 0xDF, 0x3D,
    0x8F, 0x9C, 0xC5, 0x22, 0x60, 0xB8, 0x9A, 0x49, 0x53, 0xC8, 0x37, 0x9C, 0x7C, 0x0A, 0x21, 0x2B,
];

/// The base point's order `n` (also `E256/1`'s recommended curve prime order).
const ORDER_N: [u8; 32] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x29, 0xE2, 0x60, 0x87, 0x78, 0x9B, 0xC2, 0x81, 0x5B, 0xDF, 0xF9, 0x70, 0x93, 0x54, 0x3C, 0xCF,
];

fn curve_a() -> FieldElement {
    let mut bytes = [0u8; 32];
    bytes[31] = 2;
    FieldElement::from_be_bytes(&bytes)
}

fn curve_d() -> FieldElement {
    let mut bytes = [0u8; 32];
    bytes[31] = 0x18;
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

    /// Checks `x^2 + a*y^2 == d*x^2*y^2 + 1 (mod p)`. Public-data check (coordinates are never
    /// secret by the time this is called) - an ordinary branch is fine here, unlike
    /// `scalar_multiply`.
    #[must_use]
    pub fn is_on_curve(self) -> bool {
        let x2 = self.x.square();
        let y2 = self.y.square();
        let lhs = x2.add(curve_a().multiply(y2));
        let rhs = curve_d().multiply(x2).multiply(y2).add(FieldElement::ONE);
        lhs == rhs
    }

    /// Point addition (also correct for doubling and the neutral element - the formula is
    /// complete). A convenience wrapper around `ProjectivePoint::add`; `scalar_multiply` uses the
    /// projective form directly to avoid a per-iteration inversion.
    #[must_use]
    #[allow(clippy::should_implement_trait)] // deliberate: value-returning, not the mutating
                                             // `std::ops::Add` shape - matches fp256's own style
    pub fn add(self, other: Self) -> Self {
        ProjectivePoint::from_affine(self)
            .add(ProjectivePoint::from_affine(other))
            .to_affine()
    }

    /// Constant-time scalar multiplication (clause 6.12), fixed 256 iterations MSB-first,
    /// `scalar` big-endian. The accumulator starts at `NEUTRAL` and every iteration always
    /// doubles and always computes the candidate add before selecting - no early exit, no
    /// branch on the scalar's bits.
    #[must_use]
    pub fn scalar_multiply(self, scalar: &[u8; 32]) -> Self {
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

    /// The one inversion point in the whole scalar-multiplication ladder - `self.z` is a function
    /// of the secret scalar, so this composes into `FieldElement::invert`'s traced constant-time
    /// dependency (see `fp256.rs`'s `pow_mod` doc comment).
    fn to_affine(self) -> Point {
        let z_inv = self.z.invert();
        Point {
            x: self.x.multiply(z_inv),
            y: self.y.multiply(z_inv),
        }
    }

    /// Додаток Б.4's complete addition law: `A=Z1*Z2, B=A^2, C=X1*X2, D=Y1*Y2, E=d*C*D,
    /// F=B-E, G=B+E`, `X_R=A*G*(C-a*D)`, `Y_R=A*F*((X1+Y1)*(X2+Y2)-C-D)`, `Z_R=F*G`. Used for both
    /// doubling (`self==other`) and the neutral element uniformly - no exceptional cases, because
    /// `d` is a non-square (guaranteed by clause 3.18/7.2 for every recommended curve).
    #[allow(clippy::many_single_char_names)] // a/d/b/c/e/f/g mirror Додаток Б.4's own notation
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

#[must_use]
pub fn base_point() -> Point {
    Point {
        x: FieldElement::from_be_bytes(&BASE_X),
        y: FieldElement::from_be_bytes(&BASE_Y),
    }
}

#[must_use]
pub fn order() -> [u8; 32] {
    ORDER_N
}

#[allow(clippy::needless_range_loop)]
fn bytes_be_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    let mut limb_bytes = [0u8; 8];
    for i in 0..4 {
        limb_bytes.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        limbs[3 - i] = u64::from_be_bytes(limb_bytes);
    }
    limbs
}

/// `true` iff `a < b`, both interpreted as big-endian unsigned 256-bit integers. Branchless
/// (fixed 4-limb `sbb` chain), no data-dependent control flow - callers may pass secret data
/// (e.g. a private-key-shaped scalar in `is_valid_scalar`).
#[allow(clippy::needless_range_loop)]
fn is_less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let al = bytes_be_to_limbs(a);
    let bl = bytes_be_to_limbs(b);
    let mut borrow = 0u64;
    for i in 0..4 {
        let (_, bw) = sbb(al[i], bl[i], borrow);
        borrow = bw;
    }
    borrow == 1
}

/// `1 < scalar < n-1` (clause 6.12's own precondition on a usable exponent - the strict range
/// `{2, ..., n-2}`), constant-time.
#[must_use]
pub fn is_valid_scalar(scalar: &[u8; 32]) -> bool {
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut n_minus_1 = ORDER_N;
    // n is odd (prime) - decrementing its last byte alone never borrows across bytes.
    n_minus_1[31] -= 1;

    let scalar_gt_one = is_less_than(&one, scalar);
    let scalar_lt_n_minus_1 = is_less_than(scalar, &n_minus_1);
    scalar_gt_one & scalar_lt_n_minus_1
}
