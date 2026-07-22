//! DSTU 4145-2002's m=163 curve: `y^2 + xy = x^3 + a*x^2 + b` over GF(2^163), `a = 1` - the curve
//! dual-sourced in `tests/vectors/dstu4145/gf2m163.json` (`DECISIONS.md` D-14), matching
//! `oracles/bouncycastle-java/.../DSTU4145NamedCurves.java`'s `ECCurve.F2m(163, 3, 6, 7, ...)`.
//!
//! `double`/`add` below are plain affine formulas with ordinary branches (`==`) on the point
//! coordinates. That's only safe on **public** data - both are meant for the verification path
//! (`s*G + r*Q`, entirely public inputs), never for a secret scalar's intermediate state.
//! `scalar_multiply` is the one function used with secret scalars (DSTU 4145 signing's ephemeral
//! `e`) as well as public ones (`s`, `r` in verification) - same code path either way, so there is
//! no branch that could leak which case it is (`DECISIONS.md` D-25).

use super::gf2m163::FieldElement;

fn b() -> FieldElement {
    FieldElement::from_be_bytes(&[
        0x05, 0xFF, 0x61, 0x08, 0x46, 0x2A, 0x2D, 0xC8, 0x21, 0x0A, 0xB4, 0x03, 0x92, 0x5E, 0x63,
        0x8A, 0x19, 0xC1, 0x45, 0x5D, 0x21,
    ])
}

fn gx() -> FieldElement {
    FieldElement::from_be_bytes(&[
        0x07, 0x2D, 0x86, 0x7F, 0x93, 0xA9, 0x3A, 0xC2, 0x7D, 0xF9, 0xFF, 0x01, 0xAF, 0xFE, 0x74,
        0x88, 0x5C, 0x8C, 0x54, 0x04, 0x20,
    ])
}

fn gy() -> FieldElement {
    FieldElement::from_be_bytes(&[
        0x00, 0x22, 0x4A, 0x9C, 0x39, 0x47, 0x85, 0x2B, 0x97, 0xC5, 0x59, 0x9D, 0x5F, 0x4A, 0xB8,
        0x11, 0x22, 0xAD, 0xC3, 0xFD, 0x9B,
    ])
}

/// The curve's group order `n` (big-endian, 21 bytes) - `gf2m163.json`'s `order_n`. Not a
/// `FieldElement`: this is an ordinary integer modulus for scalar (private-key/nonce) arithmetic,
/// unrelated to the curve's `GF(2^163)` polynomial field.
#[must_use]
pub fn order() -> [u8; 21] {
    [
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xBE, 0xC1, 0x2B, 0xE2,
        0x26, 0x2D, 0x39, 0xBC, 0xF1, 0x4D,
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

    /// `-P`: for this curve family, negation is `(x, y) -> (x, x + y)` (char-2 identity - see
    /// `double`/`add`'s comment on the same fact). Used to derive a DSTU 4145 public key
    /// `Q = -d*G` from a private key `d` (`DECISIONS.md` D-25's follow-up note on this - Bouncy
    /// Castle's `DSTU4145KeyPairGenerator` negates explicitly; the pseudocode doc's "`Q = d*G`"
    /// line undersold this).
    #[must_use]
    pub fn negate(self) -> Self {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine(x, y) => Point::Affine(x, x + y),
        }
    }

    /// Affine point doubling for `y^2 + xy = x^3 + x^2 + b` (`a = 1` fixed for this curve).
    /// Standard formulas (`Guide to Elliptic Curve Cryptography`, Hankerson/Menezes/Vanstone,
    /// `§3.1.2`) - branches on `x1 == 0` are fine here, see the module doc: this is never called
    /// on a secret-dependent point.
    #[must_use]
    pub fn double(self) -> Self {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine(x1, y1) => {
                if x1 == FieldElement::ZERO {
                    return Point::Infinity;
                }
                let lambda = x1 + y1.multiply(x1.invert());
                let x3 = lambda.square() + lambda + FieldElement::ONE;
                let y3 = x1.square() + (lambda + FieldElement::ONE).multiply(x3);
                Point::Affine(x3, y3)
            }
        }
    }

    /// Constant-time scalar multiplication: `k * self`, `k` a big-endian 163-bit scalar (top 5
    /// bits of `k[0]` must be zero - values are always < the curve order, which is < `2^163`).
    ///
    /// Montgomery's method for binary-curve point multiplication (`Guide to Elliptic Curve
    /// Cryptography`, Algorithm 3.40) computes only X/Z-projective coordinates through the main
    /// loop, recovering the affine `y` at the end from the original point. Two adaptations from
    /// the textbook algorithm, both needed for `DECISIONS.md` D-25's branchless posture:
    ///
    /// - The textbook version starts from `(P, 2P)` and loops only over the bits below `k`'s
    ///   *actual* highest set bit - a loop bound that depends on the secret scalar's magnitude.
    ///   This starts from `(Infinity, P)` instead (`Z = 0` represents infinity in this coordinate
    ///   system - doubling or adding into it stays at `Z = 0`, verified algebraically against the
    ///   same formulas below) and always runs the full 163 iterations, so leading zero bits of a
    ///   smaller scalar cost nothing extra and leak nothing about where the top bit actually is.
    /// - Each iteration's `if k_i == 1 {...} else {...}` (textbook step 2.1/2.2) is two formulas
    ///   that are identical in shape, differing only in which of the two (X, Z) pairs plays which
    ///   role. Implemented here as: conditionally swap the pair (branchless, via a XOR/mask swap)
    ///   based on the bit, always run the "`k_i == 1`" formula, then swap back - the same
    ///   operations execute on every iteration regardless of the bit's value.
    #[must_use]
    pub fn scalar_multiply(self, k: &[u8; 21]) -> Self {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine(x, y) => {
                let mut x1 = FieldElement::ONE;
                let mut z1 = FieldElement::ZERO; // (x1 : z1) = Infinity
                let mut x2 = x;
                let mut z2 = FieldElement::ONE; // (x2 : z2) = P

                for i in (0..163u32).rev() {
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

                let x1_affine = x1.multiply(z1.invert());
                let x2_affine = x2.multiply(z2.invert());
                let t1 = x1_affine + x;
                let t2 = x2_affine + x;
                let inner = t1.multiply(t2) + x.square() + y;
                let y1_affine = x.invert().multiply(t1).multiply(inner) + y;
                Point::Affine(x1_affine, y1_affine)
            }
        }
    }
}

impl core::ops::Add for Point {
    type Output = Self;

    /// Affine point addition. Same public-data-only caveat as `double` - see the module doc.
    fn add(self, other: Self) -> Self {
        match (self, other) {
            (Point::Infinity, q) => q,
            (p, Point::Infinity) => p,
            (Point::Affine(x1, y1), Point::Affine(x2, y2)) => {
                if x1 == x2 {
                    if y1 == y2 {
                        return self.double();
                    }
                    // x1 == x2 and y1 != y2: the only other point sharing x1 is -P = (x1, x1+y1)
                    // (char-2 curve of this form), so `other` must be `-self`.
                    return Point::Infinity;
                }
                let lambda = (y1 + y2).multiply((x1 + x2).invert());
                let x3 = lambda.square() + lambda + x1 + x2 + FieldElement::ONE;
                let y3 = lambda.multiply(x1 + x3) + x3 + y1;
                Point::Affine(x3, y3)
            }
        }
    }
}

fn bit_at(bytes: &[u8; 21], i: u32) -> u64 {
    let byte_index = 20 - (i / 8) as usize;
    let bit_in_byte = i % 8;
    u64::from((bytes[byte_index] >> bit_in_byte) & 1)
}

/// Constant-time conditional swap: swaps `a` and `b` in place when `swap == 1`, leaves both
/// unchanged when `swap == 0` - no branch, same word operations either way.
fn cswap(swap: u64, a: &mut FieldElement, b: &mut FieldElement) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..3 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}
