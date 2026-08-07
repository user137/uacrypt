//! DSTU 4145-2002's m=163 curve: `y^2 + xy = x^3 + a*x^2 + b` over GF(2^163), `a = 1` - the curve
//! dual-sourced in `tests/vectors/dstu4145/gf2m163.json` (`docs/DECISIONS.md` D-14), matching
//! `oracles/bouncycastle-java/.../DSTU4145NamedCurves.java`'s `ECCurve.F2m(163, 3, 6, 7, ...)`.
//!
//! `double`/`add` below are plain affine formulas with ordinary branches (`==`) on the point
//! coordinates. That's only safe on **public** data - both are meant for the verification path
//! (`s*G + r*Q`, entirely public inputs), never for a secret scalar's intermediate state.
//!
//! `scalar_multiply` is the sole implementation for **secret**-scalar use (signing's ephemeral
//! `e`, and `Q = -d*G`'s private-key-derived `d`) - identical in every build configuration, never
//! replaced. Under the `small-tables` feature, it is *also* still used for `verify`'s public-scalar
//! computation, exactly as before. By default (feature off), `verify` instead uses
//! `verify_combine`'s projective (López-Dahab)/Shamir's-trick fast path below, which is **not**
//! constant-time and must never be called with a secret scalar (`docs/DECISIONS.md` D-108) - the
//! module's public/secret split is now carried by *which function is called*, not by one shared
//! code path the way D-25 originally described it.

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
    /// `Q = -d*G` from a private key `d` (`docs/DECISIONS.md` D-25's follow-up note on this - Bouncy
    /// Castle's `DSTU4145KeyPairGenerator` negates explicitly; the pseudocode doc's "`Q = d*G`"
    /// line undersold this).
    #[must_use]
    pub fn negate(self) -> Self {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine(x, y) => Point::Affine(x, x + y),
        }
    }

    /// Checks `y^2 + xy == x^3 + x^2 + b` (`a = 1` fixed for this curve, matching `double`'s own
    /// assumption above). `Infinity` is not a solution of this affine equation and returns
    /// `false` - callers that must also accept the group identity check for it separately (see
    /// `signature::verify`, `docs/TASKS.md` T-189). Public-data check (never called on a
    /// secret-dependent point, same posture as `double`/`add`).
    #[must_use]
    pub fn is_on_curve(self) -> bool {
        match self {
            Point::Infinity => false,
            Point::Affine(x, y) => {
                let lhs = y.square() + x.multiply(y);
                let rhs = x.multiply(x.square()) + x.square() + b();
                lhs == rhs
            }
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
    /// the textbook algorithm, both needed for `docs/DECISIONS.md` D-25's branchless posture:
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
    ///
    /// The final X-only-to-affine recovery needs `kP` and `(k+1)P` to both be finite points -
    /// undefined at the two boundary values where that fails (`k == 0`/`k == ord(self)`, and
    /// `k == ord(self) - 1` respectively). `docs/DECISIONS.md` D-110 (T-152) found and fixed a real
    /// bug here: the recovery silently used `invert(ZERO) == ZERO` instead of detecting either
    /// case, producing a wrong-but-plausible-looking result rather than failing loudly or
    /// computing the right answer. See the `z1 == ZERO`/`z2 == ZERO` handling in the body below.
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

                // `z1 == ZERO` means `kP == Infinity` (`k == 0`, or `k == ord(self)` - only
                // reachable at or past the edge of this function's documented `k < n` domain for a
                // full-order point). `Point::Infinity` is a different enum variant from
                // `Point::Affine`, not a same-shape value a branchless mask can select between
                // (unlike the `z2 == ZERO` case below) - this needs an explicit branch.
                // `docs/DECISIONS.md` D-110 (T-152): this only fires for `k == 0` or `k >=
                // ord(self)`, never for an in-range secret scalar DSTU 4145 sign/verify actually
                // constructs, so it is not a fresh timing side channel for real callers - a
                // deliberate, named exception to this function's otherwise branchless posture,
                // not left as silently-wrong output the way it was before this fix. The zero
                // *test* itself still uses `is_zero_mask` (fixed-shape, no secret-dependent `==`)
                // rather than `FieldElement`'s derived `PartialEq` - only the resulting branch on
                // that mask is data-dependent, which is unavoidable given `Point::Infinity` is a
                // different enum variant (`docs/SECURITY.md`'s "never `==` on secret data" rule).
                if is_zero_mask(z1) != 0 {
                    return Point::Infinity;
                }

                let x1_affine = x1.multiply(z1.invert());
                let x2_affine = x2.multiply(z2.invert());
                let t1 = x1_affine + x;
                let t2 = x2_affine + x;
                let inner = t1.multiply(t2) + x.square() + y;
                let y1_affine_formula = x.invert().multiply(t1).multiply(inner) + y;

                // `z2 == ZERO` means `(k+1)P == Infinity`, i.e. `k == ord(self) - 1` - genuinely
                // inside the documented `k < n` contract (`docs/DECISIONS.md` D-110, T-152). The
                // y-recovery formula above needs `(k+1)P`'s affine x-coordinate, which doesn't
                // exist for infinity; `x2.multiply(z2.invert())` silently reads `invert(ZERO) ==
                // ZERO` instead, corrupting `y1_affine_formula`. The correct `kP` in that case is
                // exactly `-self = (x, x + y)` (`Point::negate`) - `x1_affine` already comes out
                // right either way (`self`/`-self` share an x-coordinate on this curve family), so
                // only `y` needs correcting. Selected branchlessly (same mask-and-XOR shape as
                // `cswap` above, not `==`/`if`) since `z2` is secret-scalar-derived and both
                // candidate values are same-shape field elements.
                let y1_affine = select(is_zero_mask(z2), x + y, y1_affine_formula);

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

/// Constant-time "is this field element zero" test: an all-ones mask if so, all-zeros otherwise.
/// The standard `x | wrapping_neg(x)` top-bit branchless zero test (for any nonzero `x`, either
/// `x` or `-x` has its sign bit set in two's-complement; for `x == 0` neither does), applied to
/// the OR of all 3 limbs (any single nonzero limb makes the whole element nonzero) - `docs/
/// DECISIONS.md` D-110 (T-152).
fn is_zero_mask(a: FieldElement) -> u64 {
    let combined = a.0[0] | a.0[1] | a.0[2];
    let is_nonzero = (combined | combined.wrapping_neg()) >> 63;
    0u64.wrapping_sub(1 ^ is_nonzero)
}

/// Constant-time select: returns `if_mask` when `mask` is all-ones, `otherwise` when all-zeros -
/// same XOR-and-mask shape as `cswap`'s swap above, specialized to a one-sided select
/// (`docs/DECISIONS.md` D-110, T-152).
fn select(mask: u64, if_mask: FieldElement, otherwise: FieldElement) -> FieldElement {
    let mut out = [0u64; 3];
    for ((out_limb, a), b) in out.iter_mut().zip(if_mask.0.iter()).zip(otherwise.0.iter()) {
        *out_limb = b ^ (mask & (a ^ b));
    }
    FieldElement(out)
}

/// López-Dahab projective point: `(X:Y:Z)` represents affine `(x, y) = (X/Z, Y/Z^2)` - **note the
/// asymmetric scaling** (`Y` by `Z^2`, not `Z`, unlike Jacobian coordinates). `Z == FieldElement::
/// ZERO` represents the point at infinity (any `X`/`Y` at that point are unconstrained - `to_affine`
/// checks `Z` first and never reads them). Used only by `verify_combine`'s default-profile fast
/// path below (`docs/DECISIONS.md` D-108) - public-data-only, never constant-time, never for a
/// secret scalar. `double`/`mixed_add` below are the explicit formulas "dbl-2005-dl"/"madd-2005-dl"
/// from the Bernstein/Lange Explicit-Formulas Database (`hyperelliptic.org/EFD/g12o/auto-shortw-
/// lopezdahab.html`), specialized to this curve's `a2 = 1` (the module's `a = 1` convention) -
/// their stated costs (4M+5S doubling, 8M+5S mixed addition) were independently re-derived by
/// listing every `multiply`/`square` call below and matched the database's own count exactly,
/// which is the actual correctness check for the transcription (this codebase has no local copy of
/// a citable textbook derivation to check against page numbers, only the differential proptest in
/// `tests/dstu4145_curve.rs` and this cost cross-check).
#[cfg(not(feature = "small-tables"))]
#[derive(Clone, Copy)]
struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

#[cfg(not(feature = "small-tables"))]
impl ProjectivePoint {
    fn from_affine(p: Point) -> Self {
        match p {
            Point::Infinity => ProjectivePoint {
                x: FieldElement::ONE,
                y: FieldElement::ONE,
                z: FieldElement::ZERO,
            },
            Point::Affine(x, y) => ProjectivePoint {
                x,
                y,
                z: FieldElement::ONE,
            },
        }
    }

    /// "dbl-2005-dl", `a2 = 1`: `A = Z1^2; B = b*A^2; C = X1^2; Z3 = A*C; X3 = C^2+B;
    /// Y3 = (Y1^2+Z3+B)*X3 + Z3*B` (the database's `a2*Z3` term is just `Z3` here, since `a2=1`).
    /// A point with affine `x = 0` (order-2 point) doubles to infinity automatically through this
    /// formula (`C = X1^2 = 0` forces `Z3 = A*C = 0`), matching the affine `double`'s explicit
    /// `x1 == ZERO` check above without needing a separate branch here.
    fn double(self) -> Self {
        if self.z == FieldElement::ZERO {
            return self; // doubling infinity is infinity
        }
        let a = self.z.square();
        let big_b = b().multiply(a.square());
        let c = self.x.square();
        let z3 = a.multiply(c);
        let x3 = c.square() + big_b;
        let y3 = (self.y.square() + z3 + big_b).multiply(x3) + z3.multiply(big_b);
        ProjectivePoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// "madd-2005-dl", `a2 = 1`, `other` affine (`Z2 = 1`): `A = Y1+Y2*Z1^2; B = X1+X2*Z1;
    /// C = B*Z1; Z3 = C^2; D = X2*Z3; X3 = A^2+C*(A+B^2+C); Y3 = (D+X3)*(A*C+Z3)+(Y2+X2)*Z3^2`.
    /// Guarded ahead of the database's generic-case formula (which assumes neither operand is
    /// infinity and the two affine `x`-coordinates differ) for totality, not for attack
    /// resistance - `verify`'s final `r' == r` check (`signature.rs`) already closes off any
    /// benefit an attacker could get from steering the accumulator here; the guards exist because
    /// the formula is otherwise partial, on public data where an honest partial sum can
    /// structurally (if very rarely, ~2^-163) coincide with infinity or with the table point.
    fn mixed_add(self, other: Point) -> Self {
        let (x2, y2) = match other {
            Point::Infinity => return self,
            Point::Affine(x, y) => (x, y),
        };
        if self.z == FieldElement::ZERO {
            return ProjectivePoint::from_affine(other);
        }
        let z1_sq = self.z.square();
        let a = self.y + y2.multiply(z1_sq);
        let b_val = self.x + x2.multiply(self.z);
        if b_val == FieldElement::ZERO {
            return if a == FieldElement::ZERO {
                self.double() // same point (B=0 means matching affine x; A=0 means matching y too)
            } else {
                // matching x, differing y: char-2 negation is (x, x+y) (see `Point::negate`), so
                // this is `-self` - the sum is infinity.
                ProjectivePoint {
                    x: FieldElement::ONE,
                    y: FieldElement::ONE,
                    z: FieldElement::ZERO,
                }
            };
        }
        let c = b_val.multiply(self.z);
        let z3 = c.square();
        let d = x2.multiply(z3);
        let b_sq = b_val.square();
        let x3 = a.square() + c.multiply(a + b_sq + c);
        let y3 = (d + x3).multiply(a.multiply(c) + z3) + (y2 + x2).multiply(z3.square());
        ProjectivePoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// The one deferred inversion for the whole `verify_combine` computation: `x = X*Z^-1`,
    /// `y = Y*(Z^-1)^2` (matching the `(X/Z, Y/Z^2)` convention stated on the type itself).
    fn to_affine(self) -> Point {
        if self.z == FieldElement::ZERO {
            return Point::Infinity;
        }
        let z_inv = self.z.invert();
        let x = self.x.multiply(z_inv);
        let y = self.y.multiply(z_inv.square());
        Point::Affine(x, y)
    }
}

/// `s*g + r*q` via Shamir's trick (simultaneous double-and-add over both scalars, one shared
/// doubling per bit position) in projective coordinates, deferring every inversion to the single
/// one inside `to_affine` at the end - `docs/DECISIONS.md` D-108. Public data only (`g`, `s`, `q`,
/// `r` are all public in DSTU 4145 verification, per this module's own doc comment); safe to
/// branch on the scalars' actual bit lengths (skip leading zero bit-pairs) precisely because this
/// is not a secret-scalar code path, unlike `scalar_multiply`'s fixed 163 iterations.
#[cfg(not(feature = "small-tables"))]
fn shamir_double_scalar_multiply(g: Point, s: &[u8; 21], q: Point, r: &[u8; 21]) -> Point {
    let g_plus_q = g + q; // existing trusted affine `Point::add` - one inversion, paid once here
    let table = [Point::Infinity, q, g, g_plus_q]; // index (bit_s << 1) | bit_r

    let top = (0..163u32)
        .rev()
        .find(|&i| bit_at(s, i) != 0 || bit_at(r, i) != 0);
    let Some(top) = top else {
        return Point::Infinity; // s == r == 0 - not reachable via `verify`'s own guards
    };

    let entry_at = |i: u32| -> Point {
        // `bit_at` only ever returns 0 or 1, so this index is provably 0..=3 - no truncation
        // possible regardless of pointer width.
        #[allow(clippy::cast_possible_truncation)]
        let index = ((bit_at(s, i) << 1) | bit_at(r, i)) as usize;
        table[index]
    };

    let mut acc = ProjectivePoint::from_affine(entry_at(top));
    for i in (0..top).rev() {
        acc = acc.double();
        let entry = entry_at(i);
        if entry != Point::Infinity {
            acc = acc.mixed_add(entry);
        }
    }
    acc.to_affine()
}

/// `verify`'s `s*g + r*q` combine step - one function, two bodies, matching
/// `hazmat::tables::apply_forward_matrix`'s `small-tables` idiom exactly (no `#[cfg]` at the call
/// site in `signature.rs`). Default: the projective/Shamir fast path above. `small-tables`: today's
/// unchanged double `scalar_multiply` call - see `docs/DECISIONS.md` D-108 for why this reuses the
/// same feature Kalyna/Kupyna/Strumok use for their own big-table/small-table split, even though
/// this particular case is a code-size/audit-surface tradeoff, not a flash-`const`-table one (no
/// new `const` table is added; `{Infinity, g, q, g+q}` above is computed fresh per call).
#[cfg(not(feature = "small-tables"))]
#[must_use]
pub fn verify_combine(g: Point, s: &[u8; 21], q: Point, r: &[u8; 21]) -> Point {
    shamir_double_scalar_multiply(g, s, q, r)
}

#[cfg(feature = "small-tables")]
#[must_use]
pub fn verify_combine(g: Point, s: &[u8; 21], q: Point, r: &[u8; 21]) -> Point {
    g.scalar_multiply(s) + q.scalar_multiply(r)
}
