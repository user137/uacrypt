//! `F_p` arithmetic for DSTU 9041's `l(p)=256` case, E256/1's prime `p = 2^256 - 435` (clauses
//! 6.5-6.8 - see `docs/pseudocode/dstu9041.md`, `docs/DECISIONS.md` D-163/D-166 for the citation
//! and the erratum this modulus was corrected against). `p`'s closeness to a power of two (a
//! 9-bit complement `C=435`) is what `reduce_wide` exploits: `2^256 ≡ C (mod p)`, so a 512-bit
//! product folds down via a couple of small multiply-and-add passes instead of general long
//! division.
//!
//! Fixed-width `[u64; 4]` (little-endian limbs), mirroring `hazmat::dstu4145::gf2m163`'s own
//! fixed-163-bit precedent - a future `l(p)=384/512` pass gets its own sibling type, not a
//! generalized one now.

/// `p`'s limbs, little-endian (`P_LIMBS[0]` is the least-significant 64 bits).
const P_LIMBS: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FE4D,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// `p = 2^256 - C`.
const C: u64 = 435;

/// `p - 2`, for `invert` via Fermat's little theorem (clause 6.8's result, substituted for the
/// literal extended-Euclidean algorithm - precedented by `gf2m163::invert`, D-109).
const P_MINUS_2: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x4B,
];

/// `(p-1)/2`, for `euler_criterion` (clause 6.6 applied to the Euler/Legendre exponent).
const P_MINUS_1_OVER_2: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x26,
];

/// `(p-1)/4`, for `sqrt`'s `f = v^((p-1)/4)` branch check (clause 6.7, `p ≡ 5 (mod 8)`).
const P_MINUS_1_OVER_4: [u8; 32] = [
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x93,
];

/// `(p+3)/8`, for `sqrt`'s candidate root `z = v^((p+3)/8)` (clause 6.7).
const P_PLUS_3_OVER_8: [u8; 32] = [
    0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xCA,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement([u64; 4]);

#[inline]
fn adc(a: u64, b: u64, carry_in: u64) -> (u64, u64) {
    let (s1, c1) = a.overflowing_add(b);
    let (s2, c2) = s1.overflowing_add(carry_in);
    (s2, u64::from(c1) | u64::from(c2))
}

#[inline]
pub(crate) fn sbb(a: u64, b: u64, borrow_in: u64) -> (u64, u64) {
    let (d1, b1) = a.overflowing_sub(b);
    let (d2, b2) = d1.overflowing_sub(borrow_in);
    (d2, u64::from(b1) | u64::from(b2))
}

#[inline]
#[allow(clippy::needless_range_loop)]
// fixed 4-limb unroll, index shared across a/b/r - the clear
// shape here, per this project's own D-39 precedent
#[allow(clippy::many_single_char_names)] // a/b/r/i/c mirror the standard adc/sbb limb-arithmetic
                                         // naming used throughout bignum code
fn add_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s, c) = adc(a[i], b[i], carry);
        r[i] = s;
        carry = c;
    }
    (r, carry)
}

/// Subtracts `p` from `x` if `x >= p`, otherwise returns `x` unchanged - branchless (mask-select),
/// no data-dependent control flow.
#[inline]
#[allow(clippy::needless_range_loop)]
fn conditional_sub_p(x: [u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, bw) = sbb(x[i], P_LIMBS[i], borrow);
        t[i] = d;
        borrow = bw;
    }
    // borrow == 0 means x >= p (subtraction succeeded) -> take t; borrow == 1 means x < p -> keep x.
    let mask = 0u64.wrapping_sub(borrow ^ 1);
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = (t[i] & mask) | (x[i] & !mask);
    }
    out
}

/// `a * c` for a small constant `c < 2^16`, returning the low 256 bits plus a tiny overflow limb.
#[inline]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::cast_possible_truncation)] // deliberate: `sum as u64` takes the low 64 bits, the
                                           // rest is captured by the shifted-out `carry`
fn mul_small(a: [u64; 4], c: u64) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let sum = u128::from(a[i]) * u128::from(c) + carry;
        r[i] = sum as u64;
        carry = sum >> 64;
    }
    (r, carry as u64)
}

/// Schoolbook 4x4-limb multiply producing an 8-limb (512-bit) wide product. Carry propagation
/// after each row is a fixed-length pass over the remaining limbs (bounded by the row index `i`,
/// a public loop position, not secret data) - no early exit.
#[inline]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::cast_possible_truncation)] // deliberate: low-64-bits extraction, see mul_small
fn wide_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let idx = i + j;
            let sum = u128::from(r[idx]) + u128::from(a[i]) * u128::from(b[j]) + carry;
            r[idx] = sum as u64;
            carry = sum >> 64;
        }
        let mut idx = i + 4;
        let mut c = carry as u64;
        while idx < 8 {
            let sum = u128::from(r[idx]) + u128::from(c);
            r[idx] = sum as u64;
            c = (sum >> 64) as u64;
            idx += 1;
        }
    }
    r
}

/// Folds a 512-bit wide product down to a fully-reduced `< p` value, using `2^256 ≡ C (mod p)`.
fn reduce_wide(wide: [u64; 8]) -> FieldElement {
    let low: [u64; 4] = [wide[0], wide[1], wide[2], wide[3]];
    let high: [u64; 4] = [wide[4], wide[5], wide[6], wide[7]];

    let (hc, hc_top) = mul_small(high, C);
    let (acc, carry) = add_limbs(low, hc);
    let overflow = carry + hc_top;

    let addition = overflow.wrapping_mul(C);
    let (acc2, carry2) = add_limbs(acc, [addition, 0, 0, 0]);

    let addition2 = carry2.wrapping_mul(C);
    let (acc3, _carry3) = add_limbs(acc2, [addition2, 0, 0, 0]);

    let r1 = conditional_sub_p(acc3);
    let r2 = conditional_sub_p(r1);
    let r3 = conditional_sub_p(r2);
    FieldElement(r3)
}

impl FieldElement {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Interprets `bytes` (big-endian) as a field element. Precondition: `bytes` encodes a value
    /// `< p` - callers that can't guarantee this should use [`from_candidate_bytes`] instead.
    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        let mut limb_bytes = [0u8; 8];
        for i in 0..4 {
            limb_bytes.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[3 - i] = u64::from_be_bytes(limb_bytes);
        }
        Self(limbs)
    }

    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)]
    // deliberate: value-returning, not the mutating
    // `std::ops::Add`/`Sub` shape - matches curve-point
    // additions elsewhere in this crate's own style
    #[allow(clippy::needless_range_loop)]
    pub fn add(self, other: Self) -> Self {
        let (r, carry) = add_limbs(self.0, other.0);
        let mut t = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, bw) = sbb(r[i], P_LIMBS[i], borrow);
            t[i] = d;
            borrow = bw;
        }
        // r (with its carry limb) >= p iff carry==1 (definitely overflowed p) or borrow==0 (the
        // direct subtraction succeeded without needing the carry limb).
        let take_t = carry | (borrow ^ 1);
        let mask = 0u64.wrapping_sub(take_t);
        let mut out = [0u64; 4];
        for i in 0..4 {
            out[i] = (t[i] & mask) | (r[i] & !mask);
        }
        Self(out)
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)]
    #[allow(clippy::needless_range_loop)]
    pub fn sub(self, other: Self) -> Self {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, bw) = sbb(self.0[i], other.0[i], borrow);
            r[i] = d;
            borrow = bw;
        }
        // borrow==1 means self < other: r currently equals (self - other) mod 2^256, i.e.
        // (self-other)+2^256; subtracting C once corrects it to (self-other)+p, landing in [0,p).
        let mask = 0u64.wrapping_sub(borrow);
        let mut out = [0u64; 4];
        let mut inner_borrow = 0u64;
        for i in 0..4 {
            let sub_val = if i == 0 { C & mask } else { 0 };
            let (d, bw) = sbb(r[i], sub_val, inner_borrow);
            out[i] = d;
            inner_borrow = bw;
        }
        Self(out)
    }

    #[must_use]
    pub fn multiply(self, other: Self) -> Self {
        reduce_wide(wide_mul(self.0, other.0))
    }

    #[must_use]
    pub fn square(self) -> Self {
        self.multiply(self)
    }

    /// `bit` must be exactly `0` or `1` - a `2` would silently interleave `a`/`b`'s limbs instead
    /// of picking one whole (`mask = 0u64.wrapping_sub(bit)` only yields all-0s/all-1s at those two
    /// values). Checked here rather than trusted at each call site (this project's own
    /// "provable from the line, not by hand-traced invariant" bounds-safety rule).
    #[inline]
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn select(bit: u64, a: Self, b: Self) -> Self {
        debug_assert!(bit <= 1, "select's bit argument must be 0 or 1");
        let mask = 0u64.wrapping_sub(bit);
        let mut out = [0u64; 4];
        for i in 0..4 {
            out[i] = (a.0[i] & mask) | (b.0[i] & !mask);
        }
        Self(out)
    }

    /// Constant-time square-and-multiply (clause 6.6), fixed 256 iterations MSB-first, `exponent`
    /// big-endian. SECURITY: this routes secret-scalar-derived data once `invert` (via Fermat) and
    /// `ProjectivePoint::to_affine` compose - not just a defensive margin, a traced dependency
    /// (design decision 3, `docs/pseudocode/dstu9041.md`/plan).
    #[must_use]
    pub fn pow_mod(self, exponent: &[u8; 32]) -> Self {
        let mut result = Self::ONE;
        for &byte in exponent {
            for bit_idx in (0..8).rev() {
                result = result.square();
                let bit = u64::from((byte >> bit_idx) & 1);
                let candidate = result.multiply(self);
                result = Self::select(bit, candidate, result);
            }
        }
        result
    }

    /// Multiplicative inverse via Fermat's little theorem (`self^(p-2)`). `invert(ZERO) == ZERO`
    /// (a defined-but-meaningless result, never a panic) - see the boundary test in
    /// `tests/dstu9041_field.rs` and `curve256.rs`'s tracing of whether this is ever reached on a
    /// genuine zero.
    #[must_use]
    pub fn invert(self) -> Self {
        self.pow_mod(&P_MINUS_2)
    }

    /// Euler's criterion: `true` iff `self` is a nonzero quadratic residue mod `p`. Returns
    /// `false` for `ZERO` (zero is conventionally excluded from "is a residue").
    #[must_use]
    pub fn euler_criterion(self) -> bool {
        self.pow_mod(&P_MINUS_1_OVER_2) == Self::ONE
    }

    /// Square root for `p ≡ 5 (mod 8)` (clause 6.7). Unconditional - callers must check
    /// [`Self::euler_criterion`] first if they need to know whether `self` is actually a residue;
    /// `sqrt(ZERO) == ZERO` by construction (both branches of the formula yield zero).
    #[must_use]
    pub fn sqrt(self) -> Self {
        let f = self.pow_mod(&P_MINUS_1_OVER_4);
        let z = self.pow_mod(&P_PLUS_3_OVER_8);
        // p-1: P_LIMBS[0] (ends ..FE4D) minus 1 needs no borrow (its low byte is 0x4D > 0).
        let p_minus_1 = Self([P_LIMBS[0] - 1, P_LIMBS[1], P_LIMBS[2], P_LIMBS[3]]);
        let is_minus_one = u64::from(f == p_minus_1);
        let w = Self(W);
        let z_corrected = w.multiply(z);
        Self::select(is_minus_one, z_corrected, z)
    }
}

/// `w = 2^((p-1)/4) mod p`, precomputed (independently cross-checked via Python in this session).
const W: [u64; 4] = {
    // FA3A4105C178A375 06B724D287DA9D3A FDEF5BA9F4C42B4B 74956ADEF6968654 (big-endian groups)
    [
        0x7495_6ADE_F696_8654,
        0xFDEF_5BA9_F4C4_2B4B,
        0x06B7_24D2_87DA_9D3A,
        0xFA3A_4105_C178_A375,
    ]
};

/// Rejection-samples `bytes` (big-endian) into a [`FieldElement`], `None` if `bytes >= p` (clause
/// 6.5). Accepts the full `[0, p-1]` range including both `0` and `p-1`.
#[must_use]
#[allow(clippy::needless_range_loop)]
pub fn from_candidate_bytes(bytes: &[u8; 32]) -> Option<FieldElement> {
    let candidate = FieldElement::from_be_bytes(bytes);
    let mut borrow = 0u64;
    for i in 0..4 {
        let (_, bw) = sbb(candidate.0[i], P_LIMBS[i], borrow);
        borrow = bw;
    }
    // borrow == 1 iff candidate < p.
    if borrow == 1 {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(test)]
mod private_constant_tests {
    use super::{FieldElement, P_LIMBS, W};

    /// `W` is only exercised by `sqrt` on the branch where `f == p-1`; nothing in the black-box
    /// test file guarantees any concrete `sqrt` call actually takes that branch, so pin `W`
    /// directly here via an identity already established in `dstu9041_field.rs`: `2` is a
    /// documented non-residue, so `2^((p-1)/2) == p-1`, i.e. `W^2 == (2^((p-1)/4))^2 == p-1`
    /// (advisor review, 2026-08-05).
    #[test]
    fn w_squared_is_p_minus_1() {
        let p_minus_1 = FieldElement([P_LIMBS[0] - 1, P_LIMBS[1], P_LIMBS[2], P_LIMBS[3]]);
        assert_eq!(FieldElement(W).square(), p_minus_1);
    }
}
