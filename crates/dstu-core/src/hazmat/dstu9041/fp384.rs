//! `F_p` arithmetic for DSTU 9041's `l(p)=384` case, E384/1's prime `p = 2^384 - 2147` (T-297 -
//! `docs/pseudocode/dstu9041.md`, `docs/DECISIONS.md` D-241 for the transcription and its checks,
//! D-244 for this module). `2^384 ≡ C (mod p)` with the 12-bit `C = 2147` is what `reduce_wide`
//! exploits, the same shape as `fp256.rs` (`2^256 - 435`) and `fp512.rs` (`2^512 - 875`).
//!
//! Fixed-width `[u64; 6]` (little-endian limbs): a third sibling module, generated from `fp512.rs`
//! by script with every constant computed from `curve-E384-1.json` (D-178's lesson), not a generic
//! over width (owner decision, D-241).

use crate::hazmat::limb::{adc, mac, sbb};

/// `p`'s limbs, little-endian (`P_LIMBS[0]` is the least-significant 64 bits).
const P_LIMBS: [u64; 6] = [
    0xFFFF_FFFF_FFFF_F79D,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// `p = 2^384 - C`.
const C: u64 = 2147;

/// `p - 2`, for `invert` via Fermat's little theorem (same substitution `fp256.rs::invert`
/// already uses in place of the literal extended-Euclidean algorithm, D-109's precedent).
const P_MINUS_2: [u8; 48] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF7, 0x9B,
];

/// `(p-1)/2`, for `euler_criterion`.
const P_MINUS_1_OVER_2: [u8; 48] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFB, 0xCE,
];

/// `(p-1)/4`, for `sqrt`'s `f = v^((p-1)/4)` branch check (`p ≡ 5 (mod 8)`, confirmed D-241).
const P_MINUS_1_OVER_4: [u8; 48] = [
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xE7,
];

/// `(p+3)/8`, for `sqrt`'s candidate root `z = v^((p+3)/8)`.
const P_PLUS_3_OVER_8: [u8; 48] = [
    0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xF4,
];

// T-242: no derived `Debug` - a field element can be a secret intermediate (`kappa`'s source);
// the manual impl below never prints its value.
#[derive(Clone, Copy, PartialEq, Eq, zeroize::Zeroize)]
pub struct FieldElement([u64; 6]);

impl core::fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FieldElement(<redacted>)")
    }
}

#[inline]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::many_single_char_names)]
fn add_limbs(a: [u64; 6], b: [u64; 6]) -> ([u64; 6], u64) {
    let mut r = [0u64; 6];
    let mut carry = 0u64;
    for i in 0..6 {
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
fn conditional_sub_p(x: [u64; 6]) -> [u64; 6] {
    let mut t = [0u64; 6];
    let mut borrow = 0u64;
    for i in 0..6 {
        let (d, bw) = sbb(x[i], P_LIMBS[i], borrow);
        t[i] = d;
        borrow = bw;
    }
    // `black_box` keeps the mask from becoming a branch (D-225).
    let mask = core::hint::black_box(0u64.wrapping_sub(borrow ^ 1));
    let mut out = [0u64; 6];
    for i in 0..6 {
        out[i] = (t[i] & mask) | (x[i] & !mask);
    }
    out
}

/// `a * c` for a small constant `c < 2^16`, returning the low 384 bits plus a tiny overflow limb.
#[inline]
#[allow(clippy::needless_range_loop)]
fn mul_small(a: [u64; 6], c: u64) -> ([u64; 6], u64) {
    let mut r = [0u64; 6];
    let mut carry = 0u64;
    for i in 0..6 {
        (r[i], carry) = mac(0, a[i], c, carry);
    }
    (r, carry)
}

/// Schoolbook 6x6-limb multiply producing a 12-limb (768-bit) wide product. Carry propagation
/// after each row is a fixed-length pass over the remaining limbs (bounded by the row index `i`,
/// a public loop position, not secret data) - no early exit.
#[inline]
#[allow(clippy::needless_range_loop)]
fn wide_mul(a: [u64; 6], b: [u64; 6]) -> [u64; 12] {
    let mut r = [0u64; 12];
    for i in 0..6 {
        let mut carry = 0u64;
        for j in 0..6 {
            let idx = i + j;
            (r[idx], carry) = mac(r[idx], a[i], b[j], carry);
        }
        let mut idx = i + 6;
        // `carry` may be any `u64` here: it goes in as `adc`'s addend, not its carry-in.
        let mut c = carry;
        while idx < 12 {
            (r[idx], c) = adc(r[idx], c, 0);
            idx += 1;
        }
    }
    r
}

/// Folds a 768-bit wide product down to a fully-reduced `< p` value, using `2^384 ≡ C (mod p)`.
fn reduce_wide(wide: [u64; 12]) -> FieldElement {
    let low: [u64; 6] = [wide[0], wide[1], wide[2], wide[3], wide[4], wide[5]];
    let high: [u64; 6] = [wide[6], wide[7], wide[8], wide[9], wide[10], wide[11]];

    let (hc, hc_top) = mul_small(high, C);
    let (acc, carry) = add_limbs(low, hc);
    let overflow = carry + hc_top;

    let addition = overflow.wrapping_mul(C);
    let (acc2, carry2) = add_limbs(acc, [addition, 0, 0, 0, 0, 0]);

    let addition2 = carry2.wrapping_mul(C);
    let (acc3, _carry3) = add_limbs(acc2, [addition2, 0, 0, 0, 0, 0]);

    let r1 = conditional_sub_p(acc3);
    let r2 = conditional_sub_p(r1);
    let r3 = conditional_sub_p(r2);
    FieldElement(r3)
}

impl FieldElement {
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0]);

    /// Interprets `bytes` (big-endian) as a field element. Precondition: `bytes` encodes a value
    /// `< p` - callers that can't guarantee this should use [`from_candidate_bytes`] instead.
    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn from_be_bytes(bytes: &[u8; 48]) -> Self {
        let mut limbs = [0u64; 6];
        let mut limb_bytes = [0u8; 8];
        for i in 0..6 {
            limb_bytes.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[5 - i] = u64::from_be_bytes(limb_bytes);
        }
        Self(limbs)
    }

    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn to_be_bytes(self) -> [u8; 48] {
        let mut out = [0u8; 48];
        for i in 0..6 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[5 - i].to_be_bytes());
        }
        out
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)]
    #[allow(clippy::needless_range_loop)]
    pub fn add(self, other: Self) -> Self {
        let (r, carry) = add_limbs(self.0, other.0);
        let mut t = [0u64; 6];
        let mut borrow = 0u64;
        for i in 0..6 {
            let (d, bw) = sbb(r[i], P_LIMBS[i], borrow);
            t[i] = d;
            borrow = bw;
        }
        let take_t = carry | (borrow ^ 1);
        // `black_box` keeps the mask from becoming a branch (D-225).
        let mask = core::hint::black_box(0u64.wrapping_sub(take_t));
        let mut out = [0u64; 6];
        for i in 0..6 {
            out[i] = (t[i] & mask) | (r[i] & !mask);
        }
        Self(out)
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)]
    #[allow(clippy::needless_range_loop)]
    pub fn sub(self, other: Self) -> Self {
        let mut r = [0u64; 6];
        let mut borrow = 0u64;
        for i in 0..6 {
            let (d, bw) = sbb(self.0[i], other.0[i], borrow);
            r[i] = d;
            borrow = bw;
        }
        // borrow==1 means self < other: r currently equals (self - other) mod 2^384, i.e.
        // (self-other)+2^384; subtracting C once corrects it to (self-other)+p, landing in [0,p).
        // `black_box` keeps the mask from becoming a branch (D-225).
        let mask = core::hint::black_box(0u64.wrapping_sub(borrow));
        let mut out = [0u64; 6];
        let mut inner_borrow = 0u64;
        for i in 0..6 {
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

    /// `bit` must be exactly `0` or `1` - see `fp256.rs::select`'s identical doc comment for why
    /// this is checked rather than trusted at each call site.
    #[inline]
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn select(bit: u64, a: Self, b: Self) -> Self {
        debug_assert!(bit <= 1, "select's bit argument must be 0 or 1");
        // `black_box` keeps the mask from becoming a branch (D-225).
        let mask = core::hint::black_box(0u64.wrapping_sub(bit));
        let mut out = [0u64; 6];
        for i in 0..6 {
            out[i] = (a.0[i] & mask) | (b.0[i] & !mask);
        }
        Self(out)
    }

    /// Constant-time square-and-multiply, fixed 384 iterations MSB-first, `exponent` big-endian.
    /// SECURITY: routes secret-scalar-derived data once `invert` (via Fermat) and
    /// `ProjectivePoint::to_affine` compose - same traced dependency `fp256.rs::pow_mod` documents.
    #[must_use]
    pub fn pow_mod(self, exponent: &[u8; 48]) -> Self {
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
    /// `tests/dstu9041_field_384.rs`.
    #[must_use]
    pub fn invert(self) -> Self {
        self.pow_mod(&P_MINUS_2)
    }

    /// Euler's criterion: `true` iff `self` is a nonzero quadratic residue mod `p`. Returns
    /// `false` for `ZERO`.
    #[must_use]
    pub fn euler_criterion(self) -> bool {
        self.pow_mod(&P_MINUS_1_OVER_2) == Self::ONE
    }

    /// Square root for `p ≡ 5 (mod 8)`. Unconditional - callers must check
    /// [`Self::euler_criterion`] first if they need to know whether `self` is actually a residue;
    /// `sqrt(ZERO) == ZERO` by construction (both branches of the formula yield zero).
    #[must_use]
    pub fn sqrt(self) -> Self {
        let f = self.pow_mod(&P_MINUS_1_OVER_4);
        let z = self.pow_mod(&P_PLUS_3_OVER_8);
        // p-1: P_LIMBS[0] (ends ..F79D) minus 1 needs no borrow (its low byte is 0x9D > 0).
        let p_minus_1 = Self([
            P_LIMBS[0] - 1,
            P_LIMBS[1],
            P_LIMBS[2],
            P_LIMBS[3],
            P_LIMBS[4],
            P_LIMBS[5],
        ]);
        let is_minus_one = u64::from(f == p_minus_1);
        let w = Self(W);
        let z_corrected = w.multiply(z);
        Self::select(is_minus_one, z_corrected, z)
    }
}

/// `w = 2^((p-1)/4) mod p`, generated from `p` and equal to Table В.2's own `w` column for E384/1
/// (both checked by the generator, D-241); `w_squared_is_p_minus_1` below pins it again.
const W: [u64; 6] = [
    0x7F1D_389E_E5CE_A1C1,
    0xA5A0_A33C_2009_F6B0,
    0x5ED9_90AE_6792_6D52,
    0x2818_CECA_634E_C925,
    0x87CF_ADDA_2636_8BFF,
    0xCF5F_8268_D231_25BE,
];

/// Rejection-samples `bytes` (big-endian) into a [`FieldElement`], `None` if `bytes >= p`.
/// Accepts the full `[0, p-1]` range including both `0` and `p-1`.
#[must_use]
#[allow(clippy::needless_range_loop)]
pub fn from_candidate_bytes(bytes: &[u8; 48]) -> Option<FieldElement> {
    let candidate = FieldElement::from_be_bytes(bytes);
    let mut borrow = 0u64;
    for i in 0..6 {
        let (_, bw) = sbb(candidate.0[i], P_LIMBS[i], borrow);
        borrow = bw;
    }
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
    /// directly here via the same identity `fp256.rs` uses: `2` is a documented non-residue mod
    /// this `p` too (independently checked, D-241), so `2^((p-1)/2) == p-1`, i.e.
    /// `W^2 == (2^((p-1)/4))^2 == p-1`.
    #[test]
    fn w_squared_is_p_minus_1() {
        let p_minus_1 = FieldElement([
            P_LIMBS[0] - 1,
            P_LIMBS[1],
            P_LIMBS[2],
            P_LIMBS[3],
            P_LIMBS[4],
            P_LIMBS[5],
        ]);
        assert_eq!(FieldElement(W).square(), p_minus_1);
    }
}

/// Kani proof harness, mirroring `fp256.rs`'s own `kani_proofs` module (T-177, D-102/D-112) at the
/// 6-limb size. Full `multiply`/`wide_mul` symbolic equivalence is deliberately not
/// attempted here for the same reason `fp256.rs` doesn't attempt it - D-112's already-established
/// intractability for this multiplier-equivalence class, and a 6-limb schoolbook multiply is an
/// instance of the same class, not a new question.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn less_than_p(x: [u64; 6]) -> bool {
        let mut borrow = 0u64;
        for i in 0..6 {
            let (_, bw) = sbb(x[i], P_LIMBS[i], borrow);
            borrow = bw;
        }
        borrow == 1
    }

    #[kani::proof]
    fn conditional_sub_p_is_always_fully_reduced() {
        let x: [u64; 6] = kani::any();
        let r = conditional_sub_p(x);
        assert!(less_than_p(r));
    }

    #[kani::proof]
    fn select_matches_spec() {
        let bit: u64 = kani::any();
        kani::assume(bit <= 1);
        let a: [u64; 6] = kani::any();
        let b: [u64; 6] = kani::any();
        let r = FieldElement::select(bit, FieldElement(a), FieldElement(b));
        if bit == 1 {
            assert_eq!(r, FieldElement(a));
        } else {
            assert_eq!(r, FieldElement(b));
        }
    }

    #[kani::proof]
    fn add_of_reduced_operands_is_fully_reduced() {
        let a: [u64; 6] = kani::any();
        let b: [u64; 6] = kani::any();
        kani::assume(less_than_p(a));
        kani::assume(less_than_p(b));
        let r = FieldElement(a).add(FieldElement(b));
        assert!(less_than_p(r.0));
    }

    #[kani::proof]
    fn sub_of_reduced_operands_is_fully_reduced() {
        let a: [u64; 6] = kani::any();
        let b: [u64; 6] = kani::any();
        kani::assume(less_than_p(a));
        kani::assume(less_than_p(b));
        let r = FieldElement(a).sub(FieldElement(b));
        assert!(less_than_p(r.0));
    }

    #[kani::proof]
    fn reduce_wide_is_always_fully_reduced() {
        let wide: [u64; 12] = kani::any();
        let r = reduce_wide(wide);
        assert!(less_than_p(r.0));
    }
}
