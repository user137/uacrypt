//! `F_p` arithmetic for DSTU 9041's `l(p)=512` case, E512/1's prime `p = 2^512 - 875` (T-192
//! Phase 1 - see `docs/pseudocode/dstu9041.md`, `docs/DECISIONS.md` D-176 for the citation and
//! independent verification this modulus was checked against). `p`'s closeness to a power of two
//! (a 10-bit complement `C=875`) is what `reduce_wide` exploits: `2^512 ≡ C (mod p)`, so a
//! 1024-bit product folds down via a couple of small multiply-and-add passes instead of general
//! long division - the same shape `fp256.rs` uses for `l(p)=256`'s `p = 2^256 - 435`, confirmed
//! (not assumed) to carry over once `p`'s own subtrahend was independently transcribed (D-176).
//!
//! Fixed-width `[u64; 8]` (little-endian limbs), mirroring `fp256.rs`'s own `[u64; 4]` shape - a
//! sibling module, not a generic-over-width one, per this project's existing `gf2m163`/`fp256`
//! precedent of one fixed-width type per field rather than premature generics.

/// `p`'s limbs, little-endian (`P_LIMBS[0]` is the least-significant 64 bits).
const P_LIMBS: [u64; 8] = [
    0xFFFF_FFFF_FFFF_FC95,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// `p = 2^512 - C`.
const C: u64 = 875;

/// `p - 2`, for `invert` via Fermat's little theorem (same substitution `fp256.rs::invert`
/// already uses in place of the literal extended-Euclidean algorithm, D-109's precedent).
const P_MINUS_2: [u8; 64] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x93,
];

/// `(p-1)/2`, for `euler_criterion`.
const P_MINUS_1_OVER_2: [u8; 64] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x4A,
];

/// `(p-1)/4`, for `sqrt`'s `f = v^((p-1)/4)` branch check (`p ≡ 5 (mod 8)`, confirmed D-176).
const P_MINUS_1_OVER_4: [u8; 64] = [
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x25,
];

/// `(p+3)/8`, for `sqrt`'s candidate root `z = v^((p+3)/8)`.
const P_PLUS_3_OVER_8: [u8; 64] = [
    0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x93,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement([u64; 8]);

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
#[allow(clippy::many_single_char_names)]
fn add_limbs(a: [u64; 8], b: [u64; 8]) -> ([u64; 8], u64) {
    let mut r = [0u64; 8];
    let mut carry = 0u64;
    for i in 0..8 {
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
fn conditional_sub_p(x: [u64; 8]) -> [u64; 8] {
    let mut t = [0u64; 8];
    let mut borrow = 0u64;
    for i in 0..8 {
        let (d, bw) = sbb(x[i], P_LIMBS[i], borrow);
        t[i] = d;
        borrow = bw;
    }
    let mask = 0u64.wrapping_sub(borrow ^ 1);
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = (t[i] & mask) | (x[i] & !mask);
    }
    out
}

/// `a * c` for a small constant `c < 2^16`, returning the low 512 bits plus a tiny overflow limb.
#[inline]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::cast_possible_truncation)]
fn mul_small(a: [u64; 8], c: u64) -> ([u64; 8], u64) {
    let mut r = [0u64; 8];
    let mut carry: u128 = 0;
    for i in 0..8 {
        let sum = u128::from(a[i]) * u128::from(c) + carry;
        r[i] = sum as u64;
        carry = sum >> 64;
    }
    (r, carry as u64)
}

/// Schoolbook 8x8-limb multiply producing a 16-limb (1024-bit) wide product. Carry propagation
/// after each row is a fixed-length pass over the remaining limbs (bounded by the row index `i`,
/// a public loop position, not secret data) - no early exit.
#[inline]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::cast_possible_truncation)]
fn wide_mul(a: [u64; 8], b: [u64; 8]) -> [u64; 16] {
    let mut r = [0u64; 16];
    for i in 0..8 {
        let mut carry: u128 = 0;
        for j in 0..8 {
            let idx = i + j;
            let sum = u128::from(r[idx]) + u128::from(a[i]) * u128::from(b[j]) + carry;
            r[idx] = sum as u64;
            carry = sum >> 64;
        }
        let mut idx = i + 8;
        let mut c = carry as u64;
        while idx < 16 {
            let sum = u128::from(r[idx]) + u128::from(c);
            r[idx] = sum as u64;
            c = (sum >> 64) as u64;
            idx += 1;
        }
    }
    r
}

/// Folds a 1024-bit wide product down to a fully-reduced `< p` value, using `2^512 ≡ C (mod p)`.
fn reduce_wide(wide: [u64; 16]) -> FieldElement {
    let low: [u64; 8] = [
        wide[0], wide[1], wide[2], wide[3], wide[4], wide[5], wide[6], wide[7],
    ];
    let high: [u64; 8] = [
        wide[8], wide[9], wide[10], wide[11], wide[12], wide[13], wide[14], wide[15],
    ];

    let (hc, hc_top) = mul_small(high, C);
    let (acc, carry) = add_limbs(low, hc);
    let overflow = carry + hc_top;

    let addition = overflow.wrapping_mul(C);
    let (acc2, carry2) = add_limbs(acc, [addition, 0, 0, 0, 0, 0, 0, 0]);

    let addition2 = carry2.wrapping_mul(C);
    let (acc3, _carry3) = add_limbs(acc2, [addition2, 0, 0, 0, 0, 0, 0, 0]);

    let r1 = conditional_sub_p(acc3);
    let r2 = conditional_sub_p(r1);
    let r3 = conditional_sub_p(r2);
    FieldElement(r3)
}

impl FieldElement {
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);

    /// Interprets `bytes` (big-endian) as a field element. Precondition: `bytes` encodes a value
    /// `< p` - callers that can't guarantee this should use [`from_candidate_bytes`] instead.
    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn from_be_bytes(bytes: &[u8; 64]) -> Self {
        let mut limbs = [0u64; 8];
        let mut limb_bytes = [0u8; 8];
        for i in 0..8 {
            limb_bytes.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[7 - i] = u64::from_be_bytes(limb_bytes);
        }
        Self(limbs)
    }

    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn to_be_bytes(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        for i in 0..8 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[7 - i].to_be_bytes());
        }
        out
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)]
    #[allow(clippy::needless_range_loop)]
    pub fn add(self, other: Self) -> Self {
        let (r, carry) = add_limbs(self.0, other.0);
        let mut t = [0u64; 8];
        let mut borrow = 0u64;
        for i in 0..8 {
            let (d, bw) = sbb(r[i], P_LIMBS[i], borrow);
            t[i] = d;
            borrow = bw;
        }
        let take_t = carry | (borrow ^ 1);
        let mask = 0u64.wrapping_sub(take_t);
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = (t[i] & mask) | (r[i] & !mask);
        }
        Self(out)
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)]
    #[allow(clippy::needless_range_loop)]
    pub fn sub(self, other: Self) -> Self {
        let mut r = [0u64; 8];
        let mut borrow = 0u64;
        for i in 0..8 {
            let (d, bw) = sbb(self.0[i], other.0[i], borrow);
            r[i] = d;
            borrow = bw;
        }
        // borrow==1 means self < other: r currently equals (self - other) mod 2^512, i.e.
        // (self-other)+2^512; subtracting C once corrects it to (self-other)+p, landing in [0,p).
        let mask = 0u64.wrapping_sub(borrow);
        let mut out = [0u64; 8];
        let mut inner_borrow = 0u64;
        for i in 0..8 {
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
        let mask = 0u64.wrapping_sub(bit);
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = (a.0[i] & mask) | (b.0[i] & !mask);
        }
        Self(out)
    }

    /// Constant-time square-and-multiply, fixed 512 iterations MSB-first, `exponent` big-endian.
    /// SECURITY: routes secret-scalar-derived data once `invert` (via Fermat) and
    /// `ProjectivePoint::to_affine` compose - same traced dependency `fp256.rs::pow_mod` documents.
    #[must_use]
    pub fn pow_mod(self, exponent: &[u8; 64]) -> Self {
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
    /// `tests/dstu9041_field_512.rs`.
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
        // p-1: P_LIMBS[0] (ends ..FC95) minus 1 needs no borrow (its low byte is 0x95 > 0).
        let p_minus_1 = Self([
            P_LIMBS[0] - 1,
            P_LIMBS[1],
            P_LIMBS[2],
            P_LIMBS[3],
            P_LIMBS[4],
            P_LIMBS[5],
            P_LIMBS[6],
            P_LIMBS[7],
        ]);
        let is_minus_one = u64::from(f == p_minus_1);
        let w = Self(W);
        let z_corrected = w.multiply(z);
        Self::select(is_minus_one, z_corrected, z)
    }
}

/// `w = 2^((p-1)/4) mod p`, precomputed (independently cross-checked via Python in this session,
/// D-176 - also matches, to within one hex digit this session's own transcription of it couldn't
/// fully resolve, Table В.3's own tabulated `w` value for E512/1, a third independent
/// corroboration beyond the Python derivation and the `w_squared_is_p_minus_1` test below).
const W: [u64; 8] = [
    0x278B_E8FE_8CBA_96E3,
    0x0401_4FA5_39A5_B43A,
    0xBB8D_8350_BE20_41AB,
    0xCA1E_4B1E_98EB_FDF4,
    0xC423_A043_A8BA_B910,
    0xEAE5_56FC_1EA5_D8F2,
    0x12E6_8679_95AC_2A62,
    0x658D_DAB5_D202_7479,
];

/// Rejection-samples `bytes` (big-endian) into a [`FieldElement`], `None` if `bytes >= p`.
/// Accepts the full `[0, p-1]` range including both `0` and `p-1`.
#[must_use]
#[allow(clippy::needless_range_loop)]
pub fn from_candidate_bytes(bytes: &[u8; 64]) -> Option<FieldElement> {
    let candidate = FieldElement::from_be_bytes(bytes);
    let mut borrow = 0u64;
    for i in 0..8 {
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
    /// this `p` too (independently checked, D-176), so `2^((p-1)/2) == p-1`, i.e.
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
            P_LIMBS[6],
            P_LIMBS[7],
        ]);
        assert_eq!(FieldElement(W).square(), p_minus_1);
    }
}

/// Kani proof harness, mirroring `fp256.rs`'s own `kani_proofs` module (T-177, D-102/D-112) at the
/// wider 8-limb size. Full `multiply`/`wide_mul` symbolic equivalence is deliberately not
/// attempted here for the same reason `fp256.rs` doesn't attempt it - D-112's already-established
/// intractability for this multiplier-equivalence class, and an 8-limb schoolbook multiply is a
/// harder instance of the same class, not a new question.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn less_than_p(x: [u64; 8]) -> bool {
        let mut borrow = 0u64;
        for i in 0..8 {
            let (_, bw) = sbb(x[i], P_LIMBS[i], borrow);
            borrow = bw;
        }
        borrow == 1
    }

    #[kani::proof]
    fn conditional_sub_p_is_always_fully_reduced() {
        let x: [u64; 8] = kani::any();
        let r = conditional_sub_p(x);
        assert!(less_than_p(r));
    }

    #[kani::proof]
    fn select_matches_spec() {
        let bit: u64 = kani::any();
        kani::assume(bit <= 1);
        let a: [u64; 8] = kani::any();
        let b: [u64; 8] = kani::any();
        let r = FieldElement::select(bit, FieldElement(a), FieldElement(b));
        if bit == 1 {
            assert_eq!(r, FieldElement(a));
        } else {
            assert_eq!(r, FieldElement(b));
        }
    }

    #[kani::proof]
    fn add_of_reduced_operands_is_fully_reduced() {
        let a: [u64; 8] = kani::any();
        let b: [u64; 8] = kani::any();
        kani::assume(less_than_p(a));
        kani::assume(less_than_p(b));
        let r = FieldElement(a).add(FieldElement(b));
        assert!(less_than_p(r.0));
    }

    #[kani::proof]
    fn sub_of_reduced_operands_is_fully_reduced() {
        let a: [u64; 8] = kani::any();
        let b: [u64; 8] = kani::any();
        kani::assume(less_than_p(a));
        kani::assume(less_than_p(b));
        let r = FieldElement(a).sub(FieldElement(b));
        assert!(less_than_p(r.0));
    }

    #[kani::proof]
    fn reduce_wide_is_always_fully_reduced() {
        let wide: [u64; 16] = kani::any();
        let r = reduce_wide(wide);
        assert!(less_than_p(r.0));
    }
}
