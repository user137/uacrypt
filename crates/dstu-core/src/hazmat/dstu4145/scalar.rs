//! Scalar (mod `n`) integer arithmetic for DSTU 4145 signing - the curve's group order
//! (`curve163::order()`), unrelated to `gf2m163::FieldElement`'s `GF(2^163)` polynomial
//! arithmetic. Kept as a **distinct type** specifically so the two can never be mixed up by
//! accident: both are 3-limb `[u64; 3]` internally, but `FieldElement::add` is XOR and
//! `FieldElement::multiply` is carryless, while `Scalar::add`/`Scalar::multiply` are ordinary
//! carrying integer arithmetic reduced mod `n` (`DECISIONS.md` D-25's follow-up note - this was
//! flagged as the layer's single biggest silent-correctness risk).
//!
//! Both operations are branchless throughout: `Scalar` carries the private key `d` and the
//! ephemeral nonce `e` during signing, both secret. Reduction mod `n` uses a fixed-iteration
//! restoring-division pass (double-and-conditionally-subtract, one pass per product bit, always
//! run in full) rather than Barrett or any early-exit scheme - correctness-first, same posture as
//! `gf2m163`'s field reduction.

use super::curve163;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar([u64; 3]);

impl Scalar {
    /// Builds a scalar from a big-endian byte slice (up to 21 bytes). The caller must ensure the
    /// value is already less than `n` - this does not reduce (same convention as
    /// `FieldElement::from_be_bytes`).
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        Scalar(limbs_from_be_bytes(bytes))
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // deliberate: extracting one byte from a shifted limb
    pub fn to_be_bytes(self) -> [u8; 21] {
        let mut out = [0u8; 21];
        for (i, byte) in out.iter_mut().rev().enumerate() {
            let limb = i / 8;
            let shift = (i % 8) * 8;
            *byte = (self.0[limb] >> shift) as u8;
        }
        out
    }

    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0, 0, 0]
    }

    fn n() -> [u64; 3] {
        limbs_from_be_bytes(&curve163::order())
    }

    #[must_use]
    pub fn multiply(self, other: Self) -> Self {
        Scalar(reduce_mod_n(mul3(self.0, other.0)))
    }
}

impl core::ops::Add for Scalar {
    type Output = Self;

    /// Ordinary integer addition mod `n` (not XOR - see the module doc).
    fn add(self, other: Self) -> Self {
        let (sum, _carry) = add3(self.0, other.0);
        Scalar(cond_sub_if_ge(sum, Self::n()))
    }
}

fn limbs_from_be_bytes(bytes: &[u8]) -> [u64; 3] {
    let mut limbs = [0u64; 3];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        let limb = i / 8;
        let shift = (i % 8) * 8;
        limbs[limb] |= u64::from(byte) << shift;
    }
    limbs
}

/// 3-limb add with carry-out.
fn add3(a: [u64; 3], b: [u64; 3]) -> ([u64; 3], u64) {
    let mut out = [0u64; 3];
    let mut carry = 0u64;
    for i in 0..3 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        out[i] = s2;
        carry = u64::from(c1) + u64::from(c2);
    }
    (out, carry)
}

/// 3-limb subtract with borrow-out (`1` if `a < b`).
fn sub3(a: [u64; 3], b: [u64; 3]) -> ([u64; 3], u64) {
    let mut out = [0u64; 3];
    let mut borrow = 0u64;
    for i in 0..3 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = u64::from(b1) + u64::from(b2);
    }
    (out, borrow)
}

/// Returns `a - b` if `a >= b`, otherwise `a` unchanged - via a constant-time select on the
/// subtraction's borrow flag (`borrow == 0` means `a >= b`), never a branch on the comparison.
fn cond_sub_if_ge(a: [u64; 3], b: [u64; 3]) -> [u64; 3] {
    let (diff, borrow) = sub3(a, b);
    let mask = borrow.wrapping_sub(1); // borrow == 0 (a >= b) -> all-ones; borrow == 1 -> all-zeros
    let mut out = [0u64; 3];
    for i in 0..3 {
        out[i] = a[i] ^ (mask & (a[i] ^ diff[i]));
    }
    out
}

/// 3-limb by 3-limb schoolbook multiplication into 6 limbs (real carrying arithmetic, unlike
/// `gf2m163`'s carryless `poly_mul_wide`).
#[allow(clippy::cast_possible_truncation)] // deliberate: low 64 bits of a u128 partial product
fn mul3(a: [u64; 3], b: [u64; 3]) -> [u64; 6] {
    let mut out = [0u64; 6];
    for i in 0..3 {
        let mut carry = 0u128;
        for j in 0..3 {
            let product = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[i + j]) + carry;
            out[i + j] = product as u64;
            carry = product >> 64;
        }
        out[i + 3] = carry as u64;
    }
    out
}

/// Reduces a 6-limb product mod `n` via restoring division: process every bit of `product` from
/// the most significant down, doubling the running remainder and folding in each bit, then always
/// running the conditional subtract - the same fixed number of passes (`6 * 64`) regardless of
/// `product`'s actual value.
fn reduce_mod_n(product: [u64; 6]) -> [u64; 3] {
    let n = Scalar::n();
    let mut r = [0u64; 3];
    for limb_idx in (0..6).rev() {
        for bit in (0..64).rev() {
            let bit_val = (product[limb_idx] >> bit) & 1;
            r = shl1_or(r, bit_val);
            r = cond_sub_if_ge(r, n);
        }
    }
    r
}

/// Left-shifts a 3-limb value by 1 bit, OR-ing `bit` into the vacated low bit.
fn shl1_or(x: [u64; 3], bit: u64) -> [u64; 3] {
    let mut out = [0u64; 3];
    let mut carry = bit;
    for i in 0..3 {
        let next_carry = x[i] >> 63;
        out[i] = (x[i] << 1) | carry;
        carry = next_carry;
    }
    out
}
