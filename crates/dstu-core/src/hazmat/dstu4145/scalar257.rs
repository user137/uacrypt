//! Scalar (mod `n`) integer arithmetic for `m=257` DSTU 4145 signing - `curve257`'s group order,
//! unrelated to `gf2m257::FieldElement`'s `GF(2^257)` polynomial arithmetic. Same "distinct type"
//! rationale as `scalar::Scalar` (see its own module doc, `docs/DECISIONS.md` D-25's follow-up
//! note) and the same branchless discipline throughout, widened from 3/6 to 5/10 limbs.

use super::curve257;
use zeroize::Zeroize;

// Not `ZeroizeOnDrop` - see `scalar::Scalar`'s own comment on why (`Copy` + `Drop` is E0184).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct Scalar([u64; 5]);

impl Scalar {
    /// Builds a scalar from a big-endian byte slice (up to 33 bytes). The caller must ensure the
    /// value is already less than `n` - this does not reduce.
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        Scalar(limbs_from_be_bytes(bytes))
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // deliberate: extracting one byte from a shifted limb
    pub fn to_be_bytes(self) -> [u8; 33] {
        let mut out = [0u8; 33];
        for (i, byte) in out.iter_mut().rev().enumerate() {
            let limb = i / 8;
            let shift = (i % 8) * 8;
            *byte = (self.0[limb] >> shift) as u8;
        }
        out
    }

    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0, 0, 0, 0, 0]
    }

    fn n() -> [u64; 5] {
        limbs_from_be_bytes(&curve257::order())
    }

    /// Builds a scalar from a big-endian 33-byte candidate, but only if it lies in `[1, n)` - same
    /// role as `scalar::Scalar::from_candidate_bytes` (`docs/TASKS.md` T-122). Used by
    /// `crypto_sign257::SigningKey::generate`'s own rejection-sampling loop, re-derived for this
    /// curve's own order rather than assumed to carry over: `n`'s top byte here is `0x00`
    /// (`curve257::order()`'s own value, D-185), and its bit-length is 256, one bit narrower than
    /// the 33-byte/264-bit candidate draw - `crypto_sign257::SigningKey::generate` masks
    /// accordingly (top byte to `0`, second byte to its low bit) to keep the rejection rate near
    /// 50%, mirroring `crypto_sign`'s own masking for `m=163`'s order (`docs/DECISIONS.md` D-186
    /// Decision 5, resolved).
    #[cfg(any(feature = "std", feature = "getrandom"))]
    #[must_use]
    pub(crate) fn from_candidate_bytes(bytes: &[u8; 33]) -> Option<Self> {
        let limbs = limbs_from_be_bytes(bytes);
        let (_, borrow) = sub5(limbs, Self::n());
        let in_range = borrow == 1; // borrow == 1 <=> limbs < n
        let nonzero = limbs != [0, 0, 0, 0, 0];
        (in_range && nonzero).then_some(Scalar(limbs))
    }

    #[must_use]
    pub fn multiply(self, other: Self) -> Self {
        Scalar(reduce_mod_n(mul5(self.0, other.0)))
    }

    /// Reduces an arbitrary-length big-endian byte string mod `n`, via the same bit-serial
    /// restoring reduction as `reduce_mod_n`. **Callers must widen their input beyond a plain
    /// 32-byte digest before calling this** - unlike `scalar::Scalar::reduce_wide_bytes`'s existing
    /// caller (a 256-bit KMAC output folded mod `m=163`'s ~163-bit `n`, a wide enough ratio for the
    /// resulting bias to be cryptographically negligible), `curve257::order()` is itself ~256 bits,
    /// so a same-width input would reintroduce real bias. `crypto_sign257`'s nonce derivation
    /// calls this with a 48-byte (384-bit) `Kupyna384Kmac` output instead of a 32-byte one
    /// specifically to keep this ratio wide (128 bits of margin) - `docs/DECISIONS.md` D-186
    /// Decision 5, resolved.
    #[must_use]
    pub(crate) fn reduce_wide_bytes(bytes: &[u8]) -> Self {
        let n = Self::n();
        let mut r = [0u64; 5];
        for &byte in bytes {
            for bit in (0..8).rev() {
                let bit_val = u64::from((byte >> bit) & 1);
                r = shl1_or(r, bit_val);
                r = cond_sub_if_ge(r, n);
            }
        }
        Scalar(r)
    }
}

impl core::ops::Add for Scalar {
    type Output = Self;

    /// Ordinary integer addition mod `n` (not XOR - see the module doc).
    fn add(self, other: Self) -> Self {
        let (sum, _carry) = add5(self.0, other.0);
        Scalar(cond_sub_if_ge(sum, Self::n()))
    }
}

fn limbs_from_be_bytes(bytes: &[u8]) -> [u64; 5] {
    let mut limbs = [0u64; 5];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        let limb = i / 8;
        let shift = (i % 8) * 8;
        limbs[limb] |= u64::from(byte) << shift;
    }
    limbs
}

/// 5-limb add with carry-out.
fn add5(a: [u64; 5], b: [u64; 5]) -> ([u64; 5], u64) {
    let mut out = [0u64; 5];
    let mut carry = 0u64;
    for i in 0..5 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        out[i] = s2;
        carry = u64::from(c1) + u64::from(c2);
    }
    (out, carry)
}

/// 5-limb subtract with borrow-out (`1` if `a < b`).
fn sub5(a: [u64; 5], b: [u64; 5]) -> ([u64; 5], u64) {
    let mut out = [0u64; 5];
    let mut borrow = 0u64;
    for i in 0..5 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = u64::from(b1) + u64::from(b2);
    }
    (out, borrow)
}

/// Returns `a - b` if `a >= b`, otherwise `a` unchanged - constant-time select on the borrow flag.
fn cond_sub_if_ge(a: [u64; 5], b: [u64; 5]) -> [u64; 5] {
    let (diff, borrow) = sub5(a, b);
    let mask = borrow.wrapping_sub(1);
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = a[i] ^ (mask & (a[i] ^ diff[i]));
    }
    out
}

/// 5-limb by 5-limb schoolbook multiplication into 10 limbs (real carrying arithmetic, unlike
/// `gf2m257`'s carryless `poly_mul_wide`).
#[allow(clippy::cast_possible_truncation)] // deliberate: low 64 bits of a u128 partial product
fn mul5(a: [u64; 5], b: [u64; 5]) -> [u64; 10] {
    let mut out = [0u64; 10];
    for i in 0..5 {
        let mut carry = 0u128;
        for j in 0..5 {
            let product = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[i + j]) + carry;
            out[i + j] = product as u64;
            carry = product >> 64;
        }
        out[i + 5] = carry as u64;
    }
    out
}

/// Reduces a 10-limb product mod `n` via restoring division - same fixed-pass-count technique as
/// `scalar::reduce_mod_n`, widened to `10 * 64` passes.
fn reduce_mod_n(product: [u64; 10]) -> [u64; 5] {
    let n = Scalar::n();
    let mut r = [0u64; 5];
    for limb_idx in (0..10).rev() {
        for bit in (0..64).rev() {
            let bit_val = (product[limb_idx] >> bit) & 1;
            r = shl1_or(r, bit_val);
            r = cond_sub_if_ge(r, n);
        }
    }
    r
}

/// Left-shifts a 5-limb value by 1 bit, OR-ing `bit` into the vacated low bit.
fn shl1_or(x: [u64; 5], bit: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry = bit;
    for i in 0..5 {
        let next_carry = x[i] >> 63;
        out[i] = (x[i] << 1) | carry;
        carry = next_carry;
    }
    out
}

#[cfg(all(test, any(feature = "std", feature = "getrandom")))]
mod from_candidate_bytes_tests {
    use super::{curve257, Scalar};

    #[test]
    fn rejects_zero() {
        assert!(Scalar::from_candidate_bytes(&[0u8; 33]).is_none());
    }

    #[test]
    fn rejects_n_itself() {
        assert!(Scalar::from_candidate_bytes(&curve257::order()).is_none());
    }

    #[test]
    fn rejects_above_n() {
        let mut above_n = curve257::order();
        above_n[32] += 1; // n's low byte is 0x0D, room to increment without carrying
        assert!(Scalar::from_candidate_bytes(&above_n).is_none());
    }

    #[test]
    fn accepts_n_minus_one() {
        let mut n_minus_one = curve257::order();
        n_minus_one[32] -= 1;
        let scalar = Scalar::from_candidate_bytes(&n_minus_one).expect("n - 1 is in [1, n)");
        assert_eq!(scalar.to_be_bytes(), n_minus_one);
    }

    #[test]
    fn accepts_one() {
        let mut one = [0u8; 33];
        one[32] = 1;
        let scalar = Scalar::from_candidate_bytes(&one).expect("1 is in [1, n)");
        assert_eq!(scalar.to_be_bytes(), one);
    }
}
