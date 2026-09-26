//! 64-bit limb carry arithmetic for the prime-field and scalar code (`dstu9041::fp256`/`fp512`,
//! `dstu4145::scalar`/`scalar257`), written so no target has a compare to lower (T-291, D-227).
//!
//! `overflowing_add`/`overflowing_sub` and `u128` sums are an `i64` compare on a 32-bit target.
//! RV32 has no conditional select, so LLVM lowers that compare to `beq hi,hi` around an `sltu`: a
//! branch on secret limb data. Here the carry-out is the majority of the operand and sum top bits,
//! computed with bitwise operations only; the 32-bit add underneath is `add` + `sltu`, no branch.
//! No `black_box` here, unlike D-225's mask sites: there is no compare left to lower, and a
//! barrier in the multiply loop would be costly. A future LLVM could fold the formula back into a
//! compare, so T-292's asm check is the guard. Constant-time discipline, not a side-channel claim.

/// `a + b + carry_in` as `(sum, carry_out)`. `carry_in` must be 0 or 1: the carry-out is the
/// full-adder majority of the top bits of `a`, `b` and the carry into bit 63, which holds only then.
#[inline]
pub(crate) fn adc(a: u64, b: u64, carry_in: u64) -> (u64, u64) {
    debug_assert!(carry_in <= 1, "carry_in must be 0 or 1");
    let s = a.wrapping_add(b).wrapping_add(carry_in);
    (s, ((a & b) | ((a | b) & !s)) >> 63)
}

/// `a - b - borrow_in` as `(diff, borrow_out)`, `borrow_out = 1` iff `a < b + borrow_in`.
/// `borrow_in` must be 0 or 1, for the same reason as [`adc`].
#[inline]
pub(crate) fn sbb(a: u64, b: u64, borrow_in: u64) -> (u64, u64) {
    debug_assert!(borrow_in <= 1, "borrow_in must be 0 or 1");
    let d = a.wrapping_sub(b).wrapping_sub(borrow_in);
    (d, ((!a & b) | ((!a | b) & d)) >> 63)
}

/// `r + a * b + carry` as `(low, high)`, for any `u64` inputs. The `u128` product alone is
/// branch-free on RV32 (`mul`/`mulhu`); only the sums went through a compare. The high word cannot
/// overflow: `(2^64-1)^2 + 2(2^64-1) = 2^128-1`.
#[inline]
#[allow(clippy::cast_possible_truncation)] // deliberate: splitting the product into its two words
pub(crate) fn mac(r: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let product = u128::from(a) * u128::from(b);
    let (lo, c1) = adc(product as u64, r, 0);
    let (lo, c2) = adc(lo, carry, 0);
    (lo, ((product >> 64) as u64) + c1 + c2)
}

#[cfg(test)]
mod tests {
    use super::{adc, mac, sbb};
    use proptest::prelude::*;

    const EDGES: [u64; 6] = [0, 1, (1 << 63) - 1, 1 << 63, u64::MAX - 1, u64::MAX];

    #[allow(clippy::cast_possible_truncation)]
    fn split(x: u128) -> (u64, u64) {
        (x as u64, (x >> 64) as u64)
    }

    fn adc_ref(a: u64, b: u64, c: u64) -> (u64, u64) {
        split(u128::from(a) + u128::from(b) + u128::from(c))
    }

    fn sbb_ref(a: u64, b: u64, c: u64) -> (u64, u64) {
        let d = u128::from(a)
            .wrapping_sub(u128::from(b))
            .wrapping_sub(u128::from(c));
        (
            split(d).0,
            u64::from(u128::from(a) < u128::from(b) + u128::from(c)),
        )
    }

    fn mac_ref(r: u64, a: u64, b: u64, c: u64) -> (u64, u64) {
        split(u128::from(r) + u128::from(a) * u128::from(b) + u128::from(c))
    }

    #[test]
    fn adc_and_sbb_match_u128_on_the_edge_grid() {
        for a in EDGES {
            for b in EDGES {
                for c in [0, 1] {
                    assert_eq!(adc(a, b, c), adc_ref(a, b, c), "adc({a:#x}, {b:#x}, {c})");
                    assert_eq!(sbb(a, b, c), sbb_ref(a, b, c), "sbb({a:#x}, {b:#x}, {c})");
                }
            }
        }
    }

    #[test]
    fn mac_matches_u128_on_the_edge_grid() {
        for r in EDGES {
            for a in EDGES {
                for b in EDGES {
                    for c in EDGES {
                        assert_eq!(mac(r, a, b, c), mac_ref(r, a, b, c));
                    }
                }
            }
        }
    }

    #[test]
    fn mac_at_all_max_reaches_the_top_without_overflow() {
        // (2^64-1)^2 + 2(2^64-1) = 2^128-1: the largest value `mac` can produce.
        assert_eq!(
            mac(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX)
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "carry_in")]
    fn adc_rejects_a_carry_above_one() {
        let _ = adc(0, 0, 2);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "borrow_in")]
    fn sbb_rejects_a_borrow_above_one() {
        let _ = sbb(0, 0, 2);
    }

    proptest! {
        #[test]
        fn adc_matches_u128(a: u64, b: u64, c in 0u64..=1) {
            prop_assert_eq!(adc(a, b, c), adc_ref(a, b, c));
        }

        #[test]
        fn sbb_matches_u128(a: u64, b: u64, c in 0u64..=1) {
            prop_assert_eq!(sbb(a, b, c), sbb_ref(a, b, c));
        }

        #[test]
        fn mac_matches_u128(r: u64, a: u64, b: u64, c: u64) {
            prop_assert_eq!(mac(r, a, b, c), mac_ref(r, a, b, c));
        }
    }
}
