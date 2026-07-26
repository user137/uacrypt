//! Fixed-width GF(2^m) field arithmetic for DSTU 7624:2014's GCM/GMAC modes (#7) - three field
//! sizes (`m = 128/256/512`, one per Kalyna block size), each reduced modulo the pentanomial cited
//! from `oracles/uapki/library/uapkic/src/dstu7624.c`'s `dstu7624_init_gcm`/`dstu7624_init_gmac`
//! `f[]` triples. `DECISIONS.md` D-56 has the full citation and the byte/bit representation
//! derivation.
//!
//! **A distinct convention from [`super::dstu4145::gf2m163`]**: that module serializes field
//! elements big-endian (DSTU 4145's own convention). This module serializes **little-endian** -
//! byte 0 holds the lowest-degree terms - forced by `uint8_to_uint64`'s plain little-endian
//! `memcpy` reinterpretation in `oracles/uapki/library/uapkic/src/byte-utils-internal.c`, which is
//! what `gf2m_mul`'s byte-array wrapper (`dstu7624.c` lines 2963-3001) actually calls. Do not
//! assume the two GF(2^m) modules in this crate share a byte-order convention just because both
//! are "DSTU GF(2^m)" - they don't; citing the wrong one here would repeat the `hash_to_field`
//! calling-convention mistake `CLAUDE.md`'s agent-discipline section warns about, generalized to a
//! second standard.
//!
//! **Correctness-first, not speed-first** (same posture as `gf2m163`, `DECISIONS.md` D-25): a
//! branchless bit-select shift-and-add multiply (mirroring `gf2m163::poly_mul_wide`'s technique
//! exactly), then a simple bit-at-a-time top-down modular reduction - not `gf2m163::reduce`'s
//! word-offset-optimized closed form (hand-derived specifically for `m=163`/64-bit words, does not
//! generalize to three more field sizes without redoing that derivation three times), and not
//! `oracles/uapki/library/uapkic/src/math-gf2m-internal.c`'s Karatsuba-based library either (no
//! reusable code there, confirmed by reading it - only a style precedent already followed by
//! `gf2m163`).

macro_rules! gf2m_field {
    ($elem:ident, $limbs:literal, $limbs2:literal, $m:literal, $f1:literal, $f2:literal, $f3:literal) => {
        #[doc = concat!("An element of GF(2^", stringify!($m), ") - see the module doc comment ",
            "for the reduction polynomial citation and the little-endian byte-order derivation.")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $elem(pub [u64; $limbs]);

        impl $elem {
            pub const ZERO: Self = Self([0u64; $limbs]);

            #[must_use]
            pub fn from_le_bytes(bytes: &[u8; $limbs * 8]) -> Self {
                let mut limbs = [0u64; $limbs];
                for (i, limb) in limbs.iter_mut().enumerate() {
                    let mut word = [0u8; 8];
                    word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
                    *limb = u64::from_le_bytes(word);
                }
                Self(limbs)
            }

            #[must_use]
            pub fn to_le_bytes(self) -> [u8; $limbs * 8] {
                let mut out = [0u8; $limbs * 8];
                for (i, limb) in self.0.iter().enumerate() {
                    out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
                }
                out
            }

            /// GF(2^m) addition is bitwise XOR - no carry, no reduction needed.
            #[must_use]
            pub fn add(self, other: Self) -> Self {
                let mut out = [0u64; $limbs];
                for i in 0..$limbs {
                    out[i] = self.0[i] ^ other.0[i];
                }
                Self(out)
            }

            #[must_use]
            pub fn multiply(self, other: Self) -> Self {
                Self::reduce(Self::poly_mul_wide(&self.0, &other.0))
            }

            /// Multiplies by the field generator `x` directly, instead of going through the
            /// general [`Self::multiply`] path against a `2` (= `x^1`) operand - see
            /// `DECISIONS.md` D-76 / `TASKS.md` T-126: [`super::kalyna_xts`]'s once-per-block
            /// tweak-doubling is exactly this fixed-constant case, and paying the general path's
            /// full O(m^2) schoolbook multiply for it is unneeded work that scales worst at the
            /// largest `m` (512). `x`'s only nonzero bit is bit 1, so multiplying by it is a
            /// single left-shift of the whole element - O(m/64) word ops - plus, only when the
            /// shifted-out top bit (degree `m-1`) was set, one XOR of the reduction polynomial's
            /// low-degree terms to substitute for the `x^m` term that shifted out of range
            /// (`x^m = x^f1 + x^f2 + x^f3 + 1` mod the reduction polynomial - the same identity
            /// [`Self::reduce`] uses, applied once instead of once per set bit). Must stay
            /// byte-identical to `self.multiply(Self` with only bit 1 set `)` - checked directly
            /// against it by `field_axiom_tests::double_matches_general_multiply_by_two` below,
            /// not just asserted; this is a speed-only specialization, not a new field-arithmetic
            /// definition.
            #[must_use]
            pub fn double(self) -> Self {
                let top_bit = (self.0[$limbs - 1] >> 63) & 1;
                let mut out = [0u64; $limbs];
                let mut carry = 0u64;
                for i in 0..$limbs {
                    let next_carry = self.0[i] >> 63;
                    out[i] = (self.0[i] << 1) | carry;
                    carry = next_carry;
                }
                if top_bit == 1 {
                    out[0] ^= 1;
                    let terms: [u32; 3] = [$f1, $f2, $f3];
                    for term in terms {
                        let l = (term / 64) as usize;
                        let b = term % 64;
                        out[l] ^= 1u64 << b;
                    }
                }
                Self(out)
            }

            /// Binary-polynomial (carry-less) multiplication into a double-width product - the
            /// right-to-left shift-and-add method, branchless bit-select in place of an `if`,
            /// mirroring `gf2m163::poly_mul_wide` exactly (`DECISIONS.md` D-25).
            fn poly_mul_wide(a: &[u64; $limbs], b: &[u64; $limbs]) -> [u64; $limbs2] {
                let mut acc = [0u64; $limbs2];
                let mut shifted = [0u64; $limbs2];
                shifted[..$limbs].copy_from_slice(b);

                for bit_index in 0u32..$m {
                    let limb = (bit_index / 64) as usize;
                    let bit = bit_index % 64;
                    let bit_value = (a[limb] >> bit) & 1;
                    let mask = 0u64.wrapping_sub(bit_value);
                    for i in 0..$limbs2 {
                        acc[i] ^= shifted[i] & mask;
                    }
                    Self::shl1(&mut shifted);
                }

                acc
            }

            /// Left-shifts a `$limbs2`-limb little-endian array by exactly 1 bit, in place.
            fn shl1(x: &mut [u64; $limbs2]) {
                let mut carry = 0u64;
                for limb in x.iter_mut() {
                    let next_carry = *limb >> 63;
                    *limb = (*limb << 1) | carry;
                    carry = next_carry;
                }
            }

            /// Reduces a double-width product modulo
            #[doc = concat!("`x^", stringify!($m), " + x^", stringify!($f1), " + x^",
                stringify!($f2), " + x^", stringify!($f3), " + 1`,")]
            /// processing one bit at a time from the top degree down: for each set bit at degree
            /// `d >= m`, `x^d = x^(d-m) * x^m = x^(d-m) * (x^f1 + x^f2 + x^f3 + 1)` (mod the
            /// polynomial) - clear that bit and XOR in the four shifted terms.
            fn reduce(mut c: [u64; $limbs2]) -> Self {
                let top_degree: u32 = ($limbs2 * 64) - 1;
                let mut degree = top_degree;
                while degree >= $m {
                    let limb = (degree / 64) as usize;
                    let bit = degree % 64;
                    if (c[limb] >> bit) & 1 == 1 {
                        c[limb] ^= 1u64 << bit;
                        let shift = degree - $m;
                        for term in [$f1, $f2, $f3, 0u32] {
                            let d = shift + term;
                            let l = (d / 64) as usize;
                            let b = d % 64;
                            c[l] ^= 1u64 << b;
                        }
                    }
                    degree -= 1;
                }

                let mut out = [0u64; $limbs];
                out.copy_from_slice(&c[..$limbs]);
                Self(out)
            }
        }
    };
}

gf2m_field!(Gf2m128, 2, 4, 128, 7, 2, 1);
gf2m_field!(Gf2m256, 4, 8, 256, 10, 5, 2);
gf2m_field!(Gf2m512, 8, 16, 512, 8, 5, 2);

/// This module has no standalone official test vectors (D-56 - no such oracle exists anywhere;
/// [`super::kalyna_gcm`]/[`super::kalyna_gmac`] only exercise it jointly, through their own KATs,
/// all of which are block-aligned and so never drive `reduce`'s loop through its full degree
/// range). `advisor()` flagged this as a real gap before Stage D was declared done: nothing
/// confirms the reduction's top-degree terms (`degree` near `$limbs2 * 64 - 1`, close to
/// `poly_mul_wide`'s maximum possible output degree) are handled correctly, only that the
/// low/mid-degree terms official vectors happen to reach are. These are direct field-axiom tests -
/// identity, commutativity, associativity, distributivity, and the two most schedule-adjacent
/// inputs for a shift-based reduction (an all-`0x00` and an all-`0xFF` element, i.e. the two
/// extremes `poly_mul_wide` can produce) - not a substitute for a real oracle vector if one is ever
/// found, but real evidence the module is actually exercised rather than incidentally passed
/// through by five accidentally-easy KATs.
#[cfg(test)]
mod field_axiom_tests {
    use super::{Gf2m128, Gf2m256, Gf2m512};
    use proptest::prelude::*;

    macro_rules! field_axioms {
        ($mod_name:ident, $elem:ident, $limbs:literal) => {
            mod $mod_name {
                use super::*;

                const ONE: $elem = {
                    let mut limbs = [0u64; $limbs];
                    limbs[0] = 1;
                    $elem(limbs)
                };
                const TWO: $elem = {
                    let mut limbs = [0u64; $limbs];
                    limbs[0] = 2;
                    $elem(limbs)
                };
                const ALL_ONES: $elem = $elem([u64::MAX; $limbs]);

                fn arb_element() -> impl Strategy<Value = $elem> {
                    proptest::collection::vec(any::<u64>(), $limbs).prop_map(|v| {
                        let mut limbs = [0u64; $limbs];
                        limbs.copy_from_slice(&v);
                        $elem(limbs)
                    })
                }

                #[test]
                fn adding_an_element_to_itself_is_zero() {
                    // Characteristic 2: a XOR a == 0, independent of `multiply`/`reduce`.
                    assert_eq!(ALL_ONES.add(ALL_ONES), $elem::ZERO);
                }

                #[test]
                fn all_ones_times_one_is_all_ones() {
                    // The two extremes together: `poly_mul_wide`'s maximum-degree input against
                    // the one input `reduce` must leave untouched.
                    assert_eq!(ALL_ONES.multiply(ONE), ALL_ONES);
                }

                #[test]
                fn all_ones_squared_does_not_panic() {
                    // Drives `reduce`'s loop through its full top-to-bottom degree range - the
                    // one case none of the official (block-aligned) GCM/GMAC vectors can reach.
                    let _ = ALL_ONES.multiply(ALL_ONES);
                }

                #[test]
                fn double_of_all_ones_matches_general_multiply_by_two() {
                    // The one input `double`'s shift can carry out of every word at once - the
                    // `double`-specific analogue of `all_ones_squared_does_not_panic` above.
                    assert_eq!(ALL_ONES.double(), ALL_ONES.multiply(TWO));
                }

                proptest! {
                    #[test]
                    fn double_matches_general_multiply_by_two(a in arb_element()) {
                        // `TASKS.md` T-126 / `DECISIONS.md` D-76: `double` must be byte-identical
                        // to the general path it replaces in `kalyna_xts`'s tweak update, not just
                        // asymptotically faster - this is the correctness gate for that swap.
                        prop_assert_eq!(a.double(), a.multiply(TWO));
                    }

                    #[test]
                    fn multiply_by_one_is_identity(a in arb_element()) {
                        prop_assert_eq!(a.multiply(ONE), a);
                    }

                    #[test]
                    fn multiply_is_commutative(a in arb_element(), b in arb_element()) {
                        prop_assert_eq!(a.multiply(b), b.multiply(a));
                    }

                    #[test]
                    fn multiply_is_associative(a in arb_element(), b in arb_element(), c in arb_element()) {
                        prop_assert_eq!(a.multiply(b).multiply(c), a.multiply(b.multiply(c)));
                    }

                    #[test]
                    fn multiply_distributes_over_add(a in arb_element(), b in arb_element(), c in arb_element()) {
                        prop_assert_eq!(a.multiply(b.add(c)), a.multiply(b).add(a.multiply(c)));
                    }
                }
            }
        };
    }

    field_axioms!(gf2m128, Gf2m128, 2);
    field_axioms!(gf2m256, Gf2m256, 4);
    field_axioms!(gf2m512, Gf2m512, 8);
}
