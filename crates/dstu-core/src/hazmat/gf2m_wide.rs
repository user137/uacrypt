//! Fixed-width GF(2^m) field arithmetic for DSTU 7624:2014's GCM/GMAC modes (#7) - three field
//! sizes (`m = 128/256/512`, one per Kalyna block size), each reduced modulo the pentanomial cited
//! from `oracles/uapki/library/uapkic/src/dstu7624.c`'s `dstu7624_init_gcm`/`dstu7624_init_gmac`
//! `f[]` triples. `docs/DECISIONS.md` D-56 has the full citation and the byte/bit representation
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
//! **Originally correctness-first, not speed-first** (same posture as `gf2m163`, `docs/DECISIONS.md`
//! D-25): a branchless bit-select shift-and-add multiply (mirroring `gf2m163::poly_mul_wide`'s
//! technique exactly), then a simple bit-at-a-time top-down modular reduction. **Multiplication
//! was measured (`docs/TASKS.md` T-125) to be 89.6-94.3% of `kalyna_gcm`/`kalyna_gmac`'s per-block cost,
//! not the block cipher, and was switched to a 4-bit-window comb method** (`docs/DECISIONS.md` D-76, see
//! `poly_mul_wide`'s own doc comment for the technique); `reduce` is still the original
//! bit-at-a-time top-down method, not `gf2m163::reduce`'s word-offset-optimized closed form
//! (hand-derived specifically for `m=163`/64-bit words, does not generalize to three more field
//! sizes without redoing that derivation three times), and not
//! `oracles/uapki/library/uapkic/src/math-gf2m-internal.c`'s Karatsuba-based library either (no
//! reusable code there, confirmed by reading it - only a style precedent already followed by
//! `gf2m163`). `reduce` was measured to be a small fraction of the total (`poly_mul_wide` was
//! ~16,384 word-ops at m=512 pre-fix vs. `reduce`'s ~512 bit-serial iterations there), so it
//! wasn't touched at the time. **Revisited and fixed, `docs/TASKS.md` T-195**: that comparison was
//! against the pre-T-125 bit-serial multiply and no longer held once `poly_mul_wide` became the
//! 4-bit comb method - a chained (data-dependent, matching `kalyna_gcm`'s real accumulator
//! pattern) timing split at m=256 measured the old bit-serial `reduce` at ~62-64% of
//! `multiply()`'s total, i.e. the *larger* term, not `poly_mul_wide`. `reduce` is now a word-wise
//! closed form instead (see its own doc comment) - `f1`/`f2`/`f3` are all `< 64` for every field
//! size here (unlike `gf2m163`'s single hand-derived instantiation, this one generalizes across
//! all three sizes through the same macro, const-asserted at every instantiation), so a whole
//! word folds down in one step instead of 64 bit-at-a-time steps. The old bit-serial
//! implementation is kept as `reduce_bit_serial_reference` (`#[cfg(any(test, kani))]` only, dead
//! code in a release build) - both this module's own differential proptest and its Kani proofs
//! check the new implementation against it directly, not just against the field axioms.

macro_rules! gf2m_field {
    ($elem:ident, $limbs:literal, $limbs2:literal, $m:literal, $f1:literal, $f2:literal, $f3:literal) => {
        #[doc = concat!("An element of GF(2^", stringify!($m), ") - see the module doc comment ",
            "for the reduction polynomial citation and the little-endian byte-order derivation.")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $elem(pub [u64; $limbs]);

        // [`$elem::reduce`]'s word-wise closed form folds a whole word `T` down by XORing
        // `T << shift` / `T >> (64 - shift)` into two adjacent words - `64 - shift` is only
        // defined (no shift-by-64 UB) if `shift` is strictly between 0 and 64. A free (not
        // associated) const so it's checked unconditionally at compile time for every macro
        // instantiation, not only when something happens to reference it.
        const _: () = assert!($f1 > 0 && $f1 < 64 && $f2 > 0 && $f2 < 64 && $f3 > 0 && $f3 < 64);

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
            /// `docs/DECISIONS.md` D-76 / `docs/TASKS.md` T-126: [`super::kalyna_xts`]'s once-per-block
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

            /// Binary-polynomial (carry-less) multiplication into a double-width product - a
            /// 4-bit-window comb method (`docs/DECISIONS.md` D-76 / `docs/TASKS.md` T-125's field-multiply
            /// root cause, `advisor()`-directed): precompute `T[i] = a*i` for every nibble value
            /// `i` in `0..16` (`T[0] = 0`, `T[1] = a`, `T[2i] = T[i] << 1`, `T[2i+1] = T[2i] XOR
            /// a]` - the standard doubling construction, 7 shift+XOR pairs), then walk `b`'s
            /// nibbles most-significant-first, shifting the accumulator left by 4 bits and `XOR`ing
            /// in `T[nibble]` each step. This is `m/4` accumulator iterations instead of the
            /// previous bit-serial method's `m`, each doing one 4-bit shift instead of four 1-bit
            /// ones - measured ~1.8-2.3x faster on the multiply alone (narrower than the ~4-6x a
            /// pure iteration-count argument predicts, most likely the table-build overhead plus
            /// the indexed `T[nibble]` lookup costing more than the old branchless masked-`XOR`
            /// per bit did - not chased further, see the `isolated_timing_*` diagnostics in
            /// `field_axiom_tests` below for the measured numbers), which for
            /// [`super::kalyna_gcm`]/[`super::kalyna_gmac`] (where this multiply was measured to be
            /// 89.6-94.3% of the per-block cost before this change, not the block cipher)
            /// translates directly to throughput. Was the previous right-to-left bit-serial method
            /// mirroring `gf2m163::poly_mul_wide` (`docs/DECISIONS.md` D-25); that citation's
            /// *technique* no longer applies here; `gf2m163` itself is untouched.
            fn poly_mul_wide(a: &[u64; $limbs], b: &[u64; $limbs]) -> [u64; $limbs2] {
                let mut a_wide = [0u64; $limbs2];
                a_wide[..$limbs].copy_from_slice(a);

                let mut t: [[u64; $limbs2]; 16] = [[0u64; $limbs2]; 16];
                t[1] = a_wide;
                for i in 1..8usize {
                    let mut doubled = t[i];
                    Self::shl1(&mut doubled);
                    t[2 * i] = doubled;
                    let mut with_a = doubled;
                    for w in 0..$limbs2 {
                        with_a[w] ^= t[1][w];
                    }
                    t[2 * i + 1] = with_a;
                }

                let mut acc = [0u64; $limbs2];
                let nibbles = $m / 4;
                for k in (0..nibbles).rev() {
                    Self::shl4(&mut acc);
                    let word = k / 16;
                    let shift = (k % 16) * 4;
                    let nibble = ((b[word] >> shift) & 0xF) as usize;
                    for w in 0..$limbs2 {
                        acc[w] ^= t[nibble][w];
                    }
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

            /// Left-shifts a `$limbs2`-limb little-endian array by exactly 4 bits, in place - the
            /// per-nibble accumulator shift `poly_mul_wide`'s comb method uses.
            fn shl4(x: &mut [u64; $limbs2]) {
                let mut carry = 0u64;
                for limb in x.iter_mut() {
                    let next_carry = *limb >> 60;
                    *limb = (*limb << 4) | carry;
                    carry = next_carry;
                }
            }

            /// Reduces a double-width product modulo
            #[doc = concat!("`x^", stringify!($m), " + x^", stringify!($f1), " + x^",
                stringify!($f2), " + x^", stringify!($f3), " + 1`,")]
            /// word-wise instead of bit-at-a-time (`docs/DECISIONS.md` D-56 follow-up,
            /// `docs/TASKS.md` T-195): every word `c[i]` at index `i >= $limbs` is entirely above
            /// degree `m - 1`, so it folds down *as a whole word* in one step. For word index `i`,
            /// let `base = i - $limbs` and `T = c[i]`; every set bit `b` of `T` sits at degree
            /// `64*i + b = 64*base + b + m`, so (mod the polynomial)
            #[doc = concat!("`x^(64*base+b+m) = x^(64*base+b) * x^", stringify!($m),
                " = x^(64*base+b) * (x^", stringify!($f1), " + x^", stringify!($f2), " + x^",
                stringify!($f3), " + 1)`,")]
            /// summed over every set bit of `T` - equivalent to `XOR`ing `T` itself, and `T` shifted
            /// left by `f1`/`f2`/`f3` respectively, into the bit range starting at global position
            /// `64*base`. A shift by `s` (`0 < s < 64`, guaranteed by the const assertion above)
            /// splits across exactly two words: `T << s` supplies the low word's contribution,
            /// `T >> (64 - s)` the carry into the next one up - the same split-shift technique
            /// [`Self::double`]'s fixed single-bit shift already uses, generalized to an arbitrary
            /// sub-word amount. Processing `i` top-down (`$limbs2 - 1` down to `$limbs`) is what
            /// makes a single left-to-right pass sufficient: a contribution from word `i` only
            /// ever lands in words `base` and `base + 1`, both strictly below `i` (since
            /// `$limbs >= 2` in every instantiation here), so every word this loop still has left
            /// to read has already received every contribution aimed at it before it's read.
            /// Cross-checked byte-for-byte against [`Self::reduce_bit_serial_reference`] (the
            /// previous production implementation, kept only as a test/Kani oracle now) by
            /// `field_axiom_tests::reduce_matches_bit_serial_reference` below, and exhaustively for
            /// every possible input by this module's own `#[cfg(kani)]` proofs - not just asserted
            /// equivalent by the derivation above.
            fn reduce(mut c: [u64; $limbs2]) -> Self {
                let terms: [u32; 3] = [$f1, $f2, $f3];
                for i in ($limbs..$limbs2).rev() {
                    let t = c[i];
                    let base = i - $limbs;
                    c[base] ^= t;
                    for shift in terms {
                        c[base] ^= t << shift;
                        c[base + 1] ^= t >> (64 - shift);
                    }
                }

                let mut out = [0u64; $limbs];
                out.copy_from_slice(&c[..$limbs]);
                Self(out)
            }

            /// The previous production `reduce` - processes one bit at a time from the top degree
            /// down: for each set bit at degree `d >= m`, `x^d = x^(d-m) * x^m = x^(d-m) *
            /// (x^f1 + x^f2 + x^f3 + 1)` (mod the polynomial) - clear that bit and XOR in the four
            /// shifted terms. Kept only as an independent, already-years-verified oracle for
            /// [`Self::reduce`]'s word-wise replacement (`docs/TASKS.md` T-195) - not a second
            /// implementation to maintain, hence `#[cfg(any(test, kani))]` rather than a normal
            /// production path.
            #[cfg(any(test, kani))]
            fn reduce_bit_serial_reference(mut c: [u64; $limbs2]) -> Self {
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
        ($mod_name:ident, $elem:ident, $limbs:literal, $limbs2:literal) => {
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

                /// Arbitrary double-width product, the actual input type `reduce`/
                /// `reduce_bit_serial_reference` take - `arb_element()` above only covers
                /// already-narrow field elements, never the full `poly_mul_wide` output range.
                fn arb_wide() -> impl Strategy<Value = [u64; $limbs2]> {
                    proptest::collection::vec(any::<u64>(), $limbs2).prop_map(|v| {
                        let mut wide = [0u64; $limbs2];
                        wide.copy_from_slice(&v);
                        wide
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

                #[test]
                fn reduce_of_all_zero_wide_matches_bit_serial_reference() {
                    assert_eq!(
                        $elem::reduce([0u64; $limbs2]),
                        $elem::reduce_bit_serial_reference([0u64; $limbs2])
                    );
                }

                #[test]
                fn reduce_of_all_ones_wide_matches_bit_serial_reference() {
                    // The one input that sets every carry path the word-wise fold-down has -
                    // every word's top bit set, so every one of the three shifted terms carries
                    // into its neighbor on every iteration.
                    assert_eq!(
                        $elem::reduce([u64::MAX; $limbs2]),
                        $elem::reduce_bit_serial_reference([u64::MAX; $limbs2])
                    );
                }

                proptest! {
                    #[test]
                    fn double_matches_general_multiply_by_two(a in arb_element()) {
                        // `docs/TASKS.md` T-126 / `docs/DECISIONS.md` D-76: `double` must be byte-identical
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

                    #[test]
                    fn reduce_matches_bit_serial_reference(wide in arb_wide()) {
                        // The correctness gate for T-195's word-wise `reduce` rewrite - same
                        // shape as `double_matches_general_multiply_by_two` above: the new,
                        // faster implementation must be byte-identical to the old one on
                        // arbitrary double-width input, not just asymptotically equivalent by
                        // derivation.
                        prop_assert_eq!(
                            $elem::reduce(wide),
                            $elem::reduce_bit_serial_reference(wide)
                        );
                    }
                }
            }
        };
    }

    field_axioms!(gf2m128, Gf2m128, 2, 4);
    field_axioms!(gf2m256, Gf2m256, 4, 8);
    field_axioms!(gf2m512, Gf2m512, 8, 16);

    // TEMPORARY investigation for T-125 (`docs/DECISIONS.md` D-76 follow-up) - not a permanent test,
    // remove after the field-multiply-vs-block-cipher ratio is recorded. `#[ignore]`d since it's a
    // manual-timing diagnostic, not a correctness assertion; run with `--release --ignored
    // --nocapture` for a meaningful number.
    #[test]
    #[ignore]
    fn isolated_timing_gf2m256_multiply_vs_kalyna256_256_encrypt_block() {
        use std::hint::black_box;
        use std::time::Instant;

        let key = [0x11u8; 32];
        let cipher = super::super::kalyna::Kalyna256_256ExpandedKey::new(&key);
        let block = [0x22u8; 32];

        let a = Gf2m256([
            0x1111_1111_1111_1111u64,
            0x2222_2222_2222_2222,
            0x3333_3333_3333_3333,
            0x4444_4444_4444_4444,
        ]);
        let b = Gf2m256([
            0x5555_5555_5555_5555u64,
            0x6666_6666_6666_6666,
            0x7777_7777_7777_7777,
            0x8888_8888_8888_8888,
        ]);

        const N: u32 = 2_000_000;

        let start = Instant::now();
        let mut acc_block = block;
        for _ in 0..N {
            acc_block = black_box(cipher.encrypt_block(black_box(&acc_block)));
        }
        let block_elapsed = start.elapsed();
        black_box(acc_block);

        let start = Instant::now();
        let mut acc = a;
        for _ in 0..N {
            acc = black_box(acc.multiply(black_box(b)));
        }
        let mult_elapsed = start.elapsed();
        black_box(acc);

        let block_ns = block_elapsed.as_nanos() as f64 / f64::from(N);
        let mult_ns = mult_elapsed.as_nanos() as f64 / f64::from(N);
        eprintln!(
            "encrypt_block: {block_ns:.1} ns/op | Gf2m256::multiply: {mult_ns:.1} ns/op | ratio (multiply/block) = {:.2}x",
            mult_ns / block_ns
        );
    }

    // TEMPORARY investigation for T-195's Tier 1 (hardware carry-less-multiply spike) -
    // `advisor()`-directed: before touching `poly_mul_wide`, confirm `reduce` is still a small
    // share of `Gf2m256::multiply()` at *current* (post-T-125 comb-method) speed - the module doc's
    // "small fraction" claim was measured against the old bit-serial multiply (~16,384 word-ops),
    // not the current one. Not a permanent test, same `#[ignore]`d/manual-timing posture as the
    // sibling diagnostics above; remove after the split is recorded in `docs/TASKS.md`.
    #[test]
    #[ignore]
    fn isolated_timing_gf2m256_poly_mul_wide_vs_reduce_split() {
        // Each sub-loop chains its output back into the next iteration's input (matching
        // `kalyna_gcm`'s real `acc = acc.add(...).multiply(h_key)` accumulator pattern, and the
        // sibling `isolated_timing_gf2m256_multiply_vs_kalyna256_256_encrypt_block` test above) -
        // a first version without chaining measured independent, ILP-parallelizable calls on fixed
        // inputs and undercounted both terms by ~2x relative to that sibling test's chained
        // `multiply()` number, which is not the pattern GCM actually exercises.
        use std::hint::black_box;
        use std::time::Instant;

        let b: [u64; 4] = [
            0x5555_5555_5555_5555u64,
            0x6666_6666_6666_6666,
            0x7777_7777_7777_7777,
            0x8888_8888_8888_8888,
        ];

        const N: u32 = 2_000_000;

        let start = Instant::now();
        let mut a: [u64; 4] = [
            0x1111_1111_1111_1111u64,
            0x2222_2222_2222_2222,
            0x3333_3333_3333_3333,
            0x4444_4444_4444_4444,
        ];
        for _ in 0..N {
            let wide = black_box(Gf2m256::poly_mul_wide(black_box(&a), black_box(&b)));
            a.copy_from_slice(&wide[..4]);
        }
        let mul_elapsed = start.elapsed();
        black_box(a);

        let start = Instant::now();
        let mut wide: [u64; 8] = [
            0x1111_1111_1111_1111u64,
            0x2222_2222_2222_2222,
            0x3333_3333_3333_3333,
            0x4444_4444_4444_4444,
            0x5555_5555_5555_5555,
            0x6666_6666_6666_6666,
            0x7777_7777_7777_7777,
            0x8888_8888_8888_8888,
        ];
        for _ in 0..N {
            let reduced = black_box(Gf2m256::reduce(black_box(wide)));
            wide[..4].copy_from_slice(&reduced.0);
        }
        let reduce_elapsed = start.elapsed();
        black_box(wide);

        let mul_ns = mul_elapsed.as_nanos() as f64 / f64::from(N);
        let reduce_ns = reduce_elapsed.as_nanos() as f64 / f64::from(N);
        let total_ns = mul_ns + reduce_ns;
        eprintln!(
            "poly_mul_wide (chained): {mul_ns:.1} ns/op | reduce (chained): {reduce_ns:.1} ns/op | reduce share = {:.1}% | sum = {total_ns:.1} ns/op",
            100.0 * reduce_ns / total_ns
        );
    }

    #[test]
    #[ignore]
    fn isolated_timing_gf2m128_multiply_vs_kalyna128_128_encrypt_block() {
        use std::hint::black_box;
        use std::time::Instant;

        let key = [0x11u8; 16];
        let cipher = super::super::kalyna::Kalyna128_128ExpandedKey::new(&key);
        let block = [0x22u8; 16];

        let a = Gf2m128([0x1111_1111_1111_1111u64, 0x2222_2222_2222_2222]);
        let b = Gf2m128([0x5555_5555_5555_5555u64, 0x6666_6666_6666_6666]);

        const N: u32 = 2_000_000;

        let start = Instant::now();
        let mut acc_block = block;
        for _ in 0..N {
            acc_block = black_box(cipher.encrypt_block(black_box(&acc_block)));
        }
        let block_elapsed = start.elapsed();
        black_box(acc_block);

        let start = Instant::now();
        let mut acc = a;
        for _ in 0..N {
            acc = black_box(acc.multiply(black_box(b)));
        }
        let mult_elapsed = start.elapsed();
        black_box(acc);

        let block_ns = block_elapsed.as_nanos() as f64 / f64::from(N);
        let mult_ns = mult_elapsed.as_nanos() as f64 / f64::from(N);
        eprintln!(
            "encrypt_block: {block_ns:.1} ns/op | Gf2m128::multiply: {mult_ns:.1} ns/op | ratio (multiply/block) = {:.2}x",
            mult_ns / block_ns
        );
    }

    #[test]
    #[ignore]
    fn isolated_timing_gf2m512_multiply_vs_kalyna512_512_encrypt_block() {
        use std::hint::black_box;
        use std::time::Instant;

        let key = [0x11u8; 64];
        let cipher = super::super::kalyna::Kalyna512_512ExpandedKey::new(&key);
        let block = [0x22u8; 64];

        let a = Gf2m512([
            0x1111_1111_1111_1111u64,
            0x2222_2222_2222_2222,
            0x3333_3333_3333_3333,
            0x4444_4444_4444_4444,
            0x1111_1111_1111_1111u64,
            0x2222_2222_2222_2222,
            0x3333_3333_3333_3333,
            0x4444_4444_4444_4444,
        ]);
        let b = Gf2m512([
            0x5555_5555_5555_5555u64,
            0x6666_6666_6666_6666,
            0x7777_7777_7777_7777,
            0x8888_8888_8888_8888,
            0x5555_5555_5555_5555u64,
            0x6666_6666_6666_6666,
            0x7777_7777_7777_7777,
            0x8888_8888_8888_8888,
        ]);

        const N: u32 = 2_000_000;

        let start = Instant::now();
        let mut acc_block = block;
        for _ in 0..N {
            acc_block = black_box(cipher.encrypt_block(black_box(&acc_block)));
        }
        let block_elapsed = start.elapsed();
        black_box(acc_block);

        let start = Instant::now();
        let mut acc = a;
        for _ in 0..N {
            acc = black_box(acc.multiply(black_box(b)));
        }
        let mult_elapsed = start.elapsed();
        black_box(acc);

        let block_ns = block_elapsed.as_nanos() as f64 / f64::from(N);
        let mult_ns = mult_elapsed.as_nanos() as f64 / f64::from(N);
        eprintln!(
            "encrypt_block: {block_ns:.1} ns/op | Gf2m512::multiply: {mult_ns:.1} ns/op | ratio (multiply/block) = {:.2}x",
            mult_ns / block_ns
        );
    }
}

/// Bounded model checking for [`Self::reduce`]'s word-wise rewrite (`docs/TASKS.md` T-195),
/// mirroring [`super::dstu4145::gf2m163`]'s own `kani_proofs` module (same "differential test is
/// the real proof, Kani only for the tractable subset" split that module's own doc comment already
/// established) - the `field_axiom_tests` proptest above cross-checks `reduce` against
/// `reduce_bit_serial_reference` on ~256 random double-width inputs per field size; this proves
/// they agree on *every* possible input, not a sample, reusing the same already-years-verified
/// `reduce_bit_serial_reference` oracle rather than writing a third from-scratch reference.
/// **Cannot run on Windows at all** (`docs/DECISIONS.md` D-102, `xtask::kani`'s own doc comment) -
/// CI (Linux) is the only venue that actually executes these; not run locally as part of this
/// change, unlike every other test in this file.
#[cfg(kani)]
mod kani_proofs {
    use super::{Gf2m128, Gf2m256, Gf2m512};

    macro_rules! reduce_kani_proof {
        ($mod_name:ident, $elem:ident, $limbs2:literal) => {
            mod $mod_name {
                use super::*;

                #[kani::proof]
                fn reduce_matches_bit_serial_reference() {
                    let c: [u64; $limbs2] = kani::any();
                    assert_eq!($elem::reduce(c), $elem::reduce_bit_serial_reference(c));
                }
            }
        };
    }

    reduce_kani_proof!(gf2m128, Gf2m128, 4);
    reduce_kani_proof!(gf2m256, Gf2m256, 8);
    reduce_kani_proof!(gf2m512, Gf2m512, 16);
}

/// A single pairwise 64x64 -> 128-bit hardware carry-less multiply, one implementation per
/// architecture this project targets (`docs/TASKS.md` T-195's Tier 1 spike, `advisor()`-directed:
/// owner asked to measure the real lever, not estimate it). `#[target_feature(enable = ...)]` on
/// an `unsafe fn`, gated by a *runtime* feature check at every call site - not
/// `#[cfg(target_feature = ...)]`, which would be `false` on this project's actual baseline build
/// (no `-C target-feature=+...` override anywhere in `hazmat`) and would silently compile the
/// hardware path out entirely, producing a false "no speedup" result instead of a missing one.
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) mod clmul_native {
    use std::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};

    /// `PCLMULQDQ`, imm8 `0x00` selects the low 64 bits of both 128-bit operands - exactly the two
    /// `u64`s placed there by `_mm_set_epi64x(0, x as i64)` below.
    #[target_feature(enable = "pclmulqdq")]
    unsafe fn clmul64_impl(a: u64, b: u64) -> (u64, u64) {
        let ma = _mm_set_epi64x(0, a as i64);
        let mb = _mm_set_epi64x(0, b as i64);
        let prod = _mm_clmulepi64_si128(ma, mb, 0x00);
        let mut bytes = [0u8; 16];
        _mm_storeu_si128(bytes.as_mut_ptr().cast::<__m128i>(), prod);
        let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        (lo, hi)
    }

    pub(crate) fn feature_available() -> bool {
        is_x86_feature_detected!("pclmulqdq")
    }

    /// # Safety
    /// Caller must have checked [`feature_available`] first.
    pub(crate) unsafe fn clmul64(a: u64, b: u64) -> (u64, u64) {
        clmul64_impl(a, b)
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
pub(crate) mod clmul_native {
    use std::arch::aarch64::vmull_p64;

    /// `PMULL` - gated by the `aes` target feature (ARM bundles `PMULL` into the same
    /// cryptographic-extension hardware block as AES, confirmed via this project's own
    /// `rustc --print target-features` output on the Raspberry Pi, "fuse-crypto-eor - CPU fuses
    /// AES/PMULL and EOR operations"; `/proc/cpuinfo`'s `pmull` flag is the actual presence check,
    /// there is no separate `pmull`-named Rust target feature to gate on).
    #[target_feature(enable = "aes")]
    unsafe fn clmul64_impl(a: u64, b: u64) -> (u64, u64) {
        let prod: u128 = vmull_p64(a, b);
        (prod as u64, (prod >> 64) as u64)
    }

    pub(crate) fn feature_available() -> bool {
        std::arch::is_aarch64_feature_detected!("aes")
    }

    /// # Safety
    /// Caller must have checked [`feature_available`] first.
    pub(crate) unsafe fn clmul64(a: u64, b: u64) -> (u64, u64) {
        clmul64_impl(a, b)
    }
}

/// T-195 Tier 1 spike: does a hardware carry-less-multiply instruction move `multiply()`'s
/// (not just `poly_mul_wide`'s) throughput? Schoolbook (not Karatsuba - checkable limb-by-limb
/// against the existing reference, per `advisor()`) combination of pairwise hardware `clmul64`s:
/// for narrow inputs `a`, `b` with `limbs` 64-bit words each, `out[i+j] ^= lo` / `out[i+j+1] ^= hi`
/// for every `(i, j)` pair - the same limb-placement identity [`Gf2m256::poly_mul_wide`]'s comb
/// method computes a different way, cross-checked against it directly below before any timing is
/// trusted. Feeds the *production* [`Gf2m256::reduce`] afterward (not a second reduce
/// implementation) so the measured number is `multiply()`'s real replacement cost, not
/// `poly_mul_wide` in isolation - this session's own earlier mistake (T-195's "at most 38%"
/// estimate, made before `reduce` itself got fixed) is exactly the shape a `poly_mul_wide`-only
/// number would repeat. Diagnostic-only, `#[cfg(test)]`, no production code touched - see
/// `docs/TASKS.md` T-195 for the still-open feature-detection/`no_std`/fallback design a real
/// landing would need.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod clmul_spike {
    use super::clmul_native::{clmul64, feature_available};
    use super::{Gf2m128, Gf2m256, Gf2m512};
    use proptest::prelude::*;

    /// Kalyna-XTS 256-256's own measured throughput (`docs/PERFORMANCE.md`, no authentication tag
    /// at all - pure cipher): no CLMUL result on `multiply()` can push Kalyna-GCM's *overall*
    /// throughput above this, since GCM is cipher + tag no matter how cheap the tag gets. A
    /// projected number above this line means the measurement is wrong, not the instruction.
    const KALYNA_XTS_256_256_CEILING_MB_S: f64 = 163.82;

    fn schoolbook_clmul_poly_mul_wide(a: &[u64], b: &[u64]) -> Vec<u64> {
        let limbs = a.len();
        let mut out = vec![0u64; limbs * 2];
        for i in 0..limbs {
            for j in 0..limbs {
                // Safety: every call site below checks `feature_available()` first.
                let (lo, hi) = unsafe { clmul64(a[i], b[j]) };
                out[i + j] ^= lo;
                out[i + j + 1] ^= hi;
            }
        }
        out
    }

    macro_rules! clmul_spike_for {
        ($mod_name:ident, $elem:ident, $limbs:literal, $limbs2:literal) => {
            mod $mod_name {
                use super::*;

                fn arb_narrow() -> impl Strategy<Value = [u64; $limbs]> {
                    proptest::collection::vec(any::<u64>(), $limbs).prop_map(|v| {
                        let mut out = [0u64; $limbs];
                        out.copy_from_slice(&v);
                        out
                    })
                }

                proptest! {
                    #[test]
                    fn clmul_poly_mul_wide_matches_software_reference(a in arb_narrow(), b in arb_narrow()) {
                        if !feature_available() {
                            return Ok(());
                        }
                        let hw = schoolbook_clmul_poly_mul_wide(&a, &b);
                        let sw = $elem::poly_mul_wide(&a, &b);
                        prop_assert_eq!(hw.as_slice(), sw.as_slice());
                    }
                }

                #[test]
                #[ignore]
                fn isolated_timing_clmul_vs_software_multiply() {
                    if !feature_available() {
                        eprintln!(
                            "{}: hardware clmul feature not available on this CPU, skipping",
                            stringify!($elem)
                        );
                        return;
                    }
                    use std::hint::black_box;
                    use std::time::Instant;

                    const N: u32 = 2_000_000;
                    let a = [0x1111_1111_1111_1111u64; $limbs];
                    let b = [0x5555_5555_5555_5555u64; $limbs];

                    // Software baseline: existing production `multiply()` (comb `poly_mul_wide` +
                    // word-wise `reduce`), chained the same way every other diagnostic in this file
                    // chains, matching `kalyna_gcm`'s real accumulator dependency pattern.
                    let start = Instant::now();
                    let mut acc = $elem(a);
                    let operand = $elem(b);
                    for _ in 0..N {
                        acc = black_box(acc.multiply(black_box(operand)));
                    }
                    let sw_elapsed = start.elapsed();
                    black_box(acc);

                    // Hardware-`clmul` `poly_mul_wide` feeding the *same* production `reduce`.
                    let start = Instant::now();
                    let mut chained = a;
                    for _ in 0..N {
                        let wide = schoolbook_clmul_poly_mul_wide(black_box(&chained), black_box(&b));
                        let mut wide_arr = [0u64; $limbs2];
                        wide_arr.copy_from_slice(&wide);
                        let reduced = $elem::reduce(wide_arr);
                        chained.copy_from_slice(&reduced.0);
                    }
                    let hw_elapsed = start.elapsed();
                    black_box(chained);

                    let sw_ns = sw_elapsed.as_nanos() as f64 / f64::from(N);
                    let hw_ns = hw_elapsed.as_nanos() as f64 / f64::from(N);
                    eprintln!(
                        "{}: software multiply() = {sw_ns:.1} ns/op | hardware-clmul multiply = {hw_ns:.1} ns/op | speedup = {:.2}x | (Kalyna-XTS 256-256 ceiling = {} MB/s - no GCM projection may exceed this)",
                        stringify!($elem),
                        sw_ns / hw_ns,
                        KALYNA_XTS_256_256_CEILING_MB_S
                    );
                }
            }
        };
    }

    clmul_spike_for!(gf2m128_spike, Gf2m128, 2, 4);
    clmul_spike_for!(gf2m256_spike, Gf2m256, 4, 8);
    clmul_spike_for!(gf2m512_spike, Gf2m512, 8, 16);
}
