//! GF(2^257) field arithmetic, reduced modulo the trinomial `x^257 + x^12 + 1` - the reduction
//! polynomial of DSTU 4145-2002's `m=257` curve. Domain parameters extracted from two independent
//! real DSTU 4145 certificates (a `czo.gov.ua` test-CA certificate and a real Diia-issued
//! production certificate), byte-reversed per the certificates' own "DSTU 4145-2002 little endian"
//! OID convention, confirmed against Bouncy Castle's `DSTU4145NamedCurves.java` `curves[6]`
//! (`ECCurve.F2m(257, 12, ZERO, ...)`) - see `docs/DECISIONS.md` D-185/D-186 for the full
//! provenance and the byte-order pitfall found deriving it.
//!
//! **Correctness-first, not the word-offset-optimized closed form `gf2m163::reduce` uses** for its
//! pentanomial - that hand-derivation is specific to `(m, W)` and doesn't generalize without
//! redoing it from scratch per field size, the same posture already established for
//! `gf2m_wide`'s generic multi-size reduction (`docs/DECISIONS.md`). `reduce` below implements the
//! trinomial identity `x^(257+t) = x^(12+t) + x^t` directly via two fixed folding passes (see its
//! own doc comment for the bit-count proof that two passes are necessary and sufficient) - a future
//! perf task may hand-derive a closed form the way `gf2m163::reduce` has one, mirroring `T-45`'s
//! own "not scheduled, sketched only" precedent for `gf2m163::multiply`.
//!
//! **Branchless by construction** (`docs/DECISIONS.md` D-25), same discipline as `gf2m163`: no
//! secret-dependent branching or array indexing anywhere below. `multiply`'s software path selects
//! each shifted operand via an all-ones/all-zeros mask; `reduce`'s folding passes run unconditionally
//! regardless of operand values; `invert`'s only "branch" is on the fixed, public addition chain for
//! the exponent `2^257 - 2`, identical on every call regardless of the secret operand.

/// An element of GF(2^257): 5 little-endian 64-bit limbs. Bits 257..320 (the unused top 63 bits of
/// the last limb) are always zero - every constructor and operation below maintains this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u64; 5]);

impl core::ops::Add for FieldElement {
    type Output = Self;

    /// GF(2^257) addition is bitwise XOR - no carry, no reduction needed.
    fn add(self, other: Self) -> Self {
        FieldElement([
            self.0[0] ^ other.0[0],
            self.0[1] ^ other.0[1],
            self.0[2] ^ other.0[2],
            self.0[3] ^ other.0[3],
            self.0[4] ^ other.0[4],
        ])
    }
}

impl FieldElement {
    pub const ZERO: FieldElement = FieldElement([0, 0, 0, 0, 0]);
    pub const ONE: FieldElement = FieldElement([1, 0, 0, 0, 0]);

    /// Builds a field element from a big-endian byte slice (up to 33 bytes / 257 bits). The
    /// caller must ensure the value is already less than `2^257` - this does not reduce.
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; 5];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            let limb = i / 8;
            let shift = (i % 8) * 8;
            limbs[limb] |= u64::from(byte) << shift;
        }
        FieldElement(limbs)
    }

    /// Big-endian encoding, fixed at 33 bytes (257 bits, rounded up to a whole byte count).
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

    /// Dispatches to the hardware-`clmul` `poly_mul_wide_hw` below when the CPU supports it
    /// (`std`-gated runtime detection, same shape as `gf2m163`/`gf2m_wide`'s own dispatch,
    /// `docs/TASKS.md` T-198/T-199, `docs/DECISIONS.md` D-184/D-186 Decision 4) and falls back to
    /// the portable bit-serial `poly_mul_wide` otherwise. Landed together with the software path
    /// from this module's first commit, not as a later follow-up task - the dispatch design was
    /// already proven on `gf2m163`/`gf2m_wide`.
    #[must_use]
    pub fn multiply(self, other: Self) -> Self {
        #[cfg(all(
            feature = "std",
            not(kani),
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if crate::hazmat::gf2m_wide::clmul_native::feature_available() {
            // Safety: `feature_available()` just confirmed the CPU supports the target feature
            // `poly_mul_wide_hw` requires.
            let wide = unsafe { poly_mul_wide_hw(&self.0, &other.0) };
            return reduce(wide);
        }
        reduce(poly_mul_wide(&self.0, &other.0))
    }

    #[must_use]
    pub fn square(self) -> Self {
        reduce(square_wide(&self.0))
    }

    /// `self^-1 = self^(2^257 - 2)`, by Fermat's little theorem for `GF(2^257)*`. Undefined for
    /// `self == ZERO` - this returns `ZERO` in that case (Fermat's formula gives `0^k = 0` for any
    /// positive `k`), not a panic, but that value is not a meaningful inverse.
    ///
    /// `2^257 - 2 = 2*(2^256 - 1)`, so this computes `(self^(2^256 - 1))^2`. Since `256 = 2^8` is
    /// itself a power of two, the addition chain for `self^(2^256-1)` is the simplest possible
    /// shape - repeated doubling, `T_(2k) = T_k^(2^k) * T_k` - needing no odd steps the way
    /// `gf2m163::invert`'s chain for the non-power-of-two exponent 163 does:
    /// `1 -> 2 -> 4 -> 8 -> 16 -> 32 -> 64 -> 128 -> 256`, 8 combine steps (one multiply each, plus
    /// the fixed number of squarings the `2^k` part costs), 255 total squarings either way (matches
    /// `gf2m163::invert`'s own "squaring does not become free" note - `docs/DECISIONS.md` D-109).
    /// Verified against a direct (non-addition-chain) oracle by differential test, not by the
    /// chain's derivation alone - see `invert_direct`/`invert_matches_invert_direct` in `tests`.
    #[must_use]
    pub fn invert(self) -> Self {
        // `sq_n(x, n) = x^(2^n)`, i.e. `n` repeated squarings.
        let sq_n = |mut x: Self, n: u32| -> Self {
            for _ in 0..n {
                x = x.square();
            }
            x
        };

        let t1 = self; // self^(2^1 - 1)
        let t2 = sq_n(t1, 1).multiply(t1); // self^(2^2 - 1)
        let t4 = sq_n(t2, 2).multiply(t2); // self^(2^4 - 1)
        let t8 = sq_n(t4, 4).multiply(t4); // self^(2^8 - 1)
        let t16 = sq_n(t8, 8).multiply(t8); // self^(2^16 - 1)
        let t32 = sq_n(t16, 16).multiply(t16); // self^(2^32 - 1)
        let t64 = sq_n(t32, 32).multiply(t32); // self^(2^64 - 1)
        let t128 = sq_n(t64, 64).multiply(t64); // self^(2^128 - 1)
        let t256 = sq_n(t128, 128).multiply(t128); // self^(2^256 - 1)

        t256.square() // self^(2^257 - 2)
    }
}

/// Binary-polynomial (carry-less) multiplication of two 257-bit operands into a 10-limb
/// (640-bit capacity, up to 513 significant bits) product - the same right-to-left shift-and-add
/// method `gf2m163::poly_mul_wide` uses, widened to 5/10 limbs.
fn poly_mul_wide(a: &[u64; 5], b: &[u64; 5]) -> [u64; 10] {
    let mut acc = [0u64; 10];
    let mut shifted = [b[0], b[1], b[2], b[3], b[4], 0, 0, 0, 0, 0];

    for bit_index in 0..257u32 {
        let limb = (bit_index / 64) as usize;
        let bit = bit_index % 64;
        let bit_value = (a[limb] >> bit) & 1;
        let mask = 0u64.wrapping_sub(bit_value); // all-ones if the bit is 1, all-zeros otherwise
        for i in 0..10 {
            acc[i] ^= shifted[i] & mask;
        }
        shl1(&mut shifted);
    }

    acc
}

/// Hardware carry-less-multiply `poly_mul_wide` replacement (`docs/TASKS.md` T-199,
/// `docs/DECISIONS.md` D-186 Decision 4) - schoolbook combination of 25 pairwise 64x64->128
/// hardware `clmul`s, the same limb-placement identity `poly_mul_wide` computes a different way.
/// See `gf2m163::poly_mul_wide_hw`'s own doc comment for why this shape (whole loop inlined inside
/// one `#[target_feature]` function, no separate call boundary) was chosen over a software
/// comb-method rewrite - identical reasoning applies here, this module inherits the same
/// secret-scalar exposure via `curve257::scalar_multiply` once that module exists.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[target_feature(enable = "pclmulqdq")]
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// deliberate: `_mm_set_epi64x`/`_mm_cvtsi128_si64` use `i64` purely as a bit container (no signed
// interpretation anywhere below) - the casts are the intended reinterpret, not a value-changing
// truncation.
unsafe fn poly_mul_wide_hw(a: &[u64; 5], b: &[u64; 5]) -> [u64; 10] {
    use std::arch::x86_64::{
        _mm_clmulepi64_si128, _mm_cvtsi128_si64, _mm_set_epi64x, _mm_srli_si128,
    };
    let mut out = [0u64; 10];
    for i in 0..5 {
        for j in 0..5 {
            // Safety: this function itself requires `pclmulqdq` (target_feature, callers gate on
            // `clmul_native::feature_available()` first).
            let ma = _mm_set_epi64x(0, a[i] as i64);
            let mb = _mm_set_epi64x(0, b[j] as i64);
            let prod = _mm_clmulepi64_si128(ma, mb, 0x00);
            let lo = _mm_cvtsi128_si64(prod) as u64;
            let hi = _mm_cvtsi128_si64(_mm_srli_si128::<8>(prod)) as u64;
            out[i + j] ^= lo;
            out[i + j + 1] ^= hi;
        }
    }
    out
}

/// `aarch64` sibling of the `x86_64` `poly_mul_wide_hw` above - see its own doc comment.
#[cfg(all(feature = "std", target_arch = "aarch64"))]
#[target_feature(enable = "aes")]
unsafe fn poly_mul_wide_hw(a: &[u64; 5], b: &[u64; 5]) -> [u64; 10] {
    use std::arch::aarch64::vmull_p64;
    let mut out = [0u64; 10];
    for i in 0..5 {
        for j in 0..5 {
            // Safety: this function itself requires `aes`/`PMULL` (target_feature, callers gate
            // on `clmul_native::feature_available()` first).
            let prod: u128 = vmull_p64(a[i], b[j]);
            out[i + j] ^= prod as u64;
            out[i + j + 1] ^= (prod >> 64) as u64;
        }
    }
    out
}

/// Explicit software-only multiply, bypassing `multiply()`'s own hardware dispatch entirely - see
/// `gf2m163::multiply_sw`'s own doc comment for why this exists (once `multiply()` dispatches to
/// hardware on any capable CPU, every test calling `a.multiply(b)` silently stops exercising the
/// portable path). Module-level rather than nested in `mod tests` so `clmul_spike`-style sibling
/// test modules could see it too if added later - `#[cfg(test)]` only, no production caller.
#[cfg(test)]
fn multiply_sw(a: FieldElement, b: FieldElement) -> FieldElement {
    reduce(poly_mul_wide(&a.0, &b.0))
}

/// Spreads the low 32 bits of `x` across the low 64 bits of the result - see
/// `gf2m163::spread32to64`'s own doc comment for the full derivation (identical technique, this is
/// the same function, not re-derived).
fn spread32to64(x: u32) -> u64 {
    let mut x = u64::from(x);
    x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
    x = (x | (x << 8)) & 0x00FF_00FF_00FF_00FF;
    x = (x | (x << 4)) & 0x0F0F_0F0F_0F0F_0F0F;
    x = (x | (x << 2)) & 0x3333_3333_3333_3333;
    x = (x | (x << 1)) & 0x5555_5555_5555_5555;
    x
}

/// Squares a 257-bit operand into its 10-limb (up to 513-bit) wide product, via `spread32to64`
/// instead of a full carry-less self-multiplication - same technique and per-limb placement as
/// `gf2m163::square_wide`, widened to 5 input / 10 output limbs.
fn square_wide(a: &[u64; 5]) -> [u64; 10] {
    let mut out = [0u64; 10];
    for i in 0..5 {
        #[allow(clippy::cast_possible_truncation)]
        // deliberate: splitting a limb into its two halves
        let lo = a[i] as u32;
        #[allow(clippy::cast_possible_truncation)]
        // deliberate: splitting a limb into its two halves
        let hi = (a[i] >> 32) as u32;
        out[2 * i] = spread32to64(lo);
        out[2 * i + 1] = spread32to64(hi);
    }
    out
}

/// Left-shifts a 10-limb little-endian array by exactly 1 bit, in place.
fn shl1(x: &mut [u64; 10]) {
    let mut carry = 0u64;
    for limb in x.iter_mut() {
        let next_carry = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
}

/// Reduces a 10-limb (up to 576-bit capacity, up to 513 significant bits) product modulo
/// `x^257 + x^12 + 1`, producing a fully-reduced 5-limb field element.
///
/// Implements the trinomial identity `x^(257+t) = x^(12+t) + x^t` directly, i.e. the "excess"
/// portion `h = c >> 257` folds back in as `h XOR (h << 12)`, applied twice:
///
/// **Pass 1.** Input `c` has at most 513 significant bits (two <=257-bit operands multiply to at
/// most 513 bits). `h1 = c >> 257` therefore has at most `513 - 257 = 256` bits - exactly 4 limbs,
/// computed here into a 5-limb buffer (limb 4 providably always zero, not runtime-checked, matching
/// this module's branchless posture). `h1 << 12` then has at most `256 + 12 = 268` bits - 5 limbs
/// (limb-4-max bit index `267 - 256 = 11`), still fits the same 5-limb buffer with no 6th limb ever
/// needed. `pass1 = lo1 XOR h1 XOR (h1 << 12)`, where `lo1` is `c`'s low 257 bits - `pass1` can
/// therefore still exceed 257 bits, by at most `268 - 257 = 11` bits.
///
/// **Pass 2 (cleanup).** `h2 = pass1 >> 257` has at most 11 bits by the bound above - small enough
/// to live entirely in a single word (`pass1[4] >> 1`, no cross-limb carry). `h2 << 12` then has at
/// most `11 + 12 = 23` bits, also a single word, `XORed` directly into the result's limb 0 (23 < 64,
/// no spread across limbs needed). The result is `lo2 XOR h2 XOR (h2 << 12)`, all now within 257
/// bits - **exactly two passes are necessary and sufficient**, proven by this bit-count bound, not
/// discovered by iterating until convergence (branchless per `docs/DECISIONS.md` D-25 - same
/// "provably sufficient, run the fixed count" posture `gf2m163::reduce`'s own cleanup pass uses).
fn reduce(c: [u64; 10]) -> FieldElement {
    // Pass 1: split c into its low 257 bits (lo1) and everything above (h1 = c >> 257), then fold
    // h1 back in via the trinomial identity.
    let mut h1 = [0u64; 5];
    for i in 0..5 {
        h1[i] = (c[i + 4] >> 1) | (c[i + 5] << 63);
    }
    let lo1 = [c[0], c[1], c[2], c[3], c[4] & 1];

    let mut h1_shifted = [0u64; 5];
    h1_shifted[0] = h1[0] << 12;
    for i in 1..5 {
        h1_shifted[i] = (h1[i] << 12) | (h1[i - 1] >> 52);
    }

    let mut pass1 = [0u64; 5];
    for i in 0..5 {
        pass1[i] = lo1[i] ^ h1[i] ^ h1_shifted[i];
    }

    // Pass 2 (cleanup): pass1 has at most 268 bits, so its own excess (h2 = pass1 >> 257) has at
    // most 11 bits - small enough that h2 and h2 << 12 (<= 23 bits) both live entirely in limb 0,
    // no multi-limb shifting needed.
    let h2 = pass1[4] >> 1;
    let h2_shifted = h2 << 12;

    let mut result = [pass1[0], pass1[1], pass1[2], pass1[3], pass1[4] & 1];
    result[0] ^= h2 ^ h2_shifted;

    FieldElement(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn spread32to64_places_each_bit_at_double_position() {
        for bit in 0..32u32 {
            let x = 1u32 << bit;
            assert_eq!(spread32to64(x), 1u64 << (2 * bit), "bit {bit}");
        }
    }

    #[test]
    fn spread32to64_of_zero_and_all_ones() {
        assert_eq!(spread32to64(0), 0);
        assert_eq!(spread32to64(u32::MAX), 0x5555_5555_5555_5555);
    }

    /// `square_wide` must match the already-trusted `poly_mul_wide(a, a)` oracle at the *wide*
    /// (pre-`reduce`) level - see `gf2m163`'s identical test for the rationale. Bit 256 is the top
    /// meaningful bit (limb 4, which is only 1/64 full).
    #[test]
    fn square_wide_matches_multiply_wide_at_limb_boundaries() {
        for bit in [0u32, 1, 63, 64, 65, 127, 128, 191, 192, 255, 256] {
            let limb = (bit / 64) as usize;
            let shift = bit % 64;
            let mut a = [0u64; 5];
            a[limb] = 1u64 << shift;
            assert_eq!(square_wide(&a), poly_mul_wide(&a, &a), "bit {bit}");
        }
    }

    /// Every meaningful bit set at once (257 bits, top 63 bits of limb 4 zero - the invariant
    /// every `FieldElement` upholds).
    #[test]
    fn square_wide_matches_multiply_wide_for_all_bits_set() {
        let a = [u64::MAX, u64::MAX, u64::MAX, u64::MAX, 1u64];
        assert_eq!(square_wide(&a), poly_mul_wide(&a, &a));
    }

    /// `reduce`'s two-pass folding, cross-checked at the wide-product level for values sitting
    /// exactly at the pass-1/pass-2 boundary this module's own doc comment derives (bit 267, the
    /// highest bit `h1 << 12` can ever set) against a direct, unoptimized bit-at-a-time reduction -
    /// an independent second algorithm, not a restatement of `reduce`'s own folding steps.
    fn reduce_naive(c: [u64; 10]) -> FieldElement {
        // Direct polynomial long division against x^257 + x^12 + 1: for each bit from the top
        // down, if set, XOR the shifted trinomial pattern (x^12 + 1, i.e. bits {12, 0}) in at that
        // position and clear the source bit - the textbook definition of reduction mod f(x).
        let mut c = c;
        for bit in (257..513).rev() {
            let limb = bit / 64;
            let shift = bit % 64;
            let is_set = (c[limb] >> shift) & 1 == 1;
            if is_set {
                c[limb] ^= 1u64 << shift;
                let t = bit - 257;
                let t12 = t + 12;
                c[t12 / 64] ^= 1u64 << (t12 % 64);
                c[t / 64] ^= 1u64 << (t % 64);
            }
        }
        FieldElement([c[0], c[1], c[2], c[3], c[4]])
    }

    #[test]
    fn reduce_matches_naive_bit_at_a_time_reduction_at_boundaries() {
        for bit in [0u32, 1, 12, 63, 64, 256, 257, 267, 268, 300, 400, 512] {
            let limb = (bit / 64) as usize;
            let shift = bit % 64;
            let mut c = [0u64; 10];
            c[limb] = 1u64 << shift;
            assert_eq!(reduce(c), reduce_naive(c), "bit {bit}");
        }
    }

    proptest! {
        #[test]
        fn reduce_matches_naive_bit_at_a_time_reduction_for_random_wide_values(
            limbs in prop::collection::vec(any::<u64>(), 9)
        ) {
            // Top limb (index 9) stays zero - the real wide product of two 257-bit operands never
            // reaches bit 576, only up to bit 512 (limb 8's low bit).
            let mut c = [0u64; 10];
            c[..9].copy_from_slice(&limbs);
            c[8] &= 1; // bound to the real <=513-bit range poly_mul_wide/square_wide ever produce
            prop_assert_eq!(reduce(c), reduce_naive(c));
        }
    }

    /// The direct (non-addition-chain) `self^(2^257-2)` computation, kept only as a test-only
    /// oracle for `invert`'s addition-chain implementation - mirrors `gf2m163::invert_direct`.
    fn invert_direct(a: FieldElement) -> FieldElement {
        let mut result = FieldElement::ONE;
        for _ in 0..256 {
            result = result.square();
            result = result.multiply(a);
        }
        result.square()
    }

    proptest! {
        #[test]
        fn invert_matches_invert_direct(bytes in prop::collection::vec(any::<u8>(), 33)) {
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&bytes);
            arr[0] &= 0x01; // stay below 2^257, same invariant every constructor upholds
            let a = FieldElement::from_be_bytes(&arr);
            prop_assume!(a != FieldElement::ZERO);
            prop_assert_eq!(a.invert(), invert_direct(a));
        }
    }

    proptest! {
        #[test]
        fn multiply_matches_explicit_software_path(
            a_bytes in prop::collection::vec(any::<u8>(), 33),
            b_bytes in prop::collection::vec(any::<u8>(), 33),
        ) {
            let mut a_arr = [0u8; 33];
            a_arr.copy_from_slice(&a_bytes);
            a_arr[0] &= 0x01;
            let mut b_arr = [0u8; 33];
            b_arr.copy_from_slice(&b_bytes);
            b_arr[0] &= 0x01;
            let a = FieldElement::from_be_bytes(&a_arr);
            let b = FieldElement::from_be_bytes(&b_arr);
            prop_assert_eq!(a.multiply(b), multiply_sw(a, b));
        }
    }

    proptest! {
        #[test]
        fn multiply_sw_is_commutative(
            a_bytes in prop::collection::vec(any::<u8>(), 33),
            b_bytes in prop::collection::vec(any::<u8>(), 33),
        ) {
            let mut a_arr = [0u8; 33];
            a_arr.copy_from_slice(&a_bytes);
            a_arr[0] &= 0x01;
            let mut b_arr = [0u8; 33];
            b_arr.copy_from_slice(&b_bytes);
            b_arr[0] &= 0x01;
            let a = FieldElement::from_be_bytes(&a_arr);
            let b = FieldElement::from_be_bytes(&b_arr);
            prop_assert_eq!(multiply_sw(a, b), multiply_sw(b, a));
        }
    }

    proptest! {
        #[test]
        fn multiply_sw_is_associative(
            a_bytes in prop::collection::vec(any::<u8>(), 33),
            b_bytes in prop::collection::vec(any::<u8>(), 33),
            c_bytes in prop::collection::vec(any::<u8>(), 33),
        ) {
            let mut a_arr = [0u8; 33];
            a_arr.copy_from_slice(&a_bytes);
            a_arr[0] &= 0x01;
            let mut b_arr = [0u8; 33];
            b_arr.copy_from_slice(&b_bytes);
            b_arr[0] &= 0x01;
            let mut c_arr = [0u8; 33];
            c_arr.copy_from_slice(&c_bytes);
            c_arr[0] &= 0x01;
            let a = FieldElement::from_be_bytes(&a_arr);
            let b = FieldElement::from_be_bytes(&b_arr);
            let c = FieldElement::from_be_bytes(&c_arr);
            prop_assert_eq!(multiply_sw(multiply_sw(a, b), c), multiply_sw(a, multiply_sw(b, c)));
        }
    }

    proptest! {
        #[test]
        fn multiply_sw_distributes_over_add(
            a_bytes in prop::collection::vec(any::<u8>(), 33),
            b_bytes in prop::collection::vec(any::<u8>(), 33),
            c_bytes in prop::collection::vec(any::<u8>(), 33),
        ) {
            let mut a_arr = [0u8; 33];
            a_arr.copy_from_slice(&a_bytes);
            a_arr[0] &= 0x01;
            let mut b_arr = [0u8; 33];
            b_arr.copy_from_slice(&b_bytes);
            b_arr[0] &= 0x01;
            let mut c_arr = [0u8; 33];
            c_arr.copy_from_slice(&c_bytes);
            c_arr[0] &= 0x01;
            let a = FieldElement::from_be_bytes(&a_arr);
            let b = FieldElement::from_be_bytes(&b_arr);
            let c = FieldElement::from_be_bytes(&c_arr);
            prop_assert_eq!(multiply_sw(a, b + c), multiply_sw(a, b) + multiply_sw(a, c));
        }
    }

    proptest! {
        #[test]
        fn multiply_sw_by_one_is_identity(bytes in prop::collection::vec(any::<u8>(), 33)) {
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&bytes);
            arr[0] &= 0x01;
            let a = FieldElement::from_be_bytes(&arr);
            prop_assert_eq!(multiply_sw(a, FieldElement::ONE), a);
        }
    }
}
