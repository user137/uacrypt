//! GF(2^163) field arithmetic, reduced modulo the pentanomial `x^163 + x^7 + x^6 + x^3 + 1` - the
//! reduction polynomial of the DSTU 4145-2002 curve dual-sourced in
//! `tests/vectors/dstu4145/gf2m163.json` (`docs/DECISIONS.md` D-14), matching
//! `oracles/bouncycastle-java/.../DSTU4145NamedCurves.java`'s `ECCurve.F2m(163, 3, 6, 7, ...)`
//! constructor (`k1, k2, k3 = 3, 6, 7`).
//!
//! **Branchless by construction** (`docs/DECISIONS.md` D-25): every operation below runs the same
//! sequence of word ops regardless of the operand values. `multiply` selects each shifted operand
//! via an all-ones/all-zeros mask derived from a single bit rather than an `if`, and `reduce`'s
//! word-reduction and final cleanup pass run unconditionally rather than skipping zero words or
//! looping until convergence (both real optimizations in the reference this was adapted from,
//! OpenSSL's `BN_GF2m_mod_arr`, and both would branch on secret-dependent data here). `invert`'s
//! only "branch" is on the fixed, public inversion exponent `2^163 - 2` - identical on every call
//! regardless of the secret operand, so it carries no timing signal about that operand.
//!
//! `square` is a pure bit-spread (`spread32to64`/`square_wide`), not a full multiplication - GF(2)
//! squaring satisfies `a(x)^2 = a(x^2)` since char-2 cross terms vanish, needing only fixed
//! shift/AND/OR ops and no array indexing at all (`docs/DECISIONS.md` D-109, `docs/TASKS.md` T-153).
//! `invert` still runs the same fixed 162-squaring chain either way; only the number of
//! multiplies between squarings differs (D-109's Itoh-Tsujii-style addition chain vs. this file's
//! prior direct form) - both are fixed, public, data-independent sequences.

/// An element of GF(2^163): 3 little-endian 64-bit limbs. Bits 163..192 (the unused top 29 bits
/// of the last limb) are always zero - every constructor and operation below maintains this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u64; 3]);

impl core::ops::Add for FieldElement {
    type Output = Self;

    /// GF(2^163) addition is bitwise XOR - no carry, no reduction needed (the XOR of two values
    /// already below `2^163` stays below `2^163`).
    fn add(self, other: Self) -> Self {
        FieldElement([
            self.0[0] ^ other.0[0],
            self.0[1] ^ other.0[1],
            self.0[2] ^ other.0[2],
        ])
    }
}

impl FieldElement {
    pub const ZERO: FieldElement = FieldElement([0, 0, 0]);
    pub const ONE: FieldElement = FieldElement([1, 0, 0]);

    /// Builds a field element from a big-endian byte slice (up to 21 bytes / 163 bits). The
    /// caller must ensure the value is already less than `2^163` - this does not reduce.
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; 3];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            let limb = i / 8;
            let shift = (i % 8) * 8;
            limbs[limb] |= u64::from(byte) << shift;
        }
        FieldElement(limbs)
    }

    /// Big-endian encoding, fixed at 21 bytes (163 bits, rounded up to a whole byte count).
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

    /// Dispatches to the hardware-`clmul` `poly_mul_wide_hw` below when the CPU supports it
    /// (`std`-gated runtime detection, `docs/TASKS.md` T-198, same shape as `gf2m_wide`'s own
    /// dispatch) and falls back to the portable bit-serial `poly_mul_wide` otherwise -
    /// `no_std`/embedded builds, CPUs without the instruction, and (`not(kani)`) CBMC's own
    /// symbolic execution all take this same unconditional software path, unchanged from before
    /// this task. **This is the function `curve163::scalar_multiply` calls on its own
    /// secret-scalar intermediates** (the signing nonce, the private key) - the hardware path was
    /// chosen over a software comb-method rewrite specifically because it has no secret-indexed
    /// memory access at all (see `poly_mul_wide_hw`'s own doc comment and T-196's revert), so this
    /// dispatch does not reopen that question.
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

    /// `self^-1 = self^(2^163 - 2)`, by Fermat's little theorem for `GF(2^163)*`. Undefined for
    /// `self == ZERO` - this returns `ZERO` in that case (Fermat's formula itself gives `0^k = 0`
    /// for any positive `k`), not a panic, but that value is not a meaningful inverse and callers
    /// must not treat it as one. Ordinarily callers should never invert zero at all (the DSTU 4145
    /// sign/verify pseudocode's own retry loops exist precisely to avoid producing a zero value
    /// that would need inverting) - the one documented exception is
    /// `curve163::scalar_multiply`'s constant-time y-recovery step (`docs/DECISIONS.md` D-110,
    /// T-152), which still calls this on a possibly-zero value (to stay branchless) but explicitly
    /// masks the resulting corrupted output afterward rather than trusting it.
    ///
    /// `2^163 - 2 = 2*(2^162 - 1)`, so this computes `(self^(2^162 - 1))^2`. `self^(2^162 - 1)` is
    /// built via an Itoh-Tsujii-style addition chain, using repeated application of
    /// `T_(i+j) = T_i^(2^j) * T_j` (where `T_k` denotes `self^(2^k - 1)`) over the derived chain
    /// `1 -> 2 -> 3 -> 6 -> 12 -> 24 -> 27 -> 54 -> 81 -> 162` (`162 = 2*81 = 2*(80+1)`) - **9**
    /// combine steps (each one multiply, plus the fixed number of squarings the `2^j` part costs)
    /// instead of the previous direct form's 162 multiplies, needing the same ~162 total squarings
    /// either way (squaring does not become free in this polynomial-basis representation, only the
    /// multiply count drops - `docs/DECISIONS.md` D-109, `docs/TASKS.md` T-153). The chain is a
    /// fixed, public sequence over a fixed, public exponent, identical for every call regardless of
    /// `self`'s value - the same constant-time argument that already justified the prior
    /// fixed-iteration direct form. Verified against that direct form (kept as a test-only oracle,
    /// `invert_direct` below) by differential test, not by the chain's derivation alone.
    #[must_use]
    #[allow(clippy::similar_names)] // deliberate: t12/t162 etc. are the standard T_k = self^(2^k-1) notation
    pub fn invert(self) -> Self {
        // `sq_n(x, n) = x^(2^n)`, i.e. `n` repeated squarings.
        let sq_n = |mut x: Self, n: u32| -> Self {
            for _ in 0..n {
                x = x.square();
            }
            x
        };

        let t1 = self; // self^(2^1 - 1)
        let t2 = t1.square().multiply(t1); // self^(2^2 - 1)
        let t3 = sq_n(t2, 1).multiply(t1); // self^(2^3 - 1)
        let t6 = sq_n(t3, 3).multiply(t3); // self^(2^6 - 1)
        let t12 = sq_n(t6, 6).multiply(t6); // self^(2^12 - 1)
        let t24 = sq_n(t12, 12).multiply(t12); // self^(2^24 - 1)
        let t27 = sq_n(t24, 3).multiply(t3); // self^(2^27 - 1)
        let t54 = sq_n(t27, 27).multiply(t27); // self^(2^54 - 1)
        let t81 = sq_n(t54, 27).multiply(t27); // self^(2^81 - 1)
        let t162 = sq_n(t81, 81).multiply(t81); // self^(2^162 - 1)

        t162.square() // self^(2^163 - 2)
    }
}

/// Binary-polynomial (carry-less) multiplication of two 163-bit operands into a 6-limb (384-bit
/// capacity, up to 325 significant bits) product - the right-to-left shift-and-add method
/// (`Guide to Elliptic Curve Cryptography`, Hankerson/Menezes/Vanstone, Algorithm 2.33), written
/// with a branchless bit-select (`mask`) in place of the algorithm's `if a_i = 1` step.
fn poly_mul_wide(a: &[u64; 3], b: &[u64; 3]) -> [u64; 6] {
    let mut acc = [0u64; 6];
    let mut shifted = [b[0], b[1], b[2], 0u64, 0u64, 0u64];

    for bit_index in 0..163u32 {
        let limb = (bit_index / 64) as usize;
        let bit = bit_index % 64;
        let bit_value = (a[limb] >> bit) & 1;
        let mask = 0u64.wrapping_sub(bit_value); // all-ones if the bit is 1, all-zeros otherwise
        for i in 0..6 {
            acc[i] ^= shifted[i] & mask;
        }
        shl1(&mut shifted);
    }

    acc
}

/// Hardware carry-less-multiply `poly_mul_wide` replacement (`docs/TASKS.md` T-198,
/// `docs/DECISIONS.md` D-184) - schoolbook combination of 9 pairwise 64x64->128 hardware `clmul`s,
/// the same limb-placement identity the bit-serial method above computes a different way
/// (cross-checked directly in `hw_dispatch_tests` below). **Chosen over a software comb-method
/// rewrite of `poly_mul_wide` itself** (implemented, tested, and reverted in T-196): a comb method
/// needs a secret-indexed `T[nibble]` table lookup, which this module's own "Branchless by
/// construction... no array indexing at all" design principle exists to rule out, since this
/// function runs on `curve163::scalar_multiply`'s secret-scalar intermediates. Schoolbook hardware
/// `clmul` has no such cost - `pclmulqdq`/`vmull_p64` is called for a fixed 9 `(i, j)` pairs
/// unconditionally, and the instruction's own latency does not depend on its operand bits. Every
/// intrinsic call sits directly inside this single `#[target_feature]`-attributed function (not
/// behind `gf2m_wide::clmul_native::clmul64`'s separately-attributed wrapper, which the T-196 spike
/// used and which is a real non-inlinable call boundary at every one of the 9 pairs,
/// `advisor()`-flagged before landing this) - the spike's own ~64-65x/~42x numbers are a floor for
/// this production shape, not a target.
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
unsafe fn poly_mul_wide_hw(a: &[u64; 3], b: &[u64; 3]) -> [u64; 6] {
    use std::arch::x86_64::{
        _mm_clmulepi64_si128, _mm_cvtsi128_si64, _mm_set_epi64x, _mm_srli_si128,
    };
    let mut out = [0u64; 6];
    for i in 0..3 {
        for j in 0..3 {
            // Safety: this function itself requires `pclmulqdq` (target_feature, callers gate on
            // `clmul_native::feature_available()` first). Extracting both 64-bit halves via
            // `_mm_cvtsi128_si64`/`_mm_srli_si128` (both SSE2, already required for `__m128i` to
            // exist on this target) avoids the unaligned-pointer-cast `_mm_storeu_si128` into a
            // stack byte array would otherwise need.
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

/// `aarch64` sibling of the `x86_64` `poly_mul_wide_hw` above - see its own doc comment for the
/// rationale (`docs/TASKS.md` T-198).
#[cfg(all(feature = "std", target_arch = "aarch64"))]
#[target_feature(enable = "aes")]
unsafe fn poly_mul_wide_hw(a: &[u64; 3], b: &[u64; 3]) -> [u64; 6] {
    use std::arch::aarch64::vmull_p64;
    let mut out = [0u64; 6];
    for i in 0..3 {
        for j in 0..3 {
            // Safety: this function itself requires `aes`/`PMULL` (target_feature, callers gate
            // on `clmul_native::feature_available()` first).
            let prod: u128 = vmull_p64(a[i], b[j]);
            out[i + j] ^= prod as u64;
            out[i + j + 1] ^= (prod >> 64) as u64;
        }
    }
    out
}

/// Explicit software-only multiply, bypassing `multiply()`'s own hardware dispatch entirely
/// (`docs/TASKS.md` T-198). **Why this exists**: once `multiply()` dispatches to
/// `poly_mul_wide_hw` on any capable CPU (every dev machine and every `x86_64`/`aarch64` CI runner
/// has one), every test in `tests/dstu4145_gf2m.rs` that calls `a.multiply(b)` - the Bouncy Castle
/// oracle vectors, the square-matches-multiply differential, the invert involution check - silently
/// stops exercising the portable `poly_mul_wide` path at all. `poly_mul_wide`/`reduce` are private
/// to this module, so that external test file can't reach them directly - this helper (used by both
/// `tests` and `clmul_spike` below) is the only place that gap can close. Module-level rather than
/// nested in `mod tests` so both sibling test modules can see it - `#[cfg(test)]` only, no
/// production caller.
#[cfg(test)]
fn multiply_sw(a: FieldElement, b: FieldElement) -> FieldElement {
    reduce(poly_mul_wide(&a.0, &b.0))
}

/// Spreads the low 32 bits of `x` across the low 64 bits of the result, each bit `i` of `x`
/// landing at bit `2*i` of the result with a zero bit inserted between every pair - the
/// "interleave bits by binary magic numbers" technique (Sean Eron Anderson's Bit Twiddling Hacks,
/// `graphics.stanford.edu/~seander/bithacks.html#InterleaveBMN`), widened from its usual
/// 16-bit-to-32-bit form to 32-bit-to-64-bit by doubling every mask/shift constant the same way.
/// This computes exactly the GF(2) squaring identity `a(x)^2 = a(x^2)` (char-2 cross terms vanish:
/// `(a_i*x^i)^2 = a_i*x^(2i)` since `a_i` is 0 or 1), applied 32 bits at a time - a pure fixed
/// shift/AND/OR bit-spread, no array indexing anywhere, so no D-19-adjacent secret-indexing
/// question exists at all (`docs/DECISIONS.md` D-25's "branchless by construction" posture,
/// extended to a fresh operation). Verified against the `poly_mul_wide` self-multiply oracle by
/// the `square_wide_matches_multiply_wide_*` tests below, at both every single-bit position and
/// the all-bits-set case, not derived from the citation alone.
fn spread32to64(x: u32) -> u64 {
    let mut x = u64::from(x);
    x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
    x = (x | (x << 8)) & 0x00FF_00FF_00FF_00FF;
    x = (x | (x << 4)) & 0x0F0F_0F0F_0F0F_0F0F;
    x = (x | (x << 2)) & 0x3333_3333_3333_3333;
    x = (x | (x << 1)) & 0x5555_5555_5555_5555;
    x
}

/// Squares a 163-bit operand into its 6-limb (up to 325-bit) wide product, via `spread32to64`
/// instead of a full carry-less `poly_mul_wide` self-multiplication. Each input limb's low/high
/// 32-bit halves spread independently into exactly one 64-bit output limb apiece, with no
/// cross-limb interaction needed: limb `i`'s low 32 bits (global bit range `[64i, 64i+31]`) spread
/// to global bit range `[128i, 128i+62]`, landing entirely within output limb `2i`; its high 32
/// bits (global bit range `[64i+32, 64i+63]`) spread to `[128i+64, 128i+126]`, landing entirely
/// within output limb `2i+1` - both fit with no shift needed at placement time.
fn square_wide(a: &[u64; 3]) -> [u64; 6] {
    let mut out = [0u64; 6];
    for i in 0..3 {
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

/// Left-shifts a 6-limb little-endian array by exactly 1 bit, in place.
fn shl1(x: &mut [u64; 6]) {
    let mut carry = 0u64;
    for limb in x.iter_mut() {
        let next_carry = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
}

/// Reduces a 6-limb (up to 325-bit) product modulo `x^163 + x^7 + x^6 + x^3 + 1`, producing a
/// fully-reduced 3-limb field element. Adapted from OpenSSL's generic `BN_GF2m_mod_arr`
/// (`crypto/bn/bn_gf2m.c`) specialized to `m = 163`, `W = 64` (so `dN = m / W = 2`,
/// `d0 = m % W = 35`, `d1 = W - d0 = 29`) - with its two data-dependent shortcuts removed for
/// constant-time behavior (`docs/DECISIONS.md` D-25):
/// - the source removes a source word entirely if it happens to be zero; this always processes
///   every word.
/// - the source loops the final cleanup step until the overflow is zero; this always runs it a
///   fixed 2 times, which is provably sufficient (see below) and a harmless no-op past that point,
///   since re-XORing an already-zero overflow changes nothing.
fn reduce(mut c: [u64; 6]) -> FieldElement {
    // Main pass: reduce words 5, 4, 3 (each covering exponents >= 163) down into words 0..=3.
    // Each source word `zz` contributes its middle-term (7, 6, 3) and constant-term (0)
    // reductions, all of which land split across exactly two destination words `j-2`/`j-3` for
    // this specific (m, W) pair - see docs/DECISIONS.md D-25 for the derivation of the shift amounts
    // (28/36, 29/35, 32/32 for the three middle terms, 35/29 for the constant term).
    for j in (3..=5).rev() {
        let zz = c[j];
        c[j] = 0;
        c[j - 2] ^= (zz >> 28) ^ (zz >> 29) ^ (zz >> 32) ^ (zz >> 35);
        c[j - 3] ^= (zz << 36) ^ (zz << 35) ^ (zz << 32) ^ (zz << 29);
    }

    // Final cleanup: word 2 (index dN = 2) may still have bits set above position 34 (global
    // exponent 163+), left over from the main pass above. Each pass extracts those overflow bits
    // (at most 29 of them, since a single 64-bit word can only overflow bit 35 by 64-35=29 bits),
    // masks them out of c[2], and folds them into c[0] via the same z^163 = z^7+z^6+z^3+1
    // identity. One pass is provably enough (c[2] is fully masked by the end of it, so a repeat
    // pass reads an all-zero overflow and changes nothing) - run twice anyway as cheap insurance
    // against a subtle off-by-one in that argument, per docs/DECISIONS.md D-25.
    for _ in 0..2 {
        let overflow = c[2] >> 35;
        c[2] = (c[2] << 29) >> 29;
        c[0] ^= overflow ^ (overflow << 3) ^ (overflow << 6) ^ (overflow << 7);
    }

    FieldElement([c[0], c[1], c[2]])
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
    /// (pre-`reduce`) level, not just after reduction - a placement bug in the bit-spread could
    /// otherwise be silently absorbed by `reduce`'s own normalization and slip through undetected.
    /// Bits 63/64 straddle the limb-0/limb-1 boundary; bit 162 is the top meaningful bit, sitting
    /// inside limb 2 (which is only 35/64 full).
    #[test]
    fn square_wide_matches_multiply_wide_at_limb_boundaries() {
        for bit in [0u32, 1, 63, 64, 65, 127, 128, 129, 162] {
            let limb = (bit / 64) as usize;
            let shift = bit % 64;
            let mut a = [0u64; 3];
            a[limb] = 1u64 << shift;
            assert_eq!(square_wide(&a), poly_mul_wide(&a, &a), "bit {bit}");
        }
    }

    /// Every meaningful bit set at once (163 bits, top 29 bits of limb 2 zero - the invariant every
    /// `FieldElement` upholds).
    #[test]
    fn square_wide_matches_multiply_wide_for_all_bits_set() {
        let a = [u64::MAX, u64::MAX, (1u64 << 35) - 1];
        assert_eq!(square_wide(&a), poly_mul_wide(&a, &a));
    }

    /// The pre-D-109 direct 162-step square-and-multiply form of `invert`, kept only as a
    /// test-only oracle for `invert`'s new addition-chain implementation - not a second production
    /// path (same spirit as this module's own `naive_reduce` Kani oracle below).
    fn invert_direct(a: FieldElement) -> FieldElement {
        let mut result = FieldElement::ONE;
        for _ in 0..162 {
            result = result.square();
            result = result.multiply(a);
        }
        result.square()
    }

    // `invert`'s addition-chain form (D-109/T-153) against the direct-loop oracle above, for
    // random nonzero field elements - the actual proof of correctness for this phase, not the
    // derived chain's citation.
    proptest! {
        #[test]
        fn invert_matches_invert_direct(bytes in prop::collection::vec(any::<u8>(), 21)) {
            let mut arr = [0u8; 21];
            arr.copy_from_slice(&bytes);
            arr[0] &= 0x07; // stay below 2^163, same invariant every constructor upholds
            let a = FieldElement::from_be_bytes(&arr);
            prop_assume!(a != FieldElement::ZERO);
            prop_assert_eq!(a.invert(), invert_direct(a));
        }
    }

    proptest! {
        /// The real regression gate for the hardware dispatch's correctness (not just the raw
        /// `clmul` primitive - the *dispatch*, including the CPU-feature check and the
        /// `poly_mul_wide_hw` schoolbook combination), on the exact secret-scalar-shaped operands
        /// `curve163::scalar_multiply` feeds it. A no-op comparison on a CPU without the hardware
        /// feature (both sides then take the same software path), a real one everywhere this
        /// project's own dev machine and CI actually run.
        #[test]
        fn multiply_matches_explicit_software_path(
            a_bytes in prop::collection::vec(any::<u8>(), 21),
            b_bytes in prop::collection::vec(any::<u8>(), 21),
        ) {
            let mut a_arr = [0u8; 21];
            a_arr.copy_from_slice(&a_bytes);
            a_arr[0] &= 0x07;
            let mut b_arr = [0u8; 21];
            b_arr.copy_from_slice(&b_bytes);
            b_arr[0] &= 0x07;
            let a = FieldElement::from_be_bytes(&a_arr);
            let b = FieldElement::from_be_bytes(&b_arr);
            prop_assert_eq!(a.multiply(b), multiply_sw(a, b));
        }
    }

    /// Fixed nonzero edge cases the property test's random sampling might not hit by chance:
    /// `ONE`, and a value with only the top meaningful bit set.
    #[test]
    fn invert_matches_invert_direct_at_edge_values() {
        assert_eq!(FieldElement::ONE.invert(), invert_direct(FieldElement::ONE));
        let mut top_bit = [0u64; 3];
        top_bit[2] = 1u64 << 34; // bit 162, the top meaningful bit
        let a = FieldElement(top_bit);
        assert_eq!(a.invert(), invert_direct(a));
    }
}

/// Kani pilot (see `docs/TASKS.md`/`docs/DECISIONS.md` for the tracked outcome): `reduce`'s doc
/// comment above makes two claims that were previously only hand-argued, never machine-checked -
/// "one pass is provably enough" and the implicit claim that the closed-form word-shift reduction
/// actually computes the same result as the polynomial identity it's derived from. This proves
/// both, for every one of the 2^384 possible 6-limb inputs, not just the fixed vectors and hand-
/// picked property tests `dstu4145_gf2m.rs` already covers.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Bit-at-a-time reference reduction, written directly from the polynomial identity
    /// `x^163 = x^7 + x^6 + x^3 + 1` (mod the field polynomial) with no word-level shortcuts -
    /// the same technique `gf2m_wide::reduce` uses in production, here kept only as an
    /// independent oracle for this proof, not as a second implementation to maintain.
    fn naive_reduce(mut c: [u64; 6]) -> FieldElement {
        for degree in (163u32..384).rev() {
            let limb = (degree / 64) as usize;
            let bit = degree % 64;
            if (c[limb] >> bit) & 1 == 1 {
                c[limb] ^= 1u64 << bit;
                let shift = degree - 163;
                for term in [7u32, 6, 3, 0] {
                    let d = shift + term;
                    let l = (d / 64) as usize;
                    let b = d % 64;
                    c[l] ^= 1u64 << b;
                }
            }
        }
        let mut out = [0u64; 3];
        out.copy_from_slice(&c[..3]);
        FieldElement(out)
    }

    /// Cheaper of the two proofs: `reduce`'s output must always have its top 29 bits (of the
    /// 35-bit-wide word 2) clear - i.e. genuinely `< 2^163`, not just "probably" per the doc
    /// comment's hand-argued overflow bound.
    #[kani::proof]
    fn reduce_output_is_fully_reduced() {
        let c: [u64; 6] = kani::any();
        let r = reduce(c);
        assert_eq!(r.0[2] >> 35, 0);
    }

    /// The expensive proof: `reduce` and `naive_reduce` must agree on every possible input, not
    /// just the ones `dstu4145_gf2m.rs`'s fixed vectors happen to exercise.
    #[kani::proof]
    fn reduce_matches_naive_bit_loop() {
        let c: [u64; 6] = kani::any();
        assert_eq!(reduce(c), naive_reduce(c));
    }

    /// `spread32to64`'s exact bit-doubling specification (D-109/T-153, corrected by D-112):
    /// every bit `i` of a symbolic 32-bit input lands at bit `2*i` of the output, and every other
    /// output bit is zero - checked for all `2^32` possible inputs, not just the enumerated
    /// single-bit/all-ones cases the external unit tests cover
    /// (`spread32to64_places_each_bit_at_double_position`/`_of_zero_and_all_ones`).
    ///
    /// **This replaces an earlier, different proof that CI found intractable** (`docs/DECISIONS.md`
    /// D-112): the original plan compared `square_wide(&a)` against `poly_mul_wide(&a, &a)` for a
    /// symbolic `a` - i.e. proving two different multiplication constructions agree on the *same*
    /// symbolic operand squared against itself. That is a multiplier-equivalence-checking problem
    /// (SAT reasoning over products of two copies of the same symbolic bits), a fundamentally
    /// harder class than `reduce`'s two proofs above or this one - both of which are pure fixed
    /// shift/AND/OR/XOR over a symbolic input, with no product of two symbolic operands anywhere.
    /// CBMC never finished checking that harness within the CI job's 20-minute budget (confirmed
    /// from the job log, not assumed from the timeout alone: `Checking harness ...
    /// square_wide_matches_poly_mul_wide_self...` was the last line before the runner killed it).
    ///
    /// This proof instead exhaustively covers the one genuinely novel piece of arithmetic
    /// (`spread32to64`'s bit-interleave trick) directly against its own specification, with no
    /// multiplication involved at all. `square_wide`'s limb-placement composition (which half of
    /// which input limb lands at which output limb) is *not* re-proven exhaustively here - it's a
    /// simple, inspectable placement of three `spread32to64` calls (see `square_wide`'s own doc
    /// comment for the exact bit-range argument), verified by the existing limb-boundary unit tests
    /// and the random-element proptest in `dstu4145_gf2m.rs` instead, the same "differential test is
    /// the real proof, Kani only for the tractable subset" split this project already uses for
    /// `invert()`'s own addition chain (never Kani-attempted, for the analogous reason: chaining
    /// several multiplies is exactly the kind of computation this class of proof doesn't handle
    /// cheaply).
    #[kani::proof]
    fn spread32to64_is_exact_bit_doubling() {
        let x: u32 = kani::any();
        let r = spread32to64(x);
        for i in 0..32u32 {
            let bit = u64::from((x >> i) & 1);
            let placed = (r >> (2 * i)) & 1;
            assert_eq!(placed, bit);
            let odd = (r >> (2 * i + 1)) & 1;
            assert_eq!(odd, 0);
        }
    }
}

/// Hardware-`clmul` dispatch correctness/timing checks (`docs/TASKS.md` T-198, landed from the
/// T-196 Tier 1 spike - see `poly_mul_wide_hw`'s own doc comment above `multiply()` for the
/// comb-method-vs-`clmul` security reasoning). Uses `gf2m_wide::clmul_native::{clmul64,
/// feature_available}` only for `feature_available()` and (test-only) the differential oracle
/// `clmul64` provides - the production dispatch itself calls `poly_mul_wide_hw` directly, not
/// through this module.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod clmul_spike {
    use super::{multiply_sw, poly_mul_wide, FieldElement};
    use crate::hazmat::gf2m_wide::clmul_native::{clmul64, feature_available};
    use proptest::prelude::*;

    /// Schoolbook (not Karatsuba - checkable limb-by-limb) combination of 9 pairwise hardware
    /// 64x64->128 carry-less multiplies via the test-only `clmul64` oracle - same limb-placement
    /// identity `poly_mul_wide`'s own shift-and-add computes a different way, and the same
    /// identity the production `poly_mul_wide_hw` computes with its intrinsic calls inlined
    /// instead of routed through `clmul64`. Cross-checked against both below.
    fn schoolbook_clmul_poly_mul_wide(a: &[u64; 3], b: &[u64; 3]) -> [u64; 6] {
        let mut out = [0u64; 6];
        for i in 0..3 {
            for j in 0..3 {
                // Safety: every call site below checks `feature_available()` first.
                let (lo, hi) = unsafe { clmul64(a[i], b[j]) };
                out[i + j] ^= lo;
                out[i + j + 1] ^= hi;
            }
        }
        out
    }

    fn arb_narrow() -> impl Strategy<Value = [u64; 3]> {
        prop::collection::vec(any::<u64>(), 3).prop_map(|v| {
            let mut out = [0u64; 3];
            out.copy_from_slice(&v);
            // Stay below 2^163: constructors mask bit 163+, `poly_mul_wide` itself doesn't and
            // relies on that invariant (see its own doc comment) - matches every real caller.
            out[2] &= (1u64 << 35) - 1;
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
            let sw = poly_mul_wide(&a, &b);
            prop_assert_eq!(hw, sw);
        }

        /// The production `poly_mul_wide_hw` (inlined intrinsics, the function `multiply()`'s
        /// dispatch actually calls) against the same software reference, on the same operand
        /// shape `multiply_matches_explicit_software_path` in the parent `tests` module already
        /// exercises end-to-end - this is the narrower, `poly_mul_wide`-level check.
        #[test]
        fn poly_mul_wide_hw_matches_software_reference(a in arb_narrow(), b in arb_narrow()) {
            if !feature_available() {
                return Ok(());
            }
            // Safety: `feature_available()` just confirmed the CPU supports the target feature
            // `poly_mul_wide_hw` requires.
            let hw = unsafe { super::poly_mul_wide_hw(&a, &b) };
            let sw = poly_mul_wide(&a, &b);
            prop_assert_eq!(hw, sw);
        }
    }

    #[test]
    #[ignore]
    fn isolated_timing_dispatch_vs_explicit_software_multiply() {
        if !feature_available() {
            eprintln!("gf2m163: hardware clmul feature not available on this CPU, skipping");
            return;
        }
        use std::hint::black_box;
        use std::time::Instant;

        const N: u32 = 2_000_000;
        let a = FieldElement([
            0x1111_1111_1111_1111u64,
            0x2222_2222_2222_2222,
            0x3333_3333_3333,
        ]);
        let b = FieldElement([
            0x5555_5555_5555_5555u64,
            0x6666_6666_6666_6666,
            0x7777_7777_7777,
        ]);

        // Explicit software path (bit-serial `poly_mul_wide` + word-wise `reduce`, bypassing
        // `multiply()`'s own dispatch), chained the same way every `gf2m_wide` diagnostic chains,
        // matching `curve163::scalar_multiply`'s real dependency pattern (each iteration's output
        // feeds the next).
        let start = Instant::now();
        let mut acc = a;
        for _ in 0..N {
            acc = black_box(multiply_sw(acc, black_box(b)));
        }
        let sw_elapsed = start.elapsed();
        black_box(acc);

        // Production `multiply()` - on this CPU (feature confirmed available above), this now
        // dispatches to `poly_mul_wide_hw`.
        let start = Instant::now();
        let mut acc = a;
        for _ in 0..N {
            acc = black_box(acc.multiply(black_box(b)));
        }
        let hw_elapsed = start.elapsed();
        black_box(acc);

        let sw_ns = sw_elapsed.as_nanos() as f64 / f64::from(N);
        let hw_ns = hw_elapsed.as_nanos() as f64 / f64::from(N);
        eprintln!(
            "gf2m163: explicit software multiply = {sw_ns:.1} ns/op | multiply() (hw dispatch) = {hw_ns:.1} ns/op | speedup = {:.2}x",
            sw_ns / hw_ns
        );
    }
}
