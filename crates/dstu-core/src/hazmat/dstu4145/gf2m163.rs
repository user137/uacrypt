//! GF(2^163) field arithmetic, reduced modulo the pentanomial `x^163 + x^7 + x^6 + x^3 + 1` - the
//! reduction polynomial of the DSTU 4145-2002 curve dual-sourced in
//! `tests/vectors/dstu4145/gf2m163.json` (`DECISIONS.md` D-14), matching
//! `oracles/bouncycastle-java/.../DSTU4145NamedCurves.java`'s `ECCurve.F2m(163, 3, 6, 7, ...)`
//! constructor (`k1, k2, k3 = 3, 6, 7`).
//!
//! **Branchless by construction** (`DECISIONS.md` D-25): every operation below runs the same
//! sequence of word ops regardless of the operand values. `multiply` selects each shifted operand
//! via an all-ones/all-zeros mask derived from a single bit rather than an `if`, and `reduce`'s
//! word-reduction and final cleanup pass run unconditionally rather than skipping zero words or
//! looping until convergence (both real optimizations in the reference this was adapted from,
//! OpenSSL's `BN_GF2m_mod_arr`, and both would branch on secret-dependent data here). `invert`'s
//! only "branch" is on the fixed, public inversion exponent `2^163 - 2` - identical on every call
//! regardless of the secret operand, so it carries no timing signal about that operand.

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

    #[must_use]
    pub fn multiply(self, other: Self) -> Self {
        reduce(poly_mul_wide(&self.0, &other.0))
    }

    #[must_use]
    pub fn square(self) -> Self {
        self.multiply(self)
    }

    /// `self^-1 = self^(2^163 - 2)`, by Fermat's little theorem for `GF(2^163)*`. Undefined for
    /// `self == ZERO`, same as every reference implementation this was checked against - callers
    /// must never invert zero (the DSTU 4145 sign/verify pseudocode's own retry loops exist
    /// precisely to avoid producing a zero value that would need inverting).
    ///
    /// The exponent `2^163 - 2` is `162` one-bits followed by a single zero bit (`2^163 - 1` is
    /// all ones; subtracting 1 clears the lowest bit). Left-to-right square-and-multiply over
    /// that fixed bit pattern is exactly `162` (square, multiply-by-`self`) steps followed by one
    /// final square - the addition chain Itoh-Tsujii accelerates asymptotically, done here in its
    /// direct form since correctness, not speed, is the goal for this pass (see `DECISIONS.md`
    /// D-25). Every step always executes regardless of `self`'s value.
    #[must_use]
    pub fn invert(self) -> Self {
        let mut result = Self::ONE;
        for _ in 0..162 {
            result = result.square();
            result = result.multiply(self);
        }
        result.square()
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
/// constant-time behavior (`DECISIONS.md` D-25):
/// - the source removes a source word entirely if it happens to be zero; this always processes
///   every word.
/// - the source loops the final cleanup step until the overflow is zero; this always runs it a
///   fixed 2 times, which is provably sufficient (see below) and a harmless no-op past that point,
///   since re-XORing an already-zero overflow changes nothing.
fn reduce(mut c: [u64; 6]) -> FieldElement {
    // Main pass: reduce words 5, 4, 3 (each covering exponents >= 163) down into words 0..=3.
    // Each source word `zz` contributes its middle-term (7, 6, 3) and constant-term (0)
    // reductions, all of which land split across exactly two destination words `j-2`/`j-3` for
    // this specific (m, W) pair - see DECISIONS.md D-25 for the derivation of the shift amounts
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
    // against a subtle off-by-one in that argument, per DECISIONS.md D-25.
    for _ in 0..2 {
        let overflow = c[2] >> 35;
        c[2] = (c[2] << 29) >> 29;
        c[0] ^= overflow ^ (overflow << 3) ^ (overflow << 6) ^ (overflow << 7);
    }

    FieldElement([c[0], c[1], c[2]])
}
