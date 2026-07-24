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
