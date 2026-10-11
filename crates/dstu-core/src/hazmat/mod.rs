//! Low-level ("hazardous material") primitives: direct DSTU algorithm implementations with no
//! forced RNG dependency and no safety rails — callers manage keys/nonces/IVs explicitly where
//! an algorithm needs them. Available in `no_std` builds.
//!
//! A higher-level, harder-to-misuse API mirroring libsodium's `crypto_*` "easy" functions is
//! planned on top of this module and will be `std`/`alloc`-gated where it needs OS randomness.
//! See `docs/dstu-crypto-project.md` "Concrete API shape" and `docs/DECISIONS.md` D-09.

pub mod dstu4145;
pub mod dstu9041;
mod gf2m_wide;
pub mod kalyna;
pub mod kalyna_cbc;
pub mod kalyna_ccm;
pub mod kalyna_cfb;
pub mod kalyna_cmac;
pub mod kalyna_ctr;
pub mod kalyna_ecb;
pub mod kalyna_gcm;
pub mod kalyna_gmac;
pub mod kalyna_kw;
pub mod kalyna_ofb;
pub mod kalyna_xts;
pub mod kupyna;
pub mod kupyna_kdf;
pub mod kupyna_kmac;
mod limb;
pub mod strumok;
mod tables;

/// A byte count as a DSTU 7624 GCM/GMAC 64-bit bit-length field, or `None` past `2^61 - 1` bytes
/// (T-283). No real slice gets near that, but the bound is checked here, not assumed.
pub(crate) fn checked_bit_len(bytes: usize) -> Option<u64> {
    u64::try_from(bytes).ok()?.checked_mul(8)
}

#[cfg(test)]
mod tests {
    use super::checked_bit_len;

    #[test]
    fn checked_bit_len_refuses_lengths_whose_bit_count_overflows() {
        assert_eq!(checked_bit_len(0), Some(0));
        assert_eq!(checked_bit_len(17), Some(136));
        let max_ok = u64::MAX / 8;
        if let Ok(n) = usize::try_from(max_ok) {
            assert_eq!(checked_bit_len(n), Some(max_ok * 8));
            if let Some(over) = n.checked_add(1) {
                assert_eq!(checked_bit_len(over), None);
            }
        }
        if usize::BITS >= 64 {
            assert_eq!(checked_bit_len(usize::MAX), None);
        }
    }
}
