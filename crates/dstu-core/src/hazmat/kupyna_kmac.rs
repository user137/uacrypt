//! Kupyna-based KMAC - DSTU 7564:2014's own MAC mode (`crypto_auth`/`crypto_onetimeauth`
//! equivalent, `docs/dstu-crypto-project.md` "Mapping onto the libsodium API").
//!
//! **Provisional, not confirmed against the primary DSTU 7564:2014 text** - the paper this project
//! otherwise treats as its highest-trust Kupyna source (`docs/papers/Kupyna.pdf`) states this MAC
//! mode exists in the standard but does not itself describe it. Ported from two independent
//! reference implementations instead: `oracles/uapki/library/uapkic/src/dstu7564.c`
//! (`dstu7564_init_kmac`/`dstu7564_update_kmac`/`dstu7564_final_kmac`, whose own comment states
//! the construction directly - `HMAC(M,K) = H(PAD(K) || PAD(M) || (~K))`) and
//! `oracles/bouncycastle-java/.../macs/DSTU7564Mac.java` (an independent Java implementation, not
//! a port of the C above). Both implementations' self-test vectors agree byte-for-byte across all
//! three MAC sizes - see `crates/dstu-core/tests/vectors/kupyna-kmac/*.json` and `DECISIONS.md`
//! D-44 for why this is stronger evidence than Strumok's or Kalyna-CCM's equivalent caveats.
//! Full construction cited step-by-step in `docs/pseudocode/kupyna-kmac.md`.

use super::kupyna::{kupyna_padding, KupynaCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmacError {
    /// Both oracles' test data uses `key.len() == mac_len` in every case, and UAPKI's C source
    /// hard-enforces it (`CHECK_PARAM(key_buf_len == mac_len)`) - matched here rather than
    /// building Bouncy Castle's more permissive (but untested-by-any-vector) arbitrary-key-length
    /// path. See `docs/pseudocode/kupyna-kmac.md`.
    WrongKeyLength,
    TagMismatch,
}

/// Shared construction for all three MAC sizes - see `docs/pseudocode/kupyna-kmac.md` for the
/// algorithm and citations.
fn kmac_generic(
    key: &[u8],
    message: &[u8],
    columns: usize,
    rounds: usize,
    last_row_shift: usize,
    output_bytes: usize,
) -> Result<[u8; 64], KmacError> {
    if key.len() != output_bytes {
        return Err(KmacError::WrongKeyLength);
    }

    let mut core = KupynaCore::new(columns, rounds, last_row_shift);
    let block_bytes = core.block_bytes();

    // PAD(K): always exactly one block for all three MAC sizes (key.len() + 13 <= block_bytes
    // holds for 32+13<=64, 48+13<=128, 64+13<=128 - not a coincidence, the same margin the
    // official vectors themselves rely on).
    #[allow(clippy::cast_possible_truncation)] // key.len() is 32/48/64, always << u64::MAX
    let (padded_key, padded_key_len) = kupyna_padding(key, (key.len() as u64) * 8, block_bytes);
    core.update(&padded_key[..padded_key_len]);

    // M, raw - contributes to `core`'s own running `total_len` normally, same as any other
    // streamed message.
    core.update(message);

    // PAD(M)'s padding suffix, using M's *own* byte length (not `key.len() + message.len()`) as
    // the length field - `message.len()`'s tail may already be sitting in `core`'s internal
    // buffer from the `update(message)` call above, so only the *new* suffix bytes (from the
    // already-buffered length onward) are fed in, or `update` would double-count them.
    #[allow(clippy::cast_possible_truncation)] // message.len() here is always << u64::MAX
    let (pad_m, pad_m_len) =
        kupyna_padding(core.buffered(), (message.len() as u64) * 8, block_bytes);
    let already_buffered = core.buffered().len();
    core.update(&pad_m[already_buffered..pad_m_len]);

    // ~K, raw - the outermost `finalize` below applies the *true* total-length padding over
    // everything fed to `core` so far (PAD(K)'s one block + M + PAD(M)'s suffix + ~K), exactly
    // matching both oracles' final `doFinal`/`dstu7564_final_kmac` step.
    let mut inverted_key = [0u8; 64];
    for (dst, &src) in inverted_key[..key.len()].iter_mut().zip(key) {
        *dst = !src;
    }
    core.update(&inverted_key[..key.len()]);
    inverted_key.zeroize();

    Ok(core.finalize(output_bytes))
}

macro_rules! kmac_variant {
    ($name:ident, $columns:literal, $rounds:literal, $last_row_shift:literal, $mac_len:literal) => {
        pub struct $name;

        impl $name {
            /// Computes the MAC of `message` under `key` (`key` must be exactly `$mac_len` bytes).
            ///
            /// # Errors
            ///
            /// Returns `Err(KmacError::WrongKeyLength)` if `key.len() != $mac_len`.
            pub fn mac(key: &[u8], message: &[u8]) -> Result<[u8; $mac_len], KmacError> {
                let full =
                    kmac_generic(key, message, $columns, $rounds, $last_row_shift, $mac_len)?;
                let mut out = [0u8; $mac_len];
                out.copy_from_slice(&full[..$mac_len]);
                Ok(out)
            }

            /// Recomputes the MAC and compares it against `expected` in constant time
            /// (`subtle::ConstantTimeEq`, per `SECURITY.md`'s hard constraint on secret
            /// comparisons - a MAC verification is exactly this category).
            ///
            /// # Errors
            ///
            /// Returns `Err(KmacError::WrongKeyLength)` if `key.len() != $mac_len`, or
            /// `Err(KmacError::TagMismatch)` if the recomputed MAC doesn't match `expected`.
            pub fn verify(
                key: &[u8],
                message: &[u8],
                expected: &[u8; $mac_len],
            ) -> Result<(), KmacError> {
                let mac = Self::mac(key, message)?;
                if mac.ct_eq(expected).into() {
                    Ok(())
                } else {
                    Err(KmacError::TagMismatch)
                }
            }
        }
    };
}

kmac_variant!(Kupyna256Kmac, 8, 10, 7, 32);
kmac_variant!(Kupyna384Kmac, 16, 14, 11, 48);
kmac_variant!(Kupyna512Kmac, 16, 14, 11, 64);
