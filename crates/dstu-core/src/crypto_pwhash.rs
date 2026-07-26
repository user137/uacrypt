//! `crypto_pwhash` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `TASKS.md` T-71, `DECISIONS.md` D-03/D-49/D-50) - plain Argon2id, the one deliberately non-DSTU
//! component (no Ukrainian standard covers password hashing). Wraps the `argon2` crate
//! (`RustCrypto/password-hashes`, vetted in D-49) with libsodium's own `crypto_pwhash_str`/
//! `crypto_pwhash_str_verify` shape: a self-describing PHC string that embeds algorithm, version,
//! salt, and parameters, so `verify_password` needs nothing but the password and that string back.
//!
//! Every parameter choice here is cited to libsodium's own `crypto_pwhash_argon2id` C source
//! (`DECISIONS.md` D-50), not invented: only Argon2id (no algorithm knob), a fixed 1-lane
//! parallelism (`pwhash_argon2id.c`'s own `argon2id_hash_encoded(..., (uint32_t) 1U, ...)` call,
//! not a knob either), a 16-byte salt (`crypto_pwhash_argon2id_SALTBYTES`), a 32-byte hash
//! (`STR_HASHBYTES`), and three named strength presets mirroring
//! `OPSLIMIT`/`MEMLIMIT_{INTERACTIVE,MODERATE,SENSITIVE}` exactly - no raw `m_cost`/`t_cost` knob
//! exposed, per D-47's "libsodium API shape, no misconfigurable knobs" criterion.
//!
//! # Example
//!
//! For hashing passwords before storing them (never a general-purpose hash - deliberately slow and
//! memory-hard so guessing many candidate passwords against a stolen hash is expensive).
//! [`Strength::Interactive`] is used below so this example runs quickly; a real login system would
//! usually want [`Strength::Moderate`] or [`Strength::Sensitive`] instead (both take real seconds
//! and hundreds of MiB, deliberately, so not run here).
//!
//! ```rust
//! use dstu_core::crypto_pwhash::{hash_password, verify_password, Strength};
//!
//! let stored_hash = hash_password(b"correct horse battery staple", Strength::Interactive)
//!     .expect("OS CSPRNG should not fail");
//!
//! assert!(verify_password(b"correct horse battery staple", &stored_hash));
//! assert!(!verify_password(b"wrong guess", &stored_hash));
//! ```

use crate::randombytes::{randombytes_buf, RandomError};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use core::fmt;

/// Argon2id cost preset - mirrors libsodium's `crypto_pwhash_argon2id` `OPSLIMIT`/`MEMLIMIT`
/// named constants (`crypto_pwhash_argon2id.h`) exactly, not an independently chosen value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE` (t=2, 64 MiB) - online, latency-sensitive.
    Interactive,
    /// `OPSLIMIT_MODERATE` / `MEMLIMIT_MODERATE` (t=3, 256 MiB).
    Moderate,
    /// `OPSLIMIT_SENSITIVE` / `MEMLIMIT_SENSITIVE` (t=4, 1024 MiB) - highly sensitive, offline-ok.
    Sensitive,
}

impl Strength {
    /// `(m_cost in KiB, t_cost)` - libsodium's own `OPSLIMIT`/`MEMLIMIT_*` constants
    /// (`crypto_pwhash_argon2id.h`), `MEMLIMIT` converted from bytes to KiB. `p_cost` is fixed at
    /// 1 lane below, not part of this preset - libsodium hardcodes it the same way.
    const fn m_and_t_cost(self) -> (u32, u32) {
        match self {
            Strength::Interactive => (65536, 2),   // 64 MiB
            Strength::Moderate => (262_144, 3),    // 256 MiB
            Strength::Sensitive => (1_048_576, 4), // 1024 MiB
        }
    }

    /// Builds the actual `argon2::Params` for this preset. A `const fn`: an invalid preset would
    /// be a compile-time error, not a runtime one - these three presets are the only values this
    /// type can hold, so validity is closed over at compile time rather than checked per call.
    const fn params(self) -> Params {
        let (m_cost, t_cost) = self.m_and_t_cost();
        match Params::new(m_cost, t_cost, 1, None) {
            Ok(p) => p,
            Err(_) => panic!("Strength's own hardcoded (m_cost, t_cost, 1) is always valid"),
        }
    }
}

/// `crypto_pwhash_str`/`_str_verify` can fail for reasons unrelated to a wrong password: this
/// covers those.
#[derive(Debug)]
pub enum PwHashError {
    /// The OS CSPRNG failed while generating a salt (see [`crate::randombytes`]).
    Random(RandomError),
    /// Argon2/PHC-string encoding failed. Not expected to occur in practice for the fixed-length
    /// salt this module always generates - included because the underlying crate's API is
    /// fallible, not because a known failure mode exists here.
    Hash(argon2::password_hash::Error),
}

impl fmt::Display for PwHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PwHashError::Random(e) => write!(f, "{e}"),
            PwHashError::Hash(e) => write!(f, "Argon2 hashing failed: {e}"),
        }
    }
}

impl core::error::Error for PwHashError {}

impl From<RandomError> for PwHashError {
    fn from(e: RandomError) -> Self {
        PwHashError::Random(e)
    }
}

impl From<argon2::password_hash::Error> for PwHashError {
    fn from(e: argon2::password_hash::Error) -> Self {
        PwHashError::Hash(e)
    }
}

/// Hashes `password` into a self-describing PHC string (`$argon2id$v=19$m=...,t=...,p=1$<salt>$
/// <hash>`) - libsodium's `crypto_pwhash_str` equivalent. A fresh 16-byte salt
/// (`crypto_pwhash_argon2id_SALTBYTES`) is drawn per call via
/// [`crate::randombytes::randombytes_buf`], never `password_hash`'s own `rand_core`-based
/// `SaltString::generate`, so this module pulls in no `CryptoRng` dependency of its own
/// (`DECISIONS.md` D-48/D-50).
///
/// # Errors
///
/// Returns [`PwHashError::Random`] if the OS CSPRNG fails. [`PwHashError::Hash`] is not expected
/// for the fixed 16-byte salt generated here.
pub fn hash_password(password: &[u8], strength: Strength) -> Result<String, PwHashError> {
    let mut salt_bytes = [0u8; 16];
    randombytes_buf(&mut salt_bytes)?;
    let salt = SaltString::encode_b64(&salt_bytes)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, strength.params());
    let hash = argon2.hash_password(password, &salt)?;
    Ok(hash.to_string())
}

/// Verifies `password` against a PHC string produced by [`hash_password`] - libsodium's
/// `crypto_pwhash_str_verify` equivalent. Returns `false` for both a wrong password and a
/// malformed/unparseable hash string, mirroring libsodium's own single pass/fail return (nothing
/// for a caller to mishandle by branching differently on the two failure cases).
#[must_use]
pub fn verify_password(password: &[u8], hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default().verify_password(password, &parsed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::AssociatedData;

    /// Confirms the `argon2` dependency itself is spec-correct before trusting it through this
    /// module's wrapper - RFC 9106 (IETF, primary source) Appendix A's Argon2id test vector,
    /// cited verbatim. Deliberately bypasses `hash_password`/PHC-string encoding: the vector's own
    /// `p=4` doesn't match this module's fixed `p=1` (libsodium's own choice, see the module doc),
    /// so a raw `Argon2` context is built directly against the vector's exact parameters instead.
    #[test]
    fn argon2_dependency_matches_rfc9106_argon2id_vector() -> Result<(), argon2::Error> {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let associated_data = AssociatedData::new(&[0x04u8; 12])?;

        let mut builder = argon2::ParamsBuilder::new();
        builder
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(associated_data)
            .output_len(32);
        let params = builder.build()?;

        let argon2 = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)?;
        let mut out = [0u8; 32];
        argon2.hash_password_into(&password, &salt, &mut out)?;

        assert_eq!(
            out,
            [
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
                0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
                0x6b, 0x01, 0xe6, 0x59,
            ]
        );
        Ok(())
    }

    /// `Sensitive`'s own `(m_cost, t_cost, p_cost)` checked directly against a real `Params`,
    /// instead of through a real `hash_password` call - a real 1024 MiB/t=4 hash took ~85s in an
    /// unoptimized debug build (too expensive for every CI push), and `Interactive`/`Moderate`
    /// already prove (`tests/crypto_pwhash.rs`) that `Strength` flows into the PHC string through
    /// this exact code path - only the constants differ for `Sensitive`, checked here for free.
    #[test]
    fn sensitive_preset_has_libsodiums_sensitive_params() {
        let params = Strength::Sensitive.params();
        assert_eq!(params.m_cost(), 1_048_576);
        assert_eq!(params.t_cost(), 4);
        assert_eq!(params.p_cost(), 1);
    }
}
