//! `crypto_pwhash` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `docs/TASKS.md` T-71, `docs/DECISIONS.md` D-03/D-49/D-50) - plain Argon2id, the one deliberately non-DSTU
//! component (no Ukrainian standard covers password hashing). Wraps the `argon2` crate
//! (`RustCrypto/password-hashes`, vetted in D-49) with libsodium's own `crypto_pwhash_str`/
//! `crypto_pwhash_str_verify` shape: a self-describing PHC string that embeds algorithm, version,
//! salt, and parameters, so `verify_password` needs nothing but the password and that string back.
//!
//! Every parameter choice here is cited to libsodium's own `crypto_pwhash_argon2id` C source
//! (`docs/DECISIONS.md` D-50), not invented: only Argon2id (no algorithm knob), a fixed 1-lane
//! parallelism (`pwhash_argon2id.c`'s own `argon2id_hash_encoded(..., (uint32_t) 1U, ...)` call,
//! not a knob either), a 16-byte salt (`crypto_pwhash_argon2id_SALTBYTES`), a 32-byte hash
//! (`STR_HASHBYTES`), and three named strength presets mirroring
//! `OPSLIMIT`/`MEMLIMIT_{INTERACTIVE,MODERATE,SENSITIVE}` exactly - no raw `m_cost`/`t_cost` knob
//! exposed, per D-47's "libsodium API shape, no misconfigurable knobs" criterion. `verify_password`
//! reads its parameters from an untrusted string, so it accepts only a bounded set (argon2id or
//! libsodium's argon2i, `v=19`, costs up to [`Strength::Sensitive`] - `docs/DECISIONS.md` D-222).
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
use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
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

    /// This preset's `(m_cost in KiB, t_cost, p_cost)`, for a file format that records them
    /// (`uacrypt`'s passphrase container, `docs/DECISIONS.md` D-219).
    #[must_use]
    pub const fn cost(self) -> (u32, u32, u32) {
        let (m_cost, t_cost) = self.m_and_t_cost();
        (m_cost, t_cost, 1)
    }

    /// The preset whose [`cost`](Self::cost) is exactly `(m_cost, t_cost, p_cost)`, or `None`. A
    /// reader of untrusted parameters uses this to accept only the known presets instead of
    /// running Argon2 with attacker-chosen memory.
    #[must_use]
    pub fn from_cost(m_cost: u32, t_cost: u32, p_cost: u32) -> Option<Self> {
        [
            Strength::Interactive,
            Strength::Moderate,
            Strength::Sensitive,
        ]
        .into_iter()
        .find(|s| s.cost() == (m_cost, t_cost, p_cost))
    }
}

/// Salt length for [`derive_key`] - `crypto_pwhash_argon2id_SALTBYTES`.
pub const SALT_BYTES: usize = 16;

/// Output length of [`derive_key`] - one `crypto_secretstream`/`crypto_secretbox` key.
pub const KEY_BYTES: usize = 32;

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
    /// [`derive_key`] could not allocate the preset's Argon2 memory (256 MiB for
    /// [`Strength::Moderate`]) - reported instead of aborting the process.
    OutOfMemory,
    /// [`derive_key`]'s raw Argon2 call failed. Not expected for the fixed presets, salt and
    /// output length used here.
    Derive(argon2::Error),
}

impl fmt::Display for PwHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PwHashError::Random(e) => write!(f, "{e}"),
            PwHashError::Hash(e) => write!(f, "Argon2 hashing failed: {e}"),
            PwHashError::OutOfMemory => write!(f, "not enough memory for Argon2"),
            PwHashError::Derive(e) => write!(f, "Argon2 key derivation failed: {e}"),
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
/// (`docs/DECISIONS.md` D-48/D-50).
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

/// Largest `m_cost` (KiB) [`verify_password`] accepts: the [`Strength::Sensitive`] preset.
const VERIFY_MAX_M_COST: u32 = 1_048_576;

/// Largest `m_cost * t_cost` [`verify_password`] accepts: the work of [`Strength::Sensitive`]
/// (1 GiB x 4), which libsodium's argon2i `SENSITIVE` preset (512 MiB x 8) also lands on exactly.
const VERIFY_MAX_WORK: u64 = 4 * 1_048_576;

/// Shortest tag [`verify_password`] accepts - libsodium's `ARGON2_MIN_OUTLEN`.
const VERIFY_MIN_TAG_LEN: usize = 16;

/// Checks everything [`verify_password`] takes from an untrusted PHC string before any memory is
/// allocated (`docs/DECISIONS.md` D-222) and returns the Argon2 context to run.
fn verify_context(
    algorithm: &str,
    version: Option<u32>,
    (m_cost, t_cost, p_cost): (u32, u32, u32),
    tag_len: usize,
    salt_len: usize,
) -> Option<Argon2<'static>> {
    let algorithm = match algorithm {
        "argon2id" => Algorithm::Argon2id,
        "argon2i" => Algorithm::Argon2i,
        _ => return None,
    };
    if version != Some(0x13)
        || m_cost > VERIFY_MAX_M_COST
        || u64::from(m_cost) * u64::from(t_cost) > VERIFY_MAX_WORK
        || !(VERIFY_MIN_TAG_LEN..=argon2::password_hash::Output::MAX_LENGTH).contains(&tag_len)
        || salt_len < argon2::MIN_SALT_LEN
        // `Params::new` computes `p_cost * 8` before its own `MAX_P_COST` check: an overflow panic
        // with overflow checks on (T-272's fuzz target found it), so reject that range first.
        || p_cost > Params::MAX_P_COST
    {
        return None;
    }
    let params = Params::new(m_cost, t_cost, p_cost, Some(tag_len)).ok()?;
    Some(Argon2::new(algorithm, Version::V0x13, params))
}

/// The `m`, `t` and `p` of a PHC string, each exactly once and nothing else.
fn phc_costs(parsed: &PasswordHash<'_>) -> Option<(u32, u32, u32)> {
    let (mut m, mut t, mut p) = (None, None, None);
    for (ident, value) in parsed.params.iter() {
        let slot = match ident.as_str() {
            "m" => &mut m,
            "t" => &mut t,
            "p" => &mut p,
            _ => return None,
        };
        if slot.replace(value.decimal().ok()?).is_some() {
            return None;
        }
    }
    Some((m?, t?, p?))
}

/// Verifies `password` against a PHC string produced by [`hash_password`] - libsodium's
/// `crypto_pwhash_str_verify` equivalent. Returns `false` for both a wrong password and a
/// malformed/unparseable hash string, mirroring libsodium's own single pass/fail return (nothing
/// for a caller to mishandle by branching differently on the two failure cases).
///
/// The string is untrusted, so only what libsodium itself verifies is accepted, within this
/// module's own costs (`docs/DECISIONS.md` D-222): `argon2id` or `argon2i`, `v=19`, exactly the
/// `m`/`t`/`p` parameters, `m` at most the [`Strength::Sensitive`] preset's 1 GiB, `m * t` at most
/// that preset's work, a salt of at least 8 bytes and a tag of 16 to 64 bytes. Anything else is
/// `false` before any memory is allocated, and a machine that cannot allocate an accepted `m` gets
/// `false` rather than an aborted process.
#[must_use]
pub fn verify_password(password: &[u8], hash: &str) -> bool {
    use subtle::ConstantTimeEq;
    use zeroize::Zeroize;

    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    let (Some(salt), Some(expected)) = (parsed.salt, parsed.hash) else {
        return false;
    };
    let Some(costs) = phc_costs(&parsed) else {
        return false;
    };
    let mut salt_buf = [0u8; argon2::password_hash::Salt::MAX_LENGTH];
    let Ok(salt) = salt.decode_b64(&mut salt_buf) else {
        return false;
    };
    let Some(argon2) = verify_context(
        parsed.algorithm.as_str(),
        parsed.version,
        costs,
        expected.len(),
        salt.len(),
    ) else {
        return false;
    };

    let block_count = argon2.params().block_count();
    let mut blocks = Vec::new();
    if blocks.try_reserve_exact(block_count).is_err() {
        return false;
    }
    blocks.resize(block_count, argon2::Block::default());

    let mut tag_buf = zeroize::Zeroizing::new([0u8; argon2::password_hash::Output::MAX_LENGTH]);
    let tag = &mut tag_buf[..expected.len()];
    let result = argon2.hash_password_into_with_memory(password, salt, tag, &mut blocks);
    blocks.iter_mut().for_each(Zeroize::zeroize);
    result.is_ok() && bool::from(tag.ct_eq(expected.as_bytes()))
}

/// Derives a 32-byte key from `password` and `salt` - libsodium's `crypto_pwhash` equivalent
/// (Argon2id v1.3, one lane, no secret, no associated data), byte-identical to libsodium for the
/// same preset (`tests/vectors/pwhash/derive_key.json`, `docs/DECISIONS.md` D-219). The caller
/// stores the salt (and the preset's [`Strength::cost`]) next to the ciphertext; a fresh random
/// salt per encryption is the caller's job.
///
/// The Argon2 memory is reserved with `try_reserve_exact`, so a machine without the preset's
/// memory gets [`PwHashError::OutOfMemory`] rather than an aborted process, and it is zeroized
/// before being freed.
///
/// ```rust
/// use dstu_core::crypto_pwhash::{derive_key, Strength, SALT_BYTES};
///
/// let salt = [7u8; SALT_BYTES]; // store this next to the ciphertext; random in real use
/// let key = derive_key(b"correct horse battery staple", &salt, Strength::Interactive)?;
/// assert_eq!(key.len(), 32);
/// # Ok::<(), dstu_core::crypto_pwhash::PwHashError>(())
/// ```
///
/// # Errors
///
/// [`PwHashError::OutOfMemory`] if the preset's memory cannot be allocated;
/// [`PwHashError::Derive`] is not expected for the fixed parameters used here.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_BYTES],
    strength: Strength,
) -> Result<zeroize::Zeroizing<[u8; KEY_BYTES]>, PwHashError> {
    use zeroize::Zeroize;

    let params = strength.params();
    let block_count = params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(block_count)
        .map_err(|_| PwHashError::OutOfMemory)?;
    blocks.resize(block_count, argon2::Block::default());

    let mut key = zeroize::Zeroizing::new([0u8; KEY_BYTES]);
    let result =
        argon2.hash_password_into_with_memory(password, salt, key.as_mut_slice(), &mut blocks);
    blocks.iter_mut().for_each(Zeroize::zeroize);
    result.map_err(PwHashError::Derive)?;
    Ok(key)
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

    /// The bounds of `verify_context` at each edge, without running Argon2: a real hash at the
    /// memory/work bound would cost 1 GiB and seconds, so the vector file cannot reach them
    /// (`docs/DECISIONS.md` D-222).
    #[test]
    fn verify_context_accepts_exactly_up_to_each_bound() {
        let ok = |alg, ver, costs, tag, salt| verify_context(alg, ver, costs, tag, salt).is_some();
        let v19 = Some(0x13);

        assert!(ok("argon2id", v19, Strength::Sensitive.cost(), 32, 16));
        assert!(
            ok("argon2i", v19, (524_288, 8, 1), 32, 16),
            "libsodium argon2i SENSITIVE"
        );
        assert!(!ok("argon2id", v19, (1_048_577, 1, 1), 32, 16));
        assert!(!ok("argon2id", v19, (1_048_576, 5, 1), 32, 16));
        assert!(ok("argon2id", v19, (65_536, 64, 1), 32, 16));
        assert!(!ok("argon2id", v19, (65_536, 65, 1), 32, 16));
        assert!(
            !ok("argon2id", v19, (1_048_576, u32::MAX, 1), 32, 16),
            "u64 product"
        );
        assert!(!ok("argon2id", v19, (8, u32::MAX, 1), 32, 16));

        assert!(!ok("argon2id", v19, (8, 1, 1), 15, 16));
        assert!(ok("argon2id", v19, (8, 1, 1), 16, 16));
        assert!(ok("argon2id", v19, (8, 1, 1), 64, 16));
        assert!(!ok("argon2id", v19, (8, 1, 1), 65, 16));
        assert!(!ok("argon2id", v19, (8, 1, 1), 32, 7));
        assert!(ok("argon2id", v19, (8, 1, 1), 32, 8));

        assert!(
            ok("argon2id", v19, (1_048_576, 1, 64), 32, 16),
            "no cap on lanes"
        );
        assert!(!ok("argon2id", v19, (8, 1, 2), 32, 16), "RFC 9106: m >= 8p");
        assert!(!ok("argon2id", v19, (8, 0, 1), 32, 16));
        assert!(!ok("argon2id", v19, (8, 1, 0), 32, 16));
        assert!(
            !ok("argon2id", v19, (8, 1, u32::MAX), 32, 16),
            "argon2's own 8p overflows"
        );
        assert!(!ok("argon2d", v19, (8, 1, 1), 32, 16));
        assert!(!ok("argon2id", Some(0x10), (8, 1, 1), 32, 16));
        assert!(!ok("argon2id", None, (8, 1, 1), 32, 16));
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
