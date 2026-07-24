//! `randombytes` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `TASKS.md` T-72, `DECISIONS.md` D-48) - not a DSTU primitive. Wraps the OS CSPRNG (`getrandom`),
//! same as libsodium's own `randombytes_buf` does.
//!
//! `std`-gated: `hazmat` primitives never generate their own randomness (D-09 - callers supply
//! everything), and `getrandom` fails to compile outright on an unrecognized bare-metal target
//! (`DECISIONS.md` D-04's addendum) unless a custom backend is registered - so this module must
//! never become a `no_std` core dependency. Enabling this crate's `std` feature is what pulls
//! `getrandom` in at all.

use core::fmt;

/// The OS CSPRNG failed to produce randomness (e.g. the platform's entropy source is transiently
/// unavailable). See [`getrandom::Error`] for the possible underlying causes.
#[derive(Debug)]
pub struct RandomError(getrandom::Error);

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OS CSPRNG error: {}", self.0)
    }
}

impl core::error::Error for RandomError {}

/// Fills `buf` with cryptographically secure random bytes from the OS CSPRNG.
///
/// # Errors
///
/// Returns [`RandomError`] if the OS CSPRNG is unavailable or fails.
pub fn randombytes_buf(buf: &mut [u8]) -> Result<(), RandomError> {
    getrandom::fill(buf).map_err(RandomError)
}
