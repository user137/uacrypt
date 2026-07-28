//! `randombytes` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `docs/TASKS.md` T-72, `docs/DECISIONS.md` D-48) - not a DSTU primitive. Wraps the OS CSPRNG (`getrandom`),
//! same as libsodium's own `randombytes_buf` does.
//!
//! `hazmat` primitives never generate their own randomness (D-09 - callers supply everything).
//! `getrandom` fails to compile outright on an unrecognized bare-metal target (`docs/DECISIONS.md`
//! D-04's addendum) unless a backend is selected - so pulling it in is opt-in, never bundled into
//! a bare `no_std` build with no way to say no. Two ways to opt in: the `std` feature (assumes a
//! real OS, `getrandom` picks its OS backend automatically), or the narrower `getrandom` feature
//! (`docs/TASKS.md` T-123, `docs/DECISIONS.md` D-74) for `no_std` targets - an embedded caller who has
//! configured one of `getrandom`'s own non-OS backends (most commonly `custom`, via
//! `--cfg getrandom_backend="custom"` plus their own `extern "Rust" fn __getrandom_v03_custom`;
//! see <https://docs.rs/getrandom/latest/getrandom/#custom-backend>) can enable this feature alone
//! and use `randombytes_buf` without pulling in `std`/`alloc` at all. This crate does not implement
//! its own pluggable-backend registry - `getrandom` 0.3 already *is* the mechanism libsodium's
//! `randombytes_set_implementation()` plays the same role for (capability parity, not mechanism
//! parity: `getrandom`'s selection is a compile-time/link-time choice the final binary makes, not
//! a runtime-swappable function pointer) - building a second one here would duplicate an
//! already-established primitive `docs/DECISIONS.md` D-03/D-04 already rejected doing for the RNG itself.

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
