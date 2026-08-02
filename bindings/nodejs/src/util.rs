//! Small helpers shared by every `crypto_*` wrapper module - fixed-length conversion from a
//! caller-supplied `Buffer` (arbitrary length) to the fixed-size array `dstu_core`'s own API
//! expects, and a one-line `Result<T, E: Display> -> napi::Result<T>` bridge so every wrapper
//! function doesn't hand-write the same `.map_err(...)`. Mirrors `bindings/python/src/util.rs`.

use napi::{Error, Result};

/// Converts a `Buffer`-derived byte slice to a fixed-size array, raising an `Error` (a caller-input
/// mistake, not a crypto operation failure) if the length is wrong.
pub fn to_array<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        Error::from_reason(format!(
            "{name} must be exactly {N} bytes, got {}",
            bytes.len()
        ))
    })
}

/// Bridges any `dstu_core` error (all of which implement `Display`) onto `napi::Error`.
pub trait IntoDstuError<T> {
    fn dstu(self) -> Result<T>;
}

impl<T, E: core::fmt::Display> IntoDstuError<T> for core::result::Result<T, E> {
    fn dstu(self) -> Result<T> {
        self.map_err(|e| Error::from_reason(e.to_string()))
    }
}
