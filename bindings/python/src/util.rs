//! Small helpers shared by every `crypto_*` wrapper module - fixed-length conversion from a
//! caller-supplied Python `bytes` (arbitrary length) to the fixed-size array `dstu_core`'s own
//! API expects, and a one-line `Result<T, E: Display> -> PyResult<T>` bridge onto
//! [`crate::error::DstuError`] so every wrapper function doesn't hand-write the same
//! `.map_err(...)`.

use pyo3::exceptions::PyValueError;
use pyo3::PyResult;

/// Converts a Python `bytes` argument to a fixed-size array, raising `ValueError` (not
/// `DstuError` - this is a caller-input mistake, not a crypto operation failure) if the length is
/// wrong.
pub fn to_array<const N: usize>(bytes: &[u8], name: &str) -> PyResult<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        PyValueError::new_err(format!(
            "{name} must be exactly {N} bytes, got {}",
            bytes.len()
        ))
    })
}

/// Bridges any `dstu_core` error (all of which implement `Display`) onto [`crate::error::DstuError`].
pub trait IntoDstuError<T> {
    fn dstu(self) -> PyResult<T>;
}

impl<T, E: core::fmt::Display> IntoDstuError<T> for Result<T, E> {
    fn dstu(self) -> PyResult<T> {
        self.map_err(|e| crate::error::DstuError::new_err(e.to_string()))
    }
}
