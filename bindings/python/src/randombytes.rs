//! `randombytes` wrapper - see [`dstu_core::randombytes`] (OS CSPRNG via `getrandom`).

use crate::util::IntoDstuError;
use pyo3::prelude::*;

/// Returns `size` cryptographically secure random bytes from the OS CSPRNG.
#[pyfunction]
pub fn randombytes_buf(size: usize) -> PyResult<Vec<u8>> {
    let mut buf = vec![0u8; size];
    dstu_core::randombytes::randombytes_buf(&mut buf).dstu()?;
    Ok(buf)
}
