//! `crypto_auth` wrapper - see [`dstu_core::crypto_auth`] (Kupyna-256-KMAC).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_auth::{auth as core_auth, verify, Key};
use pyo3::prelude::*;

/// Generates a fresh 32-byte `crypto_auth` key from the OS CSPRNG.
#[pyfunction]
pub fn auth_keygen() -> PyResult<Vec<u8>> {
    Key::generate().dstu().map(|key| key.as_bytes().to_vec())
}

/// Computes the 32-byte MAC of `message` under `key`.
#[pyfunction]
pub fn auth(key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    let key = Key::from_bytes(to_array::<32>(key, "key")?);
    Ok(core_auth(&key, message).to_vec())
}

/// Verifies `tag` against `message` under `key`. Raises `DstuError` if the tag does not match.
#[pyfunction]
pub fn auth_verify(key: &[u8], message: &[u8], tag: &[u8]) -> PyResult<()> {
    let key = Key::from_bytes(to_array::<32>(key, "key")?);
    let tag = to_array::<32>(tag, "tag")?;
    verify(&key, message, &tag).dstu()
}
