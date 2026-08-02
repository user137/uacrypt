//! `crypto_secretbox` wrapper - see [`dstu_core::crypto_secretbox`] for the underlying
//! construction (Kalyna-256/256-GCM, internal nonce, no caller-facing AAD). Keys and sealed
//! blobs cross the Python boundary as plain `bytes`, matching this project's other bindings'
//! ergonomics rather than an opaque handle type - `dstu_core::crypto_secretbox::SecretKey`'s own
//! `Zeroize`-on-drop guarantee does not carry across the FFI boundary into a Python `bytes`
//! object regardless of wrapper shape, so there is nothing an opaque type would additionally buy
//! here.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_secretbox::{open, seal, SecretKey};
use pyo3::prelude::*;

/// Generates a fresh 32-byte `crypto_secretbox` key from the OS CSPRNG.
#[pyfunction]
pub fn secretbox_keygen() -> PyResult<Vec<u8>> {
    SecretKey::generate()
        .dstu()
        .map(|key| key.as_bytes().to_vec())
}

/// Encrypts and authenticates `plaintext` under `key`. Returns `nonce || ciphertext || tag`.
#[pyfunction]
pub fn secretbox_seal(key: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    let key = SecretKey::from_bytes(to_array::<32>(key, "key")?);
    seal(&key, plaintext).dstu()
}

/// Verifies and decrypts `sealed` (as produced by [`secretbox_seal`]) under `key`. Raises
/// `DstuError` if authentication fails or `sealed` is too short to be valid.
#[pyfunction]
pub fn secretbox_open(key: &[u8], sealed: &[u8]) -> PyResult<Vec<u8>> {
    let key = SecretKey::from_bytes(to_array::<32>(key, "key")?);
    open(&key, sealed).dstu()
}
