//! `crypto_stream` wrapper - see [`dstu_core::crypto_stream`] (Strumok-256 keystream, internal
//! IV). **No authentication** - `stream_decrypt` never fails on tampered input, it returns
//! different, silently-wrong plaintext instead (inherited from the wrapped construction). Prefer
//! [`crate::secretbox`]/[`crate::secretstream`] unless integrity is handled elsewhere.

use crate::util::IntoDstuError;
use dstu_core::crypto_stream::{decrypt, encrypt, Key};
use pyo3::prelude::*;

/// Generates a fresh 32-byte `crypto_stream` key from the OS CSPRNG.
#[pyfunction]
pub fn stream_keygen() -> PyResult<Vec<u8>> {
    Key::generate().dstu().map(|key| key.as_bytes().to_vec())
}

/// XORs `plaintext` with a fresh keystream under `key`, drawing a random IV internally. Returns
/// `iv || ciphertext`. No authentication - see the module doc.
#[pyfunction]
pub fn stream_encrypt(key: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    let key = Key::from_bytes(crate::util::to_array::<32>(key, "key")?);
    encrypt(&key, plaintext).dstu()
}

/// Reverses [`stream_encrypt`] under `key`. Raises `DstuError` only if `sealed` is too short to
/// contain an IV - a tampered `sealed` decrypts to different, silently-wrong plaintext, not an
/// error (see the module doc).
#[pyfunction]
pub fn stream_decrypt(key: &[u8], sealed: &[u8]) -> PyResult<Vec<u8>> {
    let key = Key::from_bytes(crate::util::to_array::<32>(key, "key")?);
    decrypt(&key, sealed).dstu()
}
