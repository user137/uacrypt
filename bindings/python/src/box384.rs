//! `crypto_box384` wrapper - see [`dstu_core::crypto_box384`] (`l(p)=384`/E384/1, T-297),
//! the direct sibling of [`crate::crypto_box`] at this curve size's own widths. Keys/sealed blobs
//! cross the Python boundary as plain `bytes`, matching every other wrapper in this crate.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_box384::{open, seal, PublicKey, SecretKey};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

pub(crate) fn secret_key_from_bytes(bytes: &[u8]) -> PyResult<SecretKey> {
    let e = to_array::<48>(bytes, "secret_key")?;
    SecretKey::from_bytes(&e).ok_or_else(|| {
        PyValueError::new_err("invalid secret key: must be in the range {2, ..., n-2}")
    })
}

pub(crate) fn public_key_from_bytes(bytes: &[u8]) -> PyResult<PublicKey> {
    let x = to_array::<48>(bytes, "public_key")?;
    PublicKey::from_bytes(&x).ok_or_else(|| {
        PyValueError::new_err(
            "invalid public key: not a valid field element, or not in the base point's subgroup",
        )
    })
}

/// Generates a fresh 48-byte `crypto_box384` secret key from the OS CSPRNG.
#[pyfunction]
pub fn box384_keygen() -> PyResult<Vec<u8>> {
    SecretKey::generate()
        .dstu()
        .map(|key| key.to_bytes().to_vec())
}

/// Derives the 48-byte public key for `secret_key` - safe to share/publish (the curve point's
/// `x`-coordinate only, see `dstu_core::crypto_box384`'s own module doc for why this is a safe
/// compression).
#[pyfunction]
pub fn box384_public_key(secret_key: &[u8]) -> PyResult<Vec<u8>> {
    let key = secret_key_from_bytes(secret_key)?;
    Ok(key.public_key().to_bytes().to_vec())
}

/// Encrypts `message` (any length) to the holder of `public_key`, drawing a fresh random seed and
/// ephemeral key internally. Not memory-bounded - the whole message is held in memory, matching
/// `uacrypt box-seal`'s own documented limitation.
#[pyfunction]
pub fn box384_seal(public_key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    let key = public_key_from_bytes(public_key)?;
    seal(message, &key).dstu()
}

/// Decrypts `sealed` (as produced by [`box384_seal`]) under `secret_key`. Raises `DstuError` if
/// authentication fails (wrong key, or any tampered wire segment - deliberately not distinguished
/// further, see `dstu_core::crypto_box384::OpenError`'s own doc comment) or `sealed` is too short
/// to be valid.
#[pyfunction]
pub fn box384_open(secret_key: &[u8], sealed: &[u8]) -> PyResult<Vec<u8>> {
    let key = secret_key_from_bytes(secret_key)?;
    open(sealed, &key).dstu()
}
