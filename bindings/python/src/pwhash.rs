//! `crypto_pwhash` wrapper - see [`dstu_core::crypto_pwhash`] (Argon2id, the one deliberately
//! non-DSTU component). `strength` is one of the `PWHASH_*` module constants, mirroring
//! [`dstu_core::crypto_pwhash::Strength`]'s three named presets - not a raw cost-parameter knob.

use crate::util::IntoDstuError;
use dstu_core::crypto_pwhash::{derive_key, hash_password, verify_password, Strength};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn strength_from_u8(strength: u8) -> PyResult<Strength> {
    match strength {
        0 => Ok(Strength::Interactive),
        1 => Ok(Strength::Moderate),
        2 => Ok(Strength::Sensitive),
        _ => Err(PyValueError::new_err(
            "strength must be PWHASH_INTERACTIVE (0), PWHASH_MODERATE (1), or PWHASH_SENSITIVE (2)",
        )),
    }
}

/// Hashes `password` into a self-describing PHC string, using a fresh random salt. `strength`
/// selects one of the `PWHASH_*` presets (default `PWHASH_MODERATE`).
#[pyfunction]
#[pyo3(signature = (password, strength=1))]
pub fn pwhash_hash_password(password: &[u8], strength: u8) -> PyResult<String> {
    hash_password(password, strength_from_u8(strength)?).dstu()
}

/// Verifies `password` against a PHC string produced by [`pwhash_hash_password`]. Returns
/// `False` for both a wrong password and a malformed hash string.
#[pyfunction]
pub fn pwhash_verify_password(password: &[u8], hash: &str) -> bool {
    verify_password(password, hash)
}

/// Derives a 32-byte key from `password` and a 16-byte `salt` - libsodium's `crypto_pwhash`
/// (Argon2id v1.3), byte for byte (T-269). Holds the GIL while Argon2 runs, as
/// [`pwhash_hash_password`] does.
#[pyfunction]
#[pyo3(signature = (password, salt, strength=1))]
pub fn pwhash_derive_key(password: &[u8], salt: &[u8], strength: u8) -> PyResult<Vec<u8>> {
    let salt = crate::util::to_array::<{ dstu_core::crypto_pwhash::SALT_BYTES }>(salt, "salt")?;
    let key = derive_key(password, &salt, strength_from_u8(strength)?).dstu()?;
    Ok(key.to_vec())
}
