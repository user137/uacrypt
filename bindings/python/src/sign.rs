//! `crypto_sign` wrapper - see [`dstu_core::crypto_sign`] (DSTU 4145, deterministic nonce, no RNG
//! dependency for signing itself - only [`sign_keygen`] touches the OS CSPRNG). Keys are the
//! module's own fixed-length byte encodings: a 21-byte signing key, a 42-byte uncompressed
//! verifying key (`x || y`, not the DSTU standard's own compressed point encoding - see
//! `dstu_core::crypto_sign`'s module doc), a 42-byte signature (`r || s`).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_sign::{Signature, SigningKey, VerifyingKey};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn signing_key_from_bytes(bytes: &[u8]) -> PyResult<SigningKey> {
    let d = to_array::<21>(bytes, "signing_key")?;
    SigningKey::from_bytes(&d).ok_or_else(|| {
        PyValueError::new_err("invalid signing key: must be nonzero and less than the curve order")
    })
}

/// Generates a fresh 21-byte signing key from the OS CSPRNG, uniform over the valid key range via
/// rejection sampling.
#[pyfunction]
pub fn sign_keygen() -> PyResult<Vec<u8>> {
    SigningKey::generate()
        .dstu()
        .map(|key| key.to_bytes().to_vec())
}

/// Derives the 42-byte public verifying key for `signing_key` - safe to share/publish.
#[pyfunction]
pub fn sign_verifying_key(signing_key: &[u8]) -> PyResult<Vec<u8>> {
    let key = signing_key_from_bytes(signing_key)?;
    Ok(key.verifying_key().to_uncompressed_bytes().to_vec())
}

/// Signs `message` under `signing_key`, hashing it with Kupyna-256 and deriving the ephemeral
/// nonce deterministically. Returns a 42-byte signature.
#[pyfunction]
pub fn sign_message(signing_key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    let key = signing_key_from_bytes(signing_key)?;
    Ok(key.sign(message).to_bytes().to_vec())
}

/// Verifies `signature` against `message` under the 42-byte `verifying_key`. Returns `True`/
/// `False` rather than raising - matches the wrapped `dstu_core::crypto_sign` API.
#[pyfunction]
pub fn sign_verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let verifying_key_bytes = to_array::<42>(verifying_key, "verifying_key")?;
    let key = VerifyingKey::from_uncompressed_bytes(&verifying_key_bytes);
    let sig_bytes = to_array::<42>(signature, "signature")?;
    Ok(key.verify(message, &Signature::from_bytes(&sig_bytes)))
}
