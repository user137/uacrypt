//! `crypto_sign257` wrapper - see [`dstu_core::crypto_sign257`] (DSTU 4145 `m=257`, T-199/T-204),
//! the `m=257` sibling of [`crate::sign`]. Keys are the module's own fixed-length byte encodings: a
//! 33-byte signing key, a 66-byte uncompressed verifying key (`x || y`), a 66-byte signature
//! (`r || s`). No curve-tag byte here - distinct function names (`sign257_*`) are the whole
//! dispatch mechanism, matching every other binding's own D-118-driven "no tag sniffing" rule.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_sign257::{Signature, SigningKey, VerifyingKey};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn signing_key_from_bytes(bytes: &[u8]) -> PyResult<SigningKey> {
    let d = to_array::<33>(bytes, "signing_key")?;
    SigningKey::from_bytes(&d).ok_or_else(|| {
        PyValueError::new_err("invalid signing key: must be nonzero and less than the curve order")
    })
}

/// Generates a fresh 33-byte signing key from the OS CSPRNG, uniform over the valid key range via
/// rejection sampling.
#[pyfunction]
pub fn sign257_keygen() -> PyResult<Vec<u8>> {
    SigningKey::generate()
        .dstu()
        .map(|key| key.to_bytes().to_vec())
}

/// Derives the 66-byte public verifying key for `signing_key` - safe to share/publish.
#[pyfunction]
pub fn sign257_verifying_key(signing_key: &[u8]) -> PyResult<Vec<u8>> {
    let key = signing_key_from_bytes(signing_key)?;
    Ok(key.verifying_key().to_uncompressed_bytes().to_vec())
}

/// Signs `message` under `signing_key`, hashing it with Kupyna-256 and deriving the ephemeral
/// nonce deterministically. Returns a 66-byte signature.
#[pyfunction]
pub fn sign257_message(signing_key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    let key = signing_key_from_bytes(signing_key)?;
    Ok(key.sign(message).to_bytes().to_vec())
}

/// Verifies `signature` against `message` under the 66-byte `verifying_key`. Returns `True`/
/// `False` rather than raising - matches the wrapped `dstu_core::crypto_sign257` API.
#[pyfunction]
pub fn sign257_verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let verifying_key_bytes = to_array::<66>(verifying_key, "verifying_key")?;
    let key = VerifyingKey::from_uncompressed_bytes(&verifying_key_bytes);
    let sig_bytes = to_array::<66>(signature, "signature")?;
    Ok(key.verify(message, &Signature::from_bytes(&sig_bytes)))
}
