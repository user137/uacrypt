//! `crypto_kdf` wrapper - see [`dstu_core::crypto_kdf`] (Kupyna-256-KDF).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_kdf::MasterKey;
use pyo3::prelude::*;

/// Generates a fresh 32-byte `crypto_kdf` master key from the OS CSPRNG.
#[pyfunction]
pub fn kdf_keygen() -> PyResult<Vec<u8>> {
    MasterKey::generate()
        .dstu()
        .map(|key| key.as_bytes().to_vec())
}

/// Derives a 32-byte subkey from `master_key`. `context` must be exactly 8 bytes. Different
/// `subkey_id`/`context` values (holding the others fixed) produce different, unrelated-looking
/// subkeys; the same inputs always re-derive the same subkey.
#[pyfunction]
pub fn kdf_derive_subkey(master_key: &[u8], subkey_id: u64, context: &[u8]) -> PyResult<Vec<u8>> {
    let master_key = MasterKey::from_bytes(to_array::<32>(master_key, "master_key")?);
    let context = to_array::<8>(context, "context")?;
    Ok(master_key.derive_subkey(subkey_id, &context).to_vec())
}
