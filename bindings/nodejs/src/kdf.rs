//! `crypto_kdf` wrapper - see `dstu_core::crypto_kdf` (Kupyna-256-KDF).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_kdf::MasterKey;
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

/// Generates a fresh 32-byte `crypto_kdf` master key from the OS CSPRNG.
#[napi(js_name = "kdfKeygen")]
pub fn kdf_keygen() -> Result<Buffer> {
    MasterKey::generate()
        .dstu()
        .map(|key| Buffer::from(key.as_bytes().to_vec()))
}

/// Derives a 32-byte subkey from `master_key`. `context` must be exactly 8 bytes. Different
/// `subkey_id`/`context` values (holding the others fixed) produce different, unrelated-looking
/// subkeys; the same inputs always re-derive the same subkey.
///
/// `subkey_id` is accepted as a plain (non-negative) JS `number`, not `BigInt` - napi-rs has no
/// `FromNapiValue` for `u64` (only the reverse direction), and every realistic subkey index fits
/// well within `Number.MAX_SAFE_INTEGER`. A negative value is rejected explicitly rather than
/// silently wrapping around when cast to the underlying `u64`.
#[napi(js_name = "kdfDeriveSubkey")]
pub fn kdf_derive_subkey(master_key: Buffer, subkey_id: i64, context: Buffer) -> Result<Buffer> {
    if subkey_id < 0 {
        return Err(Error::from_reason("subkey_id must be non-negative"));
    }
    let master_key = MasterKey::from_bytes(to_array::<32>(&master_key, "master_key")?);
    let context = to_array::<8>(&context, "context")?;
    Ok(Buffer::from(
        master_key
            .derive_subkey(subkey_id as u64, &context)
            .to_vec(),
    ))
}
