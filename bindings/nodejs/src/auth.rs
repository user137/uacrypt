//! `crypto_auth` wrapper - see `dstu_core::crypto_auth` (Kupyna-256-KMAC).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_auth::{auth as core_auth, verify, Key};
use napi::bindgen_prelude::Buffer;
use napi::Result;
use napi_derive::napi;

/// Generates a fresh 32-byte `crypto_auth` key from the OS CSPRNG.
#[napi(js_name = "authKeygen")]
pub fn auth_keygen() -> Result<Buffer> {
    Key::generate()
        .dstu()
        .map(|key| Buffer::from(key.as_bytes().to_vec()))
}

/// Computes the 32-byte MAC of `message` under `key`.
#[napi(js_name = "auth")]
pub fn auth(key: Buffer, message: Buffer) -> Result<Buffer> {
    let key = Key::from_bytes(to_array::<32>(&key, "key")?);
    Ok(Buffer::from(core_auth(&key, &message).to_vec()))
}

/// Verifies `tag` against `message` under `key`. Throws if the tag does not match.
#[napi(js_name = "authVerify")]
pub fn auth_verify(key: Buffer, message: Buffer, tag: Buffer) -> Result<()> {
    let key = Key::from_bytes(to_array::<32>(&key, "key")?);
    let tag = to_array::<32>(&tag, "tag")?;
    verify(&key, &message, &tag).dstu()
}
