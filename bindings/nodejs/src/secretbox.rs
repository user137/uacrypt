//! `crypto_secretbox` wrapper - see `dstu_core::crypto_secretbox` for the underlying construction
//! (Kalyna-256/256-GCM, internal nonce, no caller-facing AAD). Keys and sealed blobs cross the
//! boundary as `Buffer`, matching this project's other bindings' ergonomics rather than an opaque
//! handle type - `dstu_core::crypto_secretbox::SecretKey`'s own `Zeroize`-on-drop guarantee does
//! not carry across the FFI boundary into a JS `Buffer` regardless of wrapper shape, so there is
//! nothing an opaque type would additionally buy here.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_secretbox::{open, seal, SecretKey};
use napi::bindgen_prelude::Buffer;
use napi::Result;
use napi_derive::napi;

/// Generates a fresh 32-byte `crypto_secretbox` key from the OS CSPRNG.
#[napi(js_name = "secretboxKeygen")]
pub fn secretbox_keygen() -> Result<Buffer> {
    SecretKey::generate()
        .dstu()
        .map(|key| Buffer::from(key.as_bytes().to_vec()))
}

/// Encrypts and authenticates `plaintext` under `key`. Returns `nonce || ciphertext || tag`.
#[napi(js_name = "secretboxSeal")]
pub fn secretbox_seal(key: Buffer, plaintext: Buffer) -> Result<Buffer> {
    let key = SecretKey::from_bytes(to_array::<32>(&key, "key")?);
    seal(&key, &plaintext).dstu().map(Buffer::from)
}

/// Verifies and decrypts `sealed` (as produced by [`secretbox_seal`]) under `key`. Throws if
/// authentication fails or `sealed` is too short to be valid.
#[napi(js_name = "secretboxOpen")]
pub fn secretbox_open(key: Buffer, sealed: Buffer) -> Result<Buffer> {
    let key = SecretKey::from_bytes(to_array::<32>(&key, "key")?);
    open(&key, &sealed).dstu().map(Buffer::from)
}
