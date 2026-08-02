//! `crypto_stream` wrapper - see `dstu_core::crypto_stream` (Strumok-256 keystream, internal
//! IV). **No authentication** - `stream_decrypt` never fails on tampered input, it returns
//! different, silently-wrong plaintext instead (inherited from the wrapped construction). Prefer
//! [`crate::secretbox`]/[`crate::secretstream`] unless integrity is handled elsewhere.

use crate::util::IntoDstuError;
use dstu_core::crypto_stream::{decrypt, encrypt, Key};
use napi::bindgen_prelude::Buffer;
use napi::Result;
use napi_derive::napi;

/// Generates a fresh 32-byte `crypto_stream` key from the OS CSPRNG.
#[napi(js_name = "streamKeygen")]
pub fn stream_keygen() -> Result<Buffer> {
    Key::generate()
        .dstu()
        .map(|key| Buffer::from(key.as_bytes().to_vec()))
}

/// XORs `plaintext` with a fresh keystream under `key`, drawing a random IV internally. Returns
/// `iv || ciphertext`. No authentication - see the module doc.
#[napi(js_name = "streamEncrypt")]
pub fn stream_encrypt(key: Buffer, plaintext: Buffer) -> Result<Buffer> {
    let key = Key::from_bytes(crate::util::to_array::<32>(&key, "key")?);
    encrypt(&key, &plaintext).dstu().map(Buffer::from)
}

/// Reverses [`stream_encrypt`] under `key`. Throws only if `sealed` is too short to contain an
/// IV - a tampered `sealed` decrypts to different, silently-wrong plaintext, not an error (see the
/// module doc).
#[napi(js_name = "streamDecrypt")]
pub fn stream_decrypt(key: Buffer, sealed: Buffer) -> Result<Buffer> {
    let key = Key::from_bytes(crate::util::to_array::<32>(&key, "key")?);
    decrypt(&key, &sealed).dstu().map(Buffer::from)
}
