//! `crypto_box` wrapper - see `dstu_core::crypto_box` for the underlying hybrid-via-KDF
//! construction over `hazmat::dstu9041` (D-169). Named `crypto_box.rs`, not `box.rs` like every
//! sibling module drops its `crypto_` prefix (`secretbox.rs`, `sign.rs`, `stream.rs`) - `box`
//! alone is a reserved Rust keyword. Keys/sealed blobs cross the boundary as `Buffer`, matching
//! every other wrapper in this crate - `SecretKey`'s `Zeroize`-on-drop guarantee does not carry
//! into a JS `Buffer` regardless of wrapper shape, so there is nothing an opaque type would
//! additionally buy here (same reasoning as `secretbox.rs`'s own module doc).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_box::{open, seal, PublicKey, SecretKey};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey> {
    let e = to_array::<32>(bytes, "secretKey")?;
    SecretKey::from_bytes(&e)
        .ok_or_else(|| Error::from_reason("invalid secret key: must be in the range {2, ..., n-2}"))
}

fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    let x = to_array::<32>(bytes, "publicKey")?;
    PublicKey::from_bytes(&x).ok_or_else(|| {
        Error::from_reason(
            "invalid public key: not a valid field element, or not in the base point's subgroup",
        )
    })
}

/// Generates a fresh 32-byte `crypto_box` secret key from the OS CSPRNG.
#[napi(js_name = "boxKeygen")]
pub fn box_keygen() -> Result<Buffer> {
    SecretKey::generate()
        .dstu()
        .map(|key| Buffer::from(key.to_bytes().to_vec()))
}

/// Derives the 32-byte public key for `secretKey` - safe to share/publish (the curve point's
/// `x`-coordinate only, see `dstu_core::crypto_box`'s own module doc for why this is a safe
/// compression).
#[napi(js_name = "boxPublicKey")]
pub fn box_public_key(secret_key: Buffer) -> Result<Buffer> {
    let key = secret_key_from_bytes(&secret_key)?;
    Ok(Buffer::from(key.public_key().to_bytes().to_vec()))
}

/// Encrypts `message` (any length) to the holder of `publicKey`, drawing a fresh random seed and
/// ephemeral key internally. Not memory-bounded - the whole message is held in memory, matching
/// `uacrypt box-seal`'s own documented limitation.
#[napi(js_name = "boxSeal")]
pub fn box_seal(public_key: Buffer, message: Buffer) -> Result<Buffer> {
    let key = public_key_from_bytes(&public_key)?;
    seal(&message, &key).dstu().map(Buffer::from)
}

/// Decrypts `sealed` (as produced by [`box_seal`]) under `secretKey`. Throws if authentication
/// fails (wrong key, or any tampered wire segment - deliberately not distinguished further, see
/// `dstu_core::crypto_box::OpenError`'s own doc comment) or `sealed` is too short to be valid.
#[napi(js_name = "boxOpen")]
pub fn box_open(secret_key: Buffer, sealed: Buffer) -> Result<Buffer> {
    let key = secret_key_from_bytes(&secret_key)?;
    open(&sealed, &key).dstu().map(Buffer::from)
}
