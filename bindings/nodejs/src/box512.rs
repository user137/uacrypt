//! `crypto_box512` wrapper - see `dstu_core::crypto_box512` (`l(p)=512`/E512/1, T-193/T-204), the
//! direct sibling of [`crate::crypto_box`] at this curve size's own widths. Keys/sealed blobs
//! cross the boundary as `Buffer`, matching every other wrapper in this crate.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_box512::{open, seal, PublicKey, SecretKey};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey> {
    let e = to_array::<64>(bytes, "secretKey")?;
    SecretKey::from_bytes(&e)
        .ok_or_else(|| Error::from_reason("invalid secret key: must be in the range {2, ..., n-2}"))
}

fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    let x = to_array::<64>(bytes, "publicKey")?;
    PublicKey::from_bytes(&x).ok_or_else(|| {
        Error::from_reason(
            "invalid public key: not a valid field element, or not in the base point's subgroup",
        )
    })
}

/// Generates a fresh 64-byte `crypto_box512` secret key from the OS CSPRNG.
#[napi(js_name = "box512Keygen")]
pub fn box512_keygen() -> Result<Buffer> {
    SecretKey::generate()
        .dstu()
        .map(|key| Buffer::from(key.to_bytes().to_vec()))
}

/// Derives the 64-byte public key for `secretKey` - safe to share/publish (the curve point's
/// `x`-coordinate only, see `dstu_core::crypto_box512`'s own module doc for why this is a safe
/// compression).
#[napi(js_name = "box512PublicKey")]
pub fn box512_public_key(secret_key: Buffer) -> Result<Buffer> {
    let key = secret_key_from_bytes(&secret_key)?;
    Ok(Buffer::from(key.public_key().to_bytes().to_vec()))
}

/// Encrypts `message` (any length) to the holder of `publicKey`, drawing a fresh random seed and
/// ephemeral key internally. Not memory-bounded - the whole message is held in memory, matching
/// `uacrypt box-seal512`'s own documented limitation.
#[napi(js_name = "box512Seal")]
pub fn box512_seal(public_key: Buffer, message: Buffer) -> Result<Buffer> {
    let key = public_key_from_bytes(&public_key)?;
    seal(&message, &key).dstu().map(Buffer::from)
}

/// Decrypts `sealed` (as produced by [`box512_seal`]) under `secretKey`. Throws if authentication
/// fails (wrong key, or any tampered wire segment - deliberately not distinguished further, see
/// `dstu_core::crypto_box512::OpenError`'s own doc comment) or `sealed` is too short to be valid.
#[napi(js_name = "box512Open")]
pub fn box512_open(secret_key: Buffer, sealed: Buffer) -> Result<Buffer> {
    let key = secret_key_from_bytes(&secret_key)?;
    open(&sealed, &key).dstu().map(Buffer::from)
}
