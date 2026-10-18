//! `crypto_pwhash` wrapper - see `dstu_core::crypto_pwhash` (Argon2id, the one deliberately
//! non-DSTU component). `strength` is one of the `PWHASH_*` module constants, mirroring
//! `dstu_core::crypto_pwhash::Strength`'s three named presets - not a raw cost-parameter knob.

use crate::util::IntoDstuError;
use dstu_core::crypto_pwhash::{derive_key, hash_password, verify_password, Strength};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

fn strength_from_u8(strength: u8) -> Result<Strength> {
    match strength {
        0 => Ok(Strength::Interactive),
        1 => Ok(Strength::Moderate),
        2 => Ok(Strength::Sensitive),
        _ => Err(Error::from_reason(
            "strength must be PWHASH_INTERACTIVE (0), PWHASH_MODERATE (1), or PWHASH_SENSITIVE (2)",
        )),
    }
}

/// Hashes `password` into a self-describing PHC string, using a fresh random salt. `strength`
/// selects one of the `PWHASH_*` presets (default `PWHASH_MODERATE`, omit or pass `undefined`).
#[napi(js_name = "pwhashHashPassword")]
pub fn pwhash_hash_password(password: Buffer, strength: Option<u8>) -> Result<String> {
    hash_password(&password, strength_from_u8(strength.unwrap_or(1))?).dstu()
}

/// Verifies `password` against a PHC string produced by [`pwhash_hash_password`]. Returns
/// `false` for both a wrong password and a malformed hash string.
#[napi(js_name = "pwhashVerifyPassword")]
pub fn pwhash_verify_password(password: Buffer, hash: String) -> bool {
    verify_password(&password, &hash)
}

/// Derives a 32-byte key from `password` and a 16-byte `salt` - libsodium's `crypto_pwhash`
/// (Argon2id v1.3), byte for byte (T-269). Runs on the calling thread, as
/// [`pwhash_hash_password`] does.
#[napi(js_name = "pwhashDeriveKey")]
pub fn pwhash_derive_key(password: Buffer, salt: Buffer, strength: Option<u8>) -> Result<Buffer> {
    let salt = crate::util::to_array::<{ dstu_core::crypto_pwhash::SALT_BYTES }>(&salt, "salt")?;
    let key = derive_key(&password, &salt, strength_from_u8(strength.unwrap_or(1))?).dstu()?;
    Ok(Buffer::from(key.to_vec()))
}
