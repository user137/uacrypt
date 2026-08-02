//! `crypto_sign` wrapper - see `dstu_core::crypto_sign` (DSTU 4145, deterministic nonce, no RNG
//! dependency for signing itself - only [`sign_keygen`] touches the OS CSPRNG). Keys are the
//! module's own fixed-length byte encodings: a 21-byte signing key, a 42-byte uncompressed
//! verifying key (`x || y`, not the DSTU standard's own compressed point encoding - see
//! `dstu_core::crypto_sign`'s module doc), a 42-byte signature (`r || s`).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_sign::{Signature, SigningKey, VerifyingKey};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey> {
    let d = to_array::<21>(bytes, "signing_key")?;
    SigningKey::from_bytes(&d).ok_or_else(|| {
        Error::from_reason("invalid signing key: must be nonzero and less than the curve order")
    })
}

/// Generates a fresh 21-byte signing key from the OS CSPRNG, uniform over the valid key range via
/// rejection sampling.
#[napi(js_name = "signKeygen")]
pub fn sign_keygen() -> Result<Buffer> {
    SigningKey::generate()
        .dstu()
        .map(|key| Buffer::from(key.to_bytes().to_vec()))
}

/// Derives the 42-byte public verifying key for `signing_key` - safe to share/publish.
#[napi(js_name = "signVerifyingKey")]
pub fn sign_verifying_key(signing_key: Buffer) -> Result<Buffer> {
    let key = signing_key_from_bytes(&signing_key)?;
    Ok(Buffer::from(
        key.verifying_key().to_uncompressed_bytes().to_vec(),
    ))
}

/// Signs `message` under `signing_key`, hashing it with Kupyna-256 and deriving the ephemeral
/// nonce deterministically. Returns a 42-byte signature.
#[napi(js_name = "signMessage")]
pub fn sign_message(signing_key: Buffer, message: Buffer) -> Result<Buffer> {
    let key = signing_key_from_bytes(&signing_key)?;
    Ok(Buffer::from(key.sign(&message).to_bytes().to_vec()))
}

/// Verifies `signature` against `message` under the 42-byte `verifying_key`. Returns `true`/
/// `false` rather than throwing - matches the wrapped `dstu_core::crypto_sign` API.
#[napi(js_name = "signVerify")]
pub fn sign_verify(verifying_key: Buffer, message: Buffer, signature: Buffer) -> Result<bool> {
    let verifying_key_bytes = to_array::<42>(&verifying_key, "verifying_key")?;
    let key = VerifyingKey::from_uncompressed_bytes(&verifying_key_bytes);
    let sig_bytes = to_array::<42>(&signature, "signature")?;
    Ok(key.verify(&message, &Signature::from_bytes(&sig_bytes)))
}
