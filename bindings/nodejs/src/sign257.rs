//! `crypto_sign257` wrapper - see `dstu_core::crypto_sign257` (DSTU 4145 `m=257`, T-199/T-204),
//! the `m=257` sibling of [`crate::sign`]. Keys are the module's own fixed-length byte encodings: a
//! 33-byte signing key, a 66-byte uncompressed verifying key (`x || y`), a 66-byte signature
//! (`r || s`). No curve-tag byte here - distinct function names (`sign257*`) are the whole
//! dispatch mechanism, matching every other binding's own D-118-driven "no tag sniffing" rule.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_sign257::{Signature, SigningKey, VerifyingKey};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey> {
    let d = to_array::<33>(bytes, "signingKey")?;
    SigningKey::from_bytes(&d).ok_or_else(|| {
        Error::from_reason("invalid signing key: must be nonzero and less than the curve order")
    })
}

/// Generates a fresh 33-byte signing key from the OS CSPRNG, uniform over the valid key range via
/// rejection sampling.
#[napi(js_name = "sign257Keygen")]
pub fn sign257_keygen() -> Result<Buffer> {
    SigningKey::generate()
        .dstu()
        .map(|key| Buffer::from(key.to_bytes().to_vec()))
}

/// Derives the 66-byte public verifying key for `signingKey` - safe to share/publish.
#[napi(js_name = "sign257VerifyingKey")]
pub fn sign257_verifying_key(signing_key: Buffer) -> Result<Buffer> {
    let key = signing_key_from_bytes(&signing_key)?;
    Ok(Buffer::from(
        key.verifying_key().to_uncompressed_bytes().to_vec(),
    ))
}

/// Signs `message` under `signingKey`, hashing it with Kupyna-256 and deriving the ephemeral
/// nonce deterministically. Returns a 66-byte signature.
#[napi(js_name = "sign257Message")]
pub fn sign257_message(signing_key: Buffer, message: Buffer) -> Result<Buffer> {
    let key = signing_key_from_bytes(&signing_key)?;
    Ok(Buffer::from(key.sign(&message).to_bytes().to_vec()))
}

/// Verifies `signature` against `message` under the 66-byte `verifyingKey`. Returns `true`/
/// `false` rather than throwing - matches the wrapped `dstu_core::crypto_sign257` API.
#[napi(js_name = "sign257Verify")]
pub fn sign257_verify(verifying_key: Buffer, message: Buffer, signature: Buffer) -> Result<bool> {
    let verifying_key_bytes = to_array::<66>(&verifying_key, "verifyingKey")?;
    let key = VerifyingKey::from_uncompressed_bytes(&verifying_key_bytes);
    let sig_bytes = to_array::<66>(&signature, "signature")?;
    Ok(key.verify(&message, &Signature::from_bytes(&sig_bytes)))
}
