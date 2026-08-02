//! `crypto_sign` wrapper - see [`dstu_core::crypto_sign`] (DSTU 4145, deterministic nonce, no RNG
//! dependency for signing itself - only [`sign_keygen`] touches the OS CSPRNG). Keys are the
//! module's own fixed-length byte encodings: a 21-byte signing key, a 42-byte uncompressed
//! verifying key (`x || y`, not the DSTU standard's own compressed point encoding - see
//! `dstu_core::crypto_sign`'s module doc), a 42-byte signature (`r || s`).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_sign::{Signature, SigningKey, VerifyingKey};
use magnus::{Error, RString, Ruby};

fn signing_key_from_bytes(ruby: &Ruby, bytes: &[u8]) -> Result<SigningKey, Error> {
    let d = to_array::<21>(ruby, bytes, "signing_key")?;
    SigningKey::from_bytes(&d).ok_or_else(|| {
        Error::new(
            ruby.exception_arg_error(),
            "invalid signing key: must be nonzero and less than the curve order",
        )
    })
}

/// Generates a fresh 21-byte signing key from the OS CSPRNG, uniform over the valid key range via
/// rejection sampling.
pub fn sign_keygen(ruby: &Ruby) -> Result<RString, Error> {
    let key = SigningKey::generate().dstu(ruby)?;
    Ok(ruby.str_from_slice(&key.to_bytes()))
}

/// Derives the 42-byte public verifying key for `signing_key` - safe to share/publish.
pub fn sign_verifying_key(ruby: &Ruby, signing_key: RString) -> Result<RString, Error> {
    let key = signing_key_from_bytes(ruby, &signing_key.to_bytes())?;
    Ok(ruby.str_from_slice(&key.verifying_key().to_uncompressed_bytes()))
}

/// Signs `message` under `signing_key`, hashing it with Kupyna-256 and deriving the ephemeral
/// nonce deterministically. Returns a 42-byte signature.
pub fn sign_message(ruby: &Ruby, signing_key: RString, message: RString) -> Result<RString, Error> {
    let key = signing_key_from_bytes(ruby, &signing_key.to_bytes())?;
    Ok(ruby.str_from_slice(&key.sign(&message.to_bytes()).to_bytes()))
}

/// Verifies `signature` against `message` under the 42-byte `verifying_key`. Returns `true`/
/// `false` rather than raising - matches the wrapped `dstu_core::crypto_sign` API.
pub fn sign_verify(
    ruby: &Ruby,
    verifying_key: RString,
    message: RString,
    signature: RString,
) -> Result<bool, Error> {
    let verifying_key_bytes = to_array::<42>(ruby, &verifying_key.to_bytes(), "verifying_key")?;
    let key = VerifyingKey::from_uncompressed_bytes(&verifying_key_bytes);
    let sig_bytes = to_array::<42>(ruby, &signature.to_bytes(), "signature")?;
    Ok(key.verify(&message.to_bytes(), &Signature::from_bytes(&sig_bytes)))
}
