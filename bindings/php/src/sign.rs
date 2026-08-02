//! `crypto_sign` wrapper - see [`dstu_core::crypto_sign`] (DSTU 4145, deterministic nonce, no RNG
//! dependency for signing itself - only [`dstu_core_sign_keygen`] touches the OS CSPRNG). Keys are
//! the module's own fixed-length byte encodings: a 21-byte signing key, a 42-byte uncompressed
//! verifying key (`x || y`, not the DSTU standard's own compressed point encoding - see
//! `dstu_core::crypto_sign`'s module doc), a 42-byte signature (`r || s`).

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_sign::{Signature, SigningKey, VerifyingKey};

fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, PhpException> {
    let d = to_array::<21>(bytes, "signing_key")?;
    SigningKey::from_bytes(&d).ok_or_else(|| {
        PhpException::new(
            "invalid signing key: must be nonzero and less than the curve order".to_string(),
            0,
            crate::error::value_error(),
        )
    })
}

/// Generates a fresh 21-byte signing key from the OS CSPRNG, uniform over the valid key range via
/// rejection sampling.
#[php_function]
pub fn dstu_core_sign_keygen() -> Result<Binary<u8>, PhpException> {
    let key = SigningKey::generate().dstu()?;
    Ok(Binary::from(key.to_bytes().to_vec()))
}

/// Derives the 42-byte public verifying key for `signing_key` - safe to share/publish.
#[php_function]
pub fn dstu_core_sign_verifying_key(signing_key: Binary<u8>) -> Result<Binary<u8>, PhpException> {
    let key = signing_key_from_bytes(&signing_key)?;
    Ok(Binary::from(
        key.verifying_key().to_uncompressed_bytes().to_vec(),
    ))
}

/// Signs `message` under `signing_key`, hashing it with Kupyna-256 and deriving the ephemeral
/// nonce deterministically. Returns a 42-byte signature.
#[php_function]
pub fn dstu_core_sign_message(
    signing_key: Binary<u8>,
    message: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = signing_key_from_bytes(&signing_key)?;
    Ok(Binary::from(key.sign(&message).to_bytes().to_vec()))
}

/// Verifies `signature` against `message` under the 42-byte `verifying_key`. Returns `true`/
/// `false` rather than throwing - matches the wrapped `dstu_core::crypto_sign` API.
#[php_function]
pub fn dstu_core_sign_verify(
    verifying_key: Binary<u8>,
    message: Binary<u8>,
    signature: Binary<u8>,
) -> Result<bool, PhpException> {
    let verifying_key_bytes = to_array::<42>(&verifying_key, "verifying_key")?;
    let key = VerifyingKey::from_uncompressed_bytes(&verifying_key_bytes);
    let sig_bytes = to_array::<42>(&signature, "signature")?;
    Ok(key.verify(&message, &Signature::from_bytes(&sig_bytes)))
}

/// Registers this module's functions - see `secretbox::register`'s doc comment for why each
/// module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_sign_keygen))
        .function(wrap_function!(dstu_core_sign_verifying_key))
        .function(wrap_function!(dstu_core_sign_message))
        .function(wrap_function!(dstu_core_sign_verify))
}
