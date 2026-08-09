//! `crypto_sign257` wrapper - see [`dstu_core::crypto_sign257`] (DSTU 4145 `m=257`, T-199/T-204),
//! the `m=257` sibling of [`crate::sign`]. Keys are the module's own fixed-length byte encodings: a
//! 33-byte signing key, a 66-byte uncompressed verifying key (`x || y`), a 66-byte signature
//! (`r || s`). No curve-tag byte here - distinct function names (`dstu_core_sign257_*`) are the
//! whole dispatch mechanism, matching every other binding's own D-118-driven "no tag sniffing" rule.

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_sign257::{Signature, SigningKey, VerifyingKey};

fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, PhpException> {
    let d = to_array::<33>(bytes, "signing_key")?;
    SigningKey::from_bytes(&d).ok_or_else(|| {
        PhpException::new(
            "invalid signing key: must be nonzero and less than the curve order".to_string(),
            0,
            crate::error::value_error(),
        )
    })
}

/// Generates a fresh 33-byte signing key from the OS CSPRNG, uniform over the valid key range via
/// rejection sampling.
///
/// `#[php(name = ...)]` overrides ext-php-rs's default `RenameRule::Snake` conversion, which
/// otherwise splits a letter/digit boundary (`sign257` -> `sign_257`) - same fix as
/// `box512::dstu_core_box512_keygen`'s own doc comment explains, confirmed by a real
/// `function_exists()` check.
#[php_function]
#[php(name = "dstu_core_sign257_keygen")]
pub fn dstu_core_sign257_keygen() -> Result<Binary<u8>, PhpException> {
    let key = SigningKey::generate().dstu()?;
    Ok(Binary::from(key.to_bytes().to_vec()))
}

/// Derives the 66-byte public verifying key for `signing_key` - safe to share/publish.
#[php_function]
#[php(name = "dstu_core_sign257_verifying_key")]
pub fn dstu_core_sign257_verifying_key(
    signing_key: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = signing_key_from_bytes(&signing_key)?;
    Ok(Binary::from(
        key.verifying_key().to_uncompressed_bytes().to_vec(),
    ))
}

/// Signs `message` under `signing_key`, hashing it with Kupyna-256 and deriving the ephemeral
/// nonce deterministically. Returns a 66-byte signature.
#[php_function]
#[php(name = "dstu_core_sign257_message")]
pub fn dstu_core_sign257_message(
    signing_key: Binary<u8>,
    message: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = signing_key_from_bytes(&signing_key)?;
    Ok(Binary::from(key.sign(&message).to_bytes().to_vec()))
}

/// Verifies `signature` against `message` under the 66-byte `verifying_key`. Returns `true`/
/// `false` rather than throwing - matches the wrapped `dstu_core::crypto_sign257` API.
#[php_function]
#[php(name = "dstu_core_sign257_verify")]
pub fn dstu_core_sign257_verify(
    verifying_key: Binary<u8>,
    message: Binary<u8>,
    signature: Binary<u8>,
) -> Result<bool, PhpException> {
    let verifying_key_bytes = to_array::<66>(&verifying_key, "verifying_key")?;
    let key = VerifyingKey::from_uncompressed_bytes(&verifying_key_bytes);
    let sig_bytes = to_array::<66>(&signature, "signature")?;
    Ok(key.verify(&message, &Signature::from_bytes(&sig_bytes)))
}

/// Registers this module's functions - see `secretbox::register`'s doc comment for why each
/// module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_sign257_keygen))
        .function(wrap_function!(dstu_core_sign257_verifying_key))
        .function(wrap_function!(dstu_core_sign257_message))
        .function(wrap_function!(dstu_core_sign257_verify))
}
