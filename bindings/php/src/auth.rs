//! `crypto_auth` wrapper - see [`dstu_core::crypto_auth`] (Kupyna-256-KMAC).

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_auth::{auth as core_auth, verify, Key};

/// Generates a fresh 32-byte `crypto_auth` key from the OS CSPRNG.
#[php_function]
pub fn dstu_core_auth_keygen() -> Result<Binary<u8>, PhpException> {
    let key = Key::generate().dstu()?;
    Ok(Binary::from(key.as_bytes().to_vec()))
}

/// Computes the 32-byte MAC of `message` under `key`.
#[php_function]
pub fn dstu_core_auth(key: Binary<u8>, message: Binary<u8>) -> Result<Binary<u8>, PhpException> {
    let key = Key::from_bytes(to_array::<32>(&key, "key")?);
    Ok(Binary::from(core_auth(&key, &message).to_vec()))
}

/// Verifies `tag` against `message` under `key`. Throws `DstuCoreException` if the tag does not
/// match.
#[php_function]
pub fn dstu_core_auth_verify(
    key: Binary<u8>,
    message: Binary<u8>,
    tag: Binary<u8>,
) -> Result<(), PhpException> {
    let key = Key::from_bytes(to_array::<32>(&key, "key")?);
    let tag = to_array::<32>(&tag, "tag")?;
    verify(&key, &message, &tag).dstu()
}

/// Registers this module's functions - see `secretbox::register`'s doc comment for why each
/// module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_auth_keygen))
        .function(wrap_function!(dstu_core_auth))
        .function(wrap_function!(dstu_core_auth_verify))
}
