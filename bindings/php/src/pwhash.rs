//! `crypto_pwhash` wrapper - see [`dstu_core::crypto_pwhash`] (Argon2id, the one deliberately
//! non-DSTU component). `strength` is one of the `DSTU_CORE_PWHASH_*` global constants, mirroring
//! [`dstu_core::crypto_pwhash::Strength`]'s three named presets - not a raw cost-parameter knob.

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::error::IntoDstuException;
use dstu_core::crypto_pwhash::{hash_password, verify_password, Strength};

fn strength_from_u8(strength: u8) -> Result<Strength, PhpException> {
    match strength {
        0 => Ok(Strength::Interactive),
        1 => Ok(Strength::Moderate),
        2 => Ok(Strength::Sensitive),
        _ => Err(PhpException::new(
            "strength must be DSTU_CORE_PWHASH_INTERACTIVE (0), DSTU_CORE_PWHASH_MODERATE (1), \
             or DSTU_CORE_PWHASH_SENSITIVE (2)"
                .to_string(),
            0,
            crate::error::value_error(),
        )),
    }
}

/// Hashes `password` into a self-describing PHC string, using a fresh random salt. `strength`
/// selects one of the `DSTU_CORE_PWHASH_*` presets.
#[php_function]
pub fn dstu_core_pwhash_hash_password(
    password: Binary<u8>,
    strength: u8,
) -> Result<String, PhpException> {
    hash_password(&password, strength_from_u8(strength)?).dstu()
}

/// Verifies `password` against a PHC string produced by [`dstu_core_pwhash_hash_password`].
/// Returns `false` for both a wrong password and a malformed hash string.
#[php_function]
pub fn dstu_core_pwhash_verify_password(password: Binary<u8>, hash: String) -> bool {
    verify_password(&password, &hash)
}

/// Registers this module's functions - see `secretbox::register`'s doc comment for why each
/// module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_pwhash_hash_password))
        .function(wrap_function!(dstu_core_pwhash_verify_password))
}
