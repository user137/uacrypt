//! `crypto_pwhash` wrapper - see [`dstu_core::crypto_pwhash`] (Argon2id, the one deliberately
//! non-DSTU component). `strength` is one of the `PWHASH_*` module constants, mirroring
//! [`dstu_core::crypto_pwhash::Strength`]'s three named presets - not a raw cost-parameter knob.

use crate::util::IntoDstuError;
use dstu_core::crypto_pwhash::{hash_password, verify_password, Strength};
use magnus::{Error, RString, Ruby};

fn strength_from_u8(ruby: &Ruby, strength: u8) -> Result<Strength, Error> {
    match strength {
        0 => Ok(Strength::Interactive),
        1 => Ok(Strength::Moderate),
        2 => Ok(Strength::Sensitive),
        _ => Err(Error::new(
            ruby.exception_arg_error(),
            "strength must be PWHASH_INTERACTIVE (0), PWHASH_MODERATE (1), or PWHASH_SENSITIVE (2)",
        )),
    }
}

/// Hashes `password` into a self-describing PHC string, using a fresh random salt. `strength`
/// selects one of the `PWHASH_*` presets.
pub fn pwhash_hash_password(ruby: &Ruby, password: RString, strength: u8) -> Result<String, Error> {
    hash_password(&password.to_bytes(), strength_from_u8(ruby, strength)?).dstu(ruby)
}

/// Verifies `password` against a PHC string produced by [`pwhash_hash_password`]. Returns `false`
/// for both a wrong password and a malformed hash string.
pub fn pwhash_verify_password(password: RString, hash: String) -> bool {
    verify_password(&password.to_bytes(), &hash)
}
