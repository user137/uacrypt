//! `crypto_auth` wrapper - see [`dstu_core::crypto_auth`] (Kupyna-256-KMAC).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_auth::{auth as core_auth, verify, Key};
use magnus::{Error, RString, Ruby};

/// Generates a fresh 32-byte `crypto_auth` key from the OS CSPRNG.
pub fn auth_keygen(ruby: &Ruby) -> Result<RString, Error> {
    let key = Key::generate().dstu(ruby)?;
    Ok(ruby.str_from_slice(key.as_bytes()))
}

/// Computes the 32-byte MAC of `message` under `key`.
pub fn auth(ruby: &Ruby, key: RString, message: RString) -> Result<RString, Error> {
    let key = Key::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
    Ok(ruby.str_from_slice(&core_auth(&key, &message.to_bytes())))
}

/// Verifies `tag` against `message` under `key`. Raises `DstuCore::Error` if the tag does not
/// match.
pub fn auth_verify(ruby: &Ruby, key: RString, message: RString, tag: RString) -> Result<(), Error> {
    let key = Key::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
    let tag = to_array::<32>(ruby, &tag.to_bytes(), "tag")?;
    verify(&key, &message.to_bytes(), &tag).dstu(ruby)
}
