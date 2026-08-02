//! `crypto_kdf` wrapper - see [`dstu_core::crypto_kdf`] (Kupyna-256-KDF).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_kdf::MasterKey;
use magnus::{Error, RString, Ruby};

/// Generates a fresh 32-byte `crypto_kdf` master key from the OS CSPRNG.
pub fn kdf_keygen(ruby: &Ruby) -> Result<RString, Error> {
    let key = MasterKey::generate().dstu(ruby)?;
    Ok(ruby.str_from_slice(key.as_bytes()))
}

/// Derives a 32-byte subkey from `master_key`. `context` must be exactly 8 bytes. `subkey_id`
/// must be non-negative. Different `subkey_id`/`context` values (holding the others fixed)
/// produce different, unrelated-looking subkeys; the same inputs always re-derive the same
/// subkey.
pub fn kdf_derive_subkey(
    ruby: &Ruby,
    master_key: RString,
    subkey_id: i64,
    context: RString,
) -> Result<RString, Error> {
    if subkey_id < 0 {
        return Err(Error::new(
            ruby.exception_arg_error(),
            "subkey_id must be non-negative",
        ));
    }
    let master_key =
        MasterKey::from_bytes(to_array::<32>(ruby, &master_key.to_bytes(), "master_key")?);
    let context = to_array::<8>(ruby, &context.to_bytes(), "context")?;
    Ok(ruby.str_from_slice(&master_key.derive_subkey(subkey_id as u64, &context)))
}
