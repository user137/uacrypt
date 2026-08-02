//! `crypto_kdf` wrapper - see [`dstu_core::crypto_kdf`] (Kupyna-256-KDF).

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_kdf::MasterKey;

/// Generates a fresh 32-byte `crypto_kdf` master key from the OS CSPRNG.
#[php_function]
pub fn dstu_core_kdf_keygen() -> Result<Binary<u8>, PhpException> {
    let key = MasterKey::generate().dstu()?;
    Ok(Binary::from(key.as_bytes().to_vec()))
}

/// Derives a 32-byte subkey from `master_key`. `context` must be exactly 8 bytes. `subkey_id`
/// must be non-negative. Different `subkey_id`/`context` values (holding the others fixed)
/// produce different, unrelated-looking subkeys; the same inputs always re-derive the same
/// subkey.
#[php_function]
pub fn dstu_core_kdf_derive_subkey(
    master_key: Binary<u8>,
    subkey_id: i64,
    context: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    if subkey_id < 0 {
        return Err(PhpException::new(
            "subkey_id must be non-negative".to_string(),
            0,
            crate::error::value_error(),
        ));
    }
    let master_key = MasterKey::from_bytes(to_array::<32>(&master_key, "master_key")?);
    let context = to_array::<8>(&context, "context")?;
    #[allow(clippy::cast_sign_loss)] // deliberate: subkey_id < 0 already rejected above
    Ok(Binary::from(
        master_key
            .derive_subkey(subkey_id as u64, &context)
            .to_vec(),
    ))
}

/// Registers this module's functions - see `secretbox::register`'s doc comment for why each
/// module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_kdf_keygen))
        .function(wrap_function!(dstu_core_kdf_derive_subkey))
}
