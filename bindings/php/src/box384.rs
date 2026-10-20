//! `crypto_box384` wrapper - see [`dstu_core::crypto_box384`] (`l(p)=384`/E384/1, T-297),
//! the direct sibling of [`crate::crypto_box`] at this curve size's own widths. Keys/sealed blobs
//! cross the PHP boundary as `Binary<u8>`, matching every other wrapper in this crate.

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_box384::{open, seal, PublicKey, SecretKey};

pub(crate) fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey, PhpException> {
    let e = to_array::<48>(bytes, "secret_key")?;
    SecretKey::from_bytes(&e).ok_or_else(|| {
        PhpException::new(
            "invalid secret key: must be in the range {2, ..., n-2}".to_string(),
            0,
            crate::error::value_error(),
        )
    })
}

pub(crate) fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, PhpException> {
    let x = to_array::<48>(bytes, "public_key")?;
    PublicKey::from_bytes(&x).ok_or_else(|| {
        PhpException::new(
            "invalid public key: not a valid field element, or not in the base point's subgroup"
                .to_string(),
            0,
            crate::error::value_error(),
        )
    })
}

/// Generates a fresh 48-byte `crypto_box384` secret key from the OS CSPRNG.
///
/// `#[php(name = ...)]` overrides ext-php-rs's default `RenameRule::Snake` conversion, which
/// otherwise splits a letter/digit boundary (`box384` -> `box_384`) - confirmed by a real
/// `function_exists()` check after the default rename silently produced `dstu_core_box_384_keygen`
/// instead, not assumed from reading the derive macro alone.
#[php_function]
#[php(name = "dstu_core_box384_keygen")]
pub fn dstu_core_box384_keygen() -> Result<Binary<u8>, PhpException> {
    let key = SecretKey::generate().dstu()?;
    Ok(Binary::from(key.to_bytes().to_vec()))
}

/// Derives the 48-byte public key for `secret_key` - safe to share/publish (the curve point's
/// `x`-coordinate only, see `dstu_core::crypto_box384`'s own module doc for why this is a safe
/// compression).
#[php_function]
#[php(name = "dstu_core_box384_public_key")]
pub fn dstu_core_box384_public_key(secret_key: Binary<u8>) -> Result<Binary<u8>, PhpException> {
    let key = secret_key_from_bytes(&secret_key)?;
    Ok(Binary::from(key.public_key().to_bytes().to_vec()))
}

/// Encrypts `message` (any length) to the holder of `public_key`, drawing a fresh random seed and
/// ephemeral key internally. Not memory-bounded - the whole message is held in memory, matching
/// `uacrypt box-seal`'s own documented limitation.
#[php_function]
#[php(name = "dstu_core_box384_seal")]
pub fn dstu_core_box384_seal(
    public_key: Binary<u8>,
    message: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = public_key_from_bytes(&public_key)?;
    let sealed = seal(&message, &key).dstu()?;
    Ok(Binary::from(sealed))
}

/// Decrypts `sealed` (as produced by [`dstu_core_box384_seal`]) under `secret_key`. Throws
/// `DstuCoreException` if authentication fails (wrong key, or any tampered wire segment -
/// deliberately not distinguished further, see `dstu_core::crypto_box384::OpenError`'s own doc
/// comment) or `sealed` is too short to be valid.
#[php_function]
#[php(name = "dstu_core_box384_open")]
pub fn dstu_core_box384_open(
    secret_key: Binary<u8>,
    sealed: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = secret_key_from_bytes(&secret_key)?;
    let plaintext = open(&sealed, &key).dstu()?;
    Ok(Binary::from(plaintext))
}

/// Registers this module's functions - see `secretbox::register`'s doc comment for why each
/// module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_box384_keygen))
        .function(wrap_function!(dstu_core_box384_public_key))
        .function(wrap_function!(dstu_core_box384_seal))
        .function(wrap_function!(dstu_core_box384_open))
}
