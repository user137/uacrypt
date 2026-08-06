//! `crypto_box` wrapper - see [`dstu_core::crypto_box`] for the underlying hybrid-via-KDF
//! construction over `hazmat::dstu9041` (D-169). Named `crypto_box.rs`, not `box.rs` like every
//! sibling module drops its `crypto_` prefix (`secretbox.rs`, `sign.rs`, `stream.rs`) - `box`
//! alone is a reserved Rust keyword. Keys/sealed blobs cross the PHP boundary as `Binary<u8>`,
//! matching every other wrapper in this crate - `SecretKey`'s `Zeroize`-on-drop guarantee does not
//! carry across the FFI boundary into a PHP string regardless of wrapper shape, so there is
//! nothing an opaque type would additionally buy here (same reasoning as `secretbox.rs`'s own
//! module doc).

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_box::{open, seal, PublicKey, SecretKey};

fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey, PhpException> {
    let e = to_array::<32>(bytes, "secret_key")?;
    SecretKey::from_bytes(&e).ok_or_else(|| {
        PhpException::new(
            "invalid secret key: must be in the range {2, ..., n-2}".to_string(),
            0,
            crate::error::value_error(),
        )
    })
}

fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, PhpException> {
    let x = to_array::<32>(bytes, "public_key")?;
    PublicKey::from_bytes(&x).ok_or_else(|| {
        PhpException::new(
            "invalid public key: not a valid field element, or not in the base point's subgroup"
                .to_string(),
            0,
            crate::error::value_error(),
        )
    })
}

/// Generates a fresh 32-byte `crypto_box` secret key from the OS CSPRNG.
#[php_function]
pub fn dstu_core_box_keygen() -> Result<Binary<u8>, PhpException> {
    let key = SecretKey::generate().dstu()?;
    Ok(Binary::from(key.to_bytes().to_vec()))
}

/// Derives the 32-byte public key for `secret_key` - safe to share/publish (the curve point's
/// `x`-coordinate only, see `dstu_core::crypto_box`'s own module doc for why this is a safe
/// compression).
#[php_function]
pub fn dstu_core_box_public_key(secret_key: Binary<u8>) -> Result<Binary<u8>, PhpException> {
    let key = secret_key_from_bytes(&secret_key)?;
    Ok(Binary::from(key.public_key().to_bytes().to_vec()))
}

/// Encrypts `message` (any length) to the holder of `public_key`, drawing a fresh random seed and
/// ephemeral key internally. Not memory-bounded - the whole message is held in memory, matching
/// `uacrypt box-seal`'s own documented limitation.
#[php_function]
pub fn dstu_core_box_seal(
    public_key: Binary<u8>,
    message: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = public_key_from_bytes(&public_key)?;
    let sealed = seal(&message, &key).dstu()?;
    Ok(Binary::from(sealed))
}

/// Decrypts `sealed` (as produced by [`dstu_core_box_seal`]) under `secret_key`. Throws
/// `DstuCoreException` if authentication fails (wrong key, or any tampered wire segment -
/// deliberately not distinguished further, see `dstu_core::crypto_box::OpenError`'s own doc
/// comment) or `sealed` is too short to be valid.
#[php_function]
pub fn dstu_core_box_open(
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
        .function(wrap_function!(dstu_core_box_keygen))
        .function(wrap_function!(dstu_core_box_public_key))
        .function(wrap_function!(dstu_core_box_seal))
        .function(wrap_function!(dstu_core_box_open))
}
