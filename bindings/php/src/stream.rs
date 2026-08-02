//! `crypto_stream` wrapper - see [`dstu_core::crypto_stream`] (Strumok-256 keystream, internal
//! IV). **No authentication** - `dstu_core_stream_decrypt` never fails on tampered input, it
//! returns different, silently-wrong plaintext instead (inherited from the wrapped construction).
//! Prefer [`crate::secretbox`]/[`crate::secretstream`] unless integrity is handled elsewhere.

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_stream::{decrypt, encrypt, Key};

/// Generates a fresh 32-byte `crypto_stream` key from the OS CSPRNG.
#[php_function]
pub fn dstu_core_stream_keygen() -> Result<Binary<u8>, PhpException> {
    let key = Key::generate().dstu()?;
    Ok(Binary::from(key.as_bytes().to_vec()))
}

/// XORs `plaintext` with a fresh keystream under `key`, drawing a random IV internally. Returns
/// `iv || ciphertext`. No authentication - see the module doc.
#[php_function]
pub fn dstu_core_stream_encrypt(
    key: Binary<u8>,
    plaintext: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = Key::from_bytes(to_array::<32>(&key, "key")?);
    let sealed = encrypt(&key, &plaintext).dstu()?;
    Ok(Binary::from(sealed))
}

/// Reverses [`dstu_core_stream_encrypt`] under `key`. Throws `DstuCoreException` only if `sealed`
/// is too short to contain an IV - a tampered `sealed` decrypts to different, silently-wrong
/// plaintext, not an error (see the module doc).
#[php_function]
pub fn dstu_core_stream_decrypt(
    key: Binary<u8>,
    sealed: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = Key::from_bytes(to_array::<32>(&key, "key")?);
    let plaintext = decrypt(&key, &sealed).dstu()?;
    Ok(Binary::from(plaintext))
}

/// Registers this module's functions - see `secretbox::register`'s doc comment for why each
/// module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_stream_keygen))
        .function(wrap_function!(dstu_core_stream_encrypt))
        .function(wrap_function!(dstu_core_stream_decrypt))
}
