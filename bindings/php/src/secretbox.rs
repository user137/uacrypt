//! `crypto_secretbox` wrapper - see [`dstu_core::crypto_secretbox`] for the underlying
//! construction (Kalyna-256/256-GCM, internal nonce, no caller-facing AAD). Keys and sealed blobs
//! cross the PHP boundary as `Binary<u8>` (a real binary string, not UTF-8-validated - see
//! `docs/DECISIONS.md` D-142), matching this project's other bindings' ergonomics rather than an
//! opaque handle type - `dstu_core::crypto_secretbox::SecretKey`'s own `Zeroize`-on-drop guarantee
//! does not carry across the FFI boundary into a PHP string regardless of wrapper shape, so there
//! is nothing an opaque type would additionally buy here.

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_secretbox::{open, seal, SecretKey};

/// Generates a fresh 32-byte `crypto_secretbox` key from the OS CSPRNG.
#[php_function]
pub fn dstu_core_secretbox_keygen() -> Result<Binary<u8>, PhpException> {
    let key = SecretKey::generate().dstu()?;
    Ok(Binary::from(key.as_bytes().to_vec()))
}

/// Encrypts and authenticates `plaintext` under `key`. Returns `nonce || ciphertext || tag`.
#[php_function]
pub fn dstu_core_secretbox_seal(
    key: Binary<u8>,
    plaintext: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = SecretKey::from_bytes(to_array::<32>(&key, "key")?);
    let sealed = seal(&key, &plaintext).dstu()?;
    Ok(Binary::from(sealed))
}

/// Verifies and decrypts `sealed` (as produced by [`dstu_core_secretbox_seal`]) under `key`.
/// Throws `DstuCoreException` if authentication fails or `sealed` is too short to be valid.
#[php_function]
pub fn dstu_core_secretbox_open(
    key: Binary<u8>,
    sealed: Binary<u8>,
) -> Result<Binary<u8>, PhpException> {
    let key = SecretKey::from_bytes(to_array::<32>(&key, "key")?);
    let plaintext = open(&key, &sealed).dstu()?;
    Ok(Binary::from(plaintext))
}

/// Registers this module's functions - `wrap_function!()` needs its argument textually in the
/// same module as the `#[php_function]` it names (the generated companion metadata item is
/// private), so each `crypto_*` module registers its own functions rather than `lib.rs` doing it
/// for every module from one place.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_secretbox_keygen))
        .function(wrap_function!(dstu_core_secretbox_seal))
        .function(wrap_function!(dstu_core_secretbox_open))
}
