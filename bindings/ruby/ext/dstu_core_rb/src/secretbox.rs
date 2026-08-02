//! `crypto_secretbox` wrapper - see [`dstu_core::crypto_secretbox`] for the underlying
//! construction (Kalyna-256/256-GCM, internal nonce, no caller-facing AAD). Keys and sealed blobs
//! cross the Ruby boundary as plain `String` (binary), matching this project's other bindings'
//! ergonomics rather than an opaque handle type - `dstu_core::crypto_secretbox::SecretKey`'s own
//! `Zeroize`-on-drop guarantee does not carry across the FFI boundary into a Ruby `String` object
//! regardless of wrapper shape, so there is nothing an opaque type would additionally buy here.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_secretbox::{open, seal, SecretKey};
use magnus::{Error, RString, Ruby};

/// Generates a fresh 32-byte `crypto_secretbox` key from the OS CSPRNG.
pub fn secretbox_keygen(ruby: &Ruby) -> Result<RString, Error> {
    let key = SecretKey::generate().dstu(ruby)?;
    Ok(ruby.str_from_slice(key.as_bytes()))
}

/// Encrypts and authenticates `plaintext` under `key`. Returns `nonce || ciphertext || tag`.
pub fn secretbox_seal(ruby: &Ruby, key: RString, plaintext: RString) -> Result<RString, Error> {
    let key = SecretKey::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
    let sealed = seal(&key, &plaintext.to_bytes()).dstu(ruby)?;
    Ok(ruby.str_from_slice(&sealed))
}

/// Verifies and decrypts `sealed` (as produced by [`secretbox_seal`]) under `key`. Raises
/// `DstuCore::Error` if authentication fails or `sealed` is too short to be valid.
pub fn secretbox_open(ruby: &Ruby, key: RString, sealed: RString) -> Result<RString, Error> {
    let key = SecretKey::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
    let plaintext = open(&key, &sealed.to_bytes()).dstu(ruby)?;
    Ok(ruby.str_from_slice(&plaintext))
}
