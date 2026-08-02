//! `crypto_stream` wrapper - see [`dstu_core::crypto_stream`] (Strumok-256 keystream, internal
//! IV). **No authentication** - `stream_decrypt` never fails on tampered input, it returns
//! different, silently-wrong plaintext instead (inherited from the wrapped construction). Prefer
//! [`crate::secretbox`]/[`crate::secretstream`] unless integrity is handled elsewhere.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_stream::{decrypt, encrypt, Key};
use magnus::{Error, RString, Ruby};

/// Generates a fresh 32-byte `crypto_stream` key from the OS CSPRNG.
pub fn stream_keygen(ruby: &Ruby) -> Result<RString, Error> {
    let key = Key::generate().dstu(ruby)?;
    Ok(ruby.str_from_slice(key.as_bytes()))
}

/// XORs `plaintext` with a fresh keystream under `key`, drawing a random IV internally. Returns
/// `iv || ciphertext`. No authentication - see the module doc.
pub fn stream_encrypt(ruby: &Ruby, key: RString, plaintext: RString) -> Result<RString, Error> {
    let key = Key::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
    let sealed = encrypt(&key, &plaintext.to_bytes()).dstu(ruby)?;
    Ok(ruby.str_from_slice(&sealed))
}

/// Reverses [`stream_encrypt`] under `key`. Raises `DstuCore::Error` only if `sealed` is too short
/// to contain an IV - a tampered `sealed` decrypts to different, silently-wrong plaintext, not an
/// error (see the module doc).
pub fn stream_decrypt(ruby: &Ruby, key: RString, sealed: RString) -> Result<RString, Error> {
    let key = Key::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
    let plaintext = decrypt(&key, &sealed.to_bytes()).dstu(ruby)?;
    Ok(ruby.str_from_slice(&plaintext))
}
