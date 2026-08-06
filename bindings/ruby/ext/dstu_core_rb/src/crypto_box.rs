//! `crypto_box` wrapper - see [`dstu_core::crypto_box`] for the underlying hybrid-via-KDF
//! construction over `hazmat::dstu9041` (D-169). Named `crypto_box.rs`, not `box.rs` like every
//! sibling module drops its `crypto_` prefix (`secretbox.rs`, `sign.rs`, `stream.rs`) - `box`
//! alone is a reserved Rust keyword. Keys/sealed blobs cross the Ruby boundary as plain `String`
//! (binary), matching every other wrapper in this crate - `SecretKey`'s `Zeroize`-on-drop
//! guarantee does not carry across the FFI boundary into a Ruby `String` regardless of wrapper
//! shape, so there is nothing an opaque type would additionally buy here (same reasoning as
//! `secretbox.rs`'s own module doc).

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_box::{open, seal, PublicKey, SecretKey};
use magnus::{Error, RString, Ruby};

fn secret_key_from_bytes(ruby: &Ruby, bytes: &[u8]) -> Result<SecretKey, Error> {
    let e = to_array::<32>(ruby, bytes, "secret_key")?;
    SecretKey::from_bytes(&e).ok_or_else(|| {
        Error::new(
            ruby.exception_arg_error(),
            "invalid secret key: must be in the range {2, ..., n-2}",
        )
    })
}

fn public_key_from_bytes(ruby: &Ruby, bytes: &[u8]) -> Result<PublicKey, Error> {
    let x = to_array::<32>(ruby, bytes, "public_key")?;
    PublicKey::from_bytes(&x).ok_or_else(|| {
        Error::new(
            ruby.exception_arg_error(),
            "invalid public key: not a valid field element, or not in the base point's subgroup",
        )
    })
}

/// Generates a fresh 32-byte `crypto_box` secret key from the OS CSPRNG.
pub fn box_keygen(ruby: &Ruby) -> Result<RString, Error> {
    let key = SecretKey::generate().dstu(ruby)?;
    Ok(ruby.str_from_slice(&key.to_bytes()))
}

/// Derives the 32-byte public key for `secret_key` - safe to share/publish (the curve point's
/// `x`-coordinate only, see `dstu_core::crypto_box`'s own module doc for why this is a safe
/// compression).
pub fn box_public_key(ruby: &Ruby, secret_key: RString) -> Result<RString, Error> {
    let key = secret_key_from_bytes(ruby, &secret_key.to_bytes())?;
    Ok(ruby.str_from_slice(&key.public_key().to_bytes()))
}

/// Encrypts `message` (any length) to the holder of `public_key`, drawing a fresh random seed and
/// ephemeral key internally. Not memory-bounded - the whole message is held in memory, matching
/// `uacrypt box-seal`'s own documented limitation.
pub fn box_seal(ruby: &Ruby, public_key: RString, message: RString) -> Result<RString, Error> {
    let key = public_key_from_bytes(ruby, &public_key.to_bytes())?;
    let sealed = seal(&message.to_bytes(), &key).dstu(ruby)?;
    Ok(ruby.str_from_slice(&sealed))
}

/// Decrypts `sealed` (as produced by [`box_seal`]) under `secret_key`. Raises `DstuCore::Error`
/// if authentication fails (wrong key, or any tampered wire segment - deliberately not
/// distinguished further, see `dstu_core::crypto_box::OpenError`'s own doc comment) or `sealed`
/// is too short to be valid.
pub fn box_open(ruby: &Ruby, secret_key: RString, sealed: RString) -> Result<RString, Error> {
    let key = secret_key_from_bytes(ruby, &secret_key.to_bytes())?;
    let plaintext = open(&sealed.to_bytes(), &key).dstu(ruby)?;
    Ok(ruby.str_from_slice(&plaintext))
}
