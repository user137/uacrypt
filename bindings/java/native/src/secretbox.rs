//! `crypto_secretbox` wrapper - see [`dstu_core::crypto_secretbox`] (Kalyna-256/256-GCM, internal
//! nonce, no caller-facing AAD). Keys and sealed blobs cross the boundary as plain `byte[]`,
//! matching Python/Node's own ergonomics - `SecretKey`'s `Zeroize`-on-drop guarantee does not
//! survive the FFI boundary into a Java `byte[]` regardless of wrapper shape, so an opaque handle
//! type would buy nothing extra here (same reasoning `bindings/python/src/secretbox.rs` already
//! recorded).

use crate::util::{guard, to_array, IntoCrypto};
use dstu_core::crypto_secretbox::{open, seal, SecretKey};
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use std::ptr;

/// Generates a fresh 32-byte `crypto_secretbox` key from the OS CSPRNG.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretBox_keygen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key = SecretKey::generate().crypto()?;
        Ok(env
            .byte_array_from_slice(key.as_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Encrypts and authenticates `plaintext` under `key`. Returns `nonce || ciphertext || tag`.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretBox_seal<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let plaintext_bytes = env
            .convert_byte_array(&plaintext)
            .expect("convert plaintext");
        let key = SecretKey::from_bytes(to_array::<32>(&key_bytes, "key")?);
        let sealed = seal(&key, &plaintext_bytes).crypto()?;
        Ok(env
            .byte_array_from_slice(&sealed)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Verifies and decrypts `sealed` (as produced by `seal`) under `key`. Throws `DstuException` if
/// authentication fails or `sealed` is too short to be valid.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretBox_open<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    sealed: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let sealed_bytes = env.convert_byte_array(&sealed).expect("convert sealed");
        let key = SecretKey::from_bytes(to_array::<32>(&key_bytes, "key")?);
        let plaintext = open(&key, &sealed_bytes).crypto()?;
        Ok(env
            .byte_array_from_slice(&plaintext)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}
