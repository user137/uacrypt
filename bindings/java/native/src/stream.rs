//! `crypto_stream` wrapper - see [`dstu_core::crypto_stream`] (Strumok-256 keystream, internal
//! IV). **No authentication** - `decrypt` never fails on tampered input, it returns different,
//! silently-wrong plaintext instead (inherited from the wrapped construction). Prefer
//! [`crate::secretbox`]/[`crate::secretstream`] unless integrity is handled elsewhere. Named
//! `StreamCipher` on the Java side (not `Stream`) to avoid colliding with `java.util.stream.Stream`
//! - same reasoning as T-52/D-152's `StreamCipherKey`.

use crate::util::{guard, to_array, IntoCrypto};
use dstu_core::crypto_stream::{decrypt, encrypt, Key};
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use std::ptr;

/// Generates a fresh 32-byte `crypto_stream` key from the OS CSPRNG.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_StreamCipher_keygen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key = Key::generate().crypto()?;
        Ok(env
            .byte_array_from_slice(key.as_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// XORs `plaintext` with a fresh keystream under `key`, drawing a random IV internally. Returns
/// `iv || ciphertext`. No authentication - see the module doc.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_StreamCipher_encrypt<'local>(
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
        let key = Key::from_bytes(to_array::<32>(&key_bytes, "key")?);
        let sealed = encrypt(&key, &plaintext_bytes).crypto()?;
        Ok(env
            .byte_array_from_slice(&sealed)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Reverses `encrypt` under `key`. Throws `DstuException` only if `sealed` is too short to
/// contain an IV - a tampered `sealed` decrypts to different, silently-wrong plaintext, not an
/// error (see the module doc).
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_StreamCipher_decrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    sealed: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let sealed_bytes = env.convert_byte_array(&sealed).expect("convert sealed");
        let key = Key::from_bytes(to_array::<32>(&key_bytes, "key")?);
        let plaintext = decrypt(&key, &sealed_bytes).crypto()?;
        Ok(env
            .byte_array_from_slice(&plaintext)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}
