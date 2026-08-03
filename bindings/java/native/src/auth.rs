//! `crypto_auth` wrapper - see [`dstu_core::crypto_auth`] (Kupyna-256-KMAC).

use crate::util::{guard, to_array, IntoCrypto};
use dstu_core::crypto_auth::{auth as core_auth, verify, Key};
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use std::ptr;

/// Generates a fresh 32-byte `crypto_auth` key from the OS CSPRNG.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Auth_keygen<'local>(
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

/// Computes the 32-byte MAC of `message` under `key`.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Auth_auth<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    message: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let message_bytes = env.convert_byte_array(&message).expect("convert message");
        let key = Key::from_bytes(to_array::<32>(&key_bytes, "key")?);
        let tag = core_auth(&key, &message_bytes);
        Ok(env
            .byte_array_from_slice(&tag)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Verifies `tag` against `message` under `key`. Throws `DstuException` if the tag does not
/// match.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Auth_verify<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    message: JByteArray<'local>,
    tag: JByteArray<'local>,
) {
    guard(&mut env, (), |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let message_bytes = env.convert_byte_array(&message).expect("convert message");
        let tag_bytes = env.convert_byte_array(&tag).expect("convert tag");
        let key = Key::from_bytes(to_array::<32>(&key_bytes, "key")?);
        let tag = to_array::<32>(&tag_bytes, "tag")?;
        verify(&key, &message_bytes, &tag).crypto()
    })
}
