//! `crypto_kdf` wrapper - see [`dstu_core::crypto_kdf`] (Kupyna-256-KDF).

use crate::util::{guard, to_array, IntoCrypto};
use dstu_core::crypto_kdf::MasterKey;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jlong};
use jni::JNIEnv;
use std::ptr;

/// Generates a fresh 32-byte `crypto_kdf` master key from the OS CSPRNG.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Kdf_keygen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key = MasterKey::generate().crypto()?;
        Ok(env
            .byte_array_from_slice(key.as_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Derives a 32-byte subkey from `masterKey`. `context` must be exactly 8 bytes.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Kdf_deriveSubkey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    master_key: JByteArray<'local>,
    subkey_id: jlong,
    context: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let master_key_bytes = env
            .convert_byte_array(&master_key)
            .expect("convert master_key");
        let context_bytes = env.convert_byte_array(&context).expect("convert context");
        let master_key = MasterKey::from_bytes(to_array::<32>(&master_key_bytes, "masterKey")?);
        let context = to_array::<8>(&context_bytes, "context")?;
        let subkey = master_key.derive_subkey(subkey_id as u64, &context);
        Ok(env
            .byte_array_from_slice(&subkey)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}
