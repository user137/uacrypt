//! `randombytes` wrapper - see [`dstu_core::randombytes`] (OS CSPRNG via `getrandom`).

use crate::util::{guard, IntoCrypto};
use jni::objects::JClass;
use jni::sys::{jbyteArray, jint};
use jni::JNIEnv;
use std::ptr;

/// Returns `size` cryptographically secure random bytes from the OS CSPRNG.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_RandomBytes_buf<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    size: jint,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        if size < 0 {
            return Err(crate::util::Failure::Misuse(
                "size must not be negative".to_string(),
            ));
        }
        let mut buf = vec![0u8; size as usize];
        dstu_core::randombytes::randombytes_buf(&mut buf).crypto()?;
        Ok(env
            .byte_array_from_slice(&buf)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}
