//! `crypto_generichash` wrapper - see [`dstu_core::crypto_generichash`] (Kupyna-256/512). One-shot
//! functions for a whole in-memory message, plus incremental `*Hasher` classes for a large or
//! streamed one - both produce the same digest for the same bytes.
//!
//! The incremental hashers are the first genuinely stateful native object in this crate: unlike
//! every stateless `keygen`/`seal`/`sign` function above, a hasher's Rust state must survive
//! across multiple JNI calls. Python/Node/Ruby get this for free from `#[pyclass]`/`#[napi]`/
//! `#[magnus::wrap]`'s own generated wrapper object; plain `jni` has no such macro, so the state
//! is boxed and handed to Java as an opaque `long` handle (`Box::into_raw`/`Box::from_raw`) -
//! Java's own equivalent of T-52/D-152's `SafeHandle`, just hand-rolled instead of framework-
//! provided.

use crate::util::{guard, Failure};
use dstu_core::crypto_generichash as core;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jlong};
use jni::JNIEnv;
use std::ptr as std_ptr;

/// Computes the 32-byte Kupyna-256 digest of `message`.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_GenericHash_hash256<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    message: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let message_bytes = env.convert_byte_array(&message).expect("convert message");
        let digest = core::Kupyna256::digest(&message_bytes);
        Ok(env
            .byte_array_from_slice(&digest)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Computes the 64-byte Kupyna-512 digest of `message`.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_GenericHash_hash512<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    message: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let message_bytes = env.convert_byte_array(&message).expect("convert message");
        let digest = core::Kupyna512::digest(&message_bytes);
        Ok(env
            .byte_array_from_slice(&digest)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

macro_rules! incremental_hasher {
    ($create:ident, $update:ident, $finalize:ident, $free:ident, $inner:ty) => {
        #[no_mangle]
        pub extern "system" fn $create<'local>(
            _env: JNIEnv<'local>,
            _class: JClass<'local>,
        ) -> jlong {
            let boxed: Box<Option<$inner>> = Box::new(Some(<$inner>::new()));
            Box::into_raw(boxed) as jlong
        }

        #[no_mangle]
        pub extern "system" fn $update<'local>(
            mut env: JNIEnv<'local>,
            _class: JClass<'local>,
            handle: jlong,
            data: JByteArray<'local>,
        ) {
            guard(&mut env, (), |env| {
                let data_bytes = env.convert_byte_array(&data).expect("convert data");
                let hasher_opt = unsafe { &mut *(handle as *mut Option<$inner>) };
                match hasher_opt {
                    Some(hasher) => {
                        hasher.update(&data_bytes);
                        Ok(())
                    }
                    None => Err(Failure::State("hasher already finalized".to_string())),
                }
            })
        }

        #[no_mangle]
        pub extern "system" fn $finalize<'local>(
            mut env: JNIEnv<'local>,
            _class: JClass<'local>,
            handle: jlong,
        ) -> jbyteArray {
            guard(&mut env, std_ptr::null_mut(), |env| {
                let hasher_opt = unsafe { &mut *(handle as *mut Option<$inner>) };
                match hasher_opt.take() {
                    Some(hasher) => Ok(env
                        .byte_array_from_slice(&hasher.finalize())
                        .expect("byte_array_from_slice")
                        .into_raw()),
                    None => Err(Failure::State("hasher already finalized".to_string())),
                }
            })
        }

        #[no_mangle]
        pub extern "system" fn $free<'local>(
            _env: JNIEnv<'local>,
            _class: JClass<'local>,
            handle: jlong,
        ) {
            if handle != 0 {
                unsafe {
                    drop(Box::from_raw(handle as *mut Option<$inner>));
                }
            }
        }
    };
}

incremental_hasher!(
    Java_ua_dstucrypto_dstucore_Kupyna256Hasher_nativeCreate,
    Java_ua_dstucrypto_dstucore_Kupyna256Hasher_nativeUpdate,
    Java_ua_dstucrypto_dstucore_Kupyna256Hasher_nativeFinalize,
    Java_ua_dstucrypto_dstucore_Kupyna256Hasher_nativeFree,
    core::Kupyna256Hasher
);

incremental_hasher!(
    Java_ua_dstucrypto_dstucore_Kupyna512Hasher_nativeCreate,
    Java_ua_dstucrypto_dstucore_Kupyna512Hasher_nativeUpdate,
    Java_ua_dstucrypto_dstucore_Kupyna512Hasher_nativeFinalize,
    Java_ua_dstucrypto_dstucore_Kupyna512Hasher_nativeFree,
    core::Kupyna512Hasher
);
