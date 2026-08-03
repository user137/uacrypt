//! `crypto_pwhash` wrapper - see [`dstu_core::crypto_pwhash`] (Argon2id, the one deliberately
//! non-DSTU component). `strength` is the ordinal of the Java-side `PwhashStrength` enum
//! (`INTERACTIVE`=0, `MODERATE`=1, `SENSITIVE`=2), mirroring
//! [`dstu_core::crypto_pwhash::Strength`]'s three named presets.

use crate::util::{guard, Failure};
use dstu_core::crypto_pwhash::{hash_password, verify_password, Strength};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use std::ptr;

fn strength_from_ordinal(strength: jint) -> Result<Strength, Failure> {
    match strength {
        0 => Ok(Strength::Interactive),
        1 => Ok(Strength::Moderate),
        2 => Ok(Strength::Sensitive),
        _ => Err(Failure::Misuse(format!(
            "unrecognized PwhashStrength ordinal: {strength}"
        ))),
    }
}

/// Hashes `password` into a self-describing PHC string, using a fresh random salt. `strength` is
/// a `PwhashStrength` ordinal (see the module doc).
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Pwhash_nativeHashPassword<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    password: JByteArray<'local>,
    strength: jint,
) -> jstring {
    guard(&mut env, ptr::null_mut(), |env| {
        let password_bytes = env.convert_byte_array(&password).expect("convert password");
        let strength = strength_from_ordinal(strength)?;
        let phc =
            hash_password(&password_bytes, strength).map_err(|e| Failure::Crypto(e.to_string()))?;
        Ok(env.new_string(phc).expect("new_string").into_raw())
    })
}

/// Verifies `password` against a PHC string produced by `hashPassword`. Returns `false` for both
/// a wrong password and a malformed hash string.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Pwhash_verifyPassword<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    password: JByteArray<'local>,
    hash: JString<'local>,
) -> jboolean {
    guard(&mut env, JNI_FALSE, |env| {
        let password_bytes = env.convert_byte_array(&password).expect("convert password");
        let hash: String = env.get_string(&hash).expect("get_string hash").into();
        Ok(if verify_password(&password_bytes, &hash) {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    })
}
