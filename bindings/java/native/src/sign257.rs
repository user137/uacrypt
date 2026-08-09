//! `crypto_sign257` wrapper - see [`dstu_core::crypto_sign257`] (DSTU 4145 `m=257`, T-199/T-204),
//! the `m=257` sibling of [`crate::sign`]. Keys are the module's own fixed-length byte encodings: a
//! 33-byte signing key, a 66-byte uncompressed verifying key (`x || y`), a 66-byte signature
//! (`r || s`). No curve-tag byte here - the distinct `Sign257` Java class is the whole dispatch
//! mechanism, matching every other binding's own D-118-driven "no tag sniffing" rule.

use crate::util::{guard, to_array, Failure, IntoCrypto};
use dstu_core::crypto_sign257::{Signature, SigningKey, VerifyingKey};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jboolean, jbyteArray, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use std::ptr;

fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, Failure> {
    let d = to_array::<33>(bytes, "signingKey")?;
    SigningKey::from_bytes(&d).ok_or_else(|| {
        Failure::Misuse(
            "invalid signing key: must be nonzero and less than the curve order".to_string(),
        )
    })
}

/// Generates a fresh 33-byte signing key from the OS CSPRNG, uniform over the valid key range via
/// rejection sampling.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Sign257_keygen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key = SigningKey::generate().crypto()?;
        Ok(env
            .byte_array_from_slice(&key.to_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Derives the 66-byte public verifying key for `signingKey` - safe to share/publish.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Sign257_verifyingKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    signing_key: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let signing_key_bytes = env
            .convert_byte_array(&signing_key)
            .expect("convert signingKey");
        let key = signing_key_from_bytes(&signing_key_bytes)?;
        Ok(env
            .byte_array_from_slice(&key.verifying_key().to_uncompressed_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Signs `message` under `signingKey`, hashing it with Kupyna-256 and deriving the ephemeral
/// nonce deterministically. Returns a 66-byte signature.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Sign257_sign<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    signing_key: JByteArray<'local>,
    message: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let signing_key_bytes = env
            .convert_byte_array(&signing_key)
            .expect("convert signingKey");
        let message_bytes = env.convert_byte_array(&message).expect("convert message");
        let key = signing_key_from_bytes(&signing_key_bytes)?;
        Ok(env
            .byte_array_from_slice(&key.sign(&message_bytes).to_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Verifies `signature` against `message` under the 66-byte `verifyingKey`. Returns `true`/
/// `false` rather than throwing - matches the wrapped `dstu_core::crypto_sign257` API.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Sign257_verify<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    verifying_key: JByteArray<'local>,
    message: JByteArray<'local>,
    signature: JByteArray<'local>,
) -> jboolean {
    guard(&mut env, JNI_FALSE, |env| {
        let verifying_key_bytes = env
            .convert_byte_array(&verifying_key)
            .expect("convert verifyingKey");
        let message_bytes = env.convert_byte_array(&message).expect("convert message");
        let signature_bytes = env
            .convert_byte_array(&signature)
            .expect("convert signature");
        let verifying_key_bytes = to_array::<66>(&verifying_key_bytes, "verifyingKey")?;
        let key = VerifyingKey::from_uncompressed_bytes(&verifying_key_bytes);
        let signature_bytes = to_array::<66>(&signature_bytes, "signature")?;
        let signature = Signature::from_bytes(&signature_bytes);
        Ok(if key.verify(&message_bytes, &signature) {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    })
}
