//! `crypto_box512` wrapper - see [`dstu_core::crypto_box512`] (`l(p)=512`/E512/1, T-193/T-204),
//! the direct sibling of [`crate::crypto_box`] at this curve size's own widths. Keys/sealed blobs
//! cross the boundary as plain `byte[]`, matching every other wrapper in this crate. The Java-side
//! class is named `Box512` (no `crypto_` prefix, no underscore - JNI encodes `_` as `_1` in
//! generated symbol names, this binding's own standing convention, `lib.rs`'s doc comment).

use crate::util::{guard, to_array, Failure, IntoCrypto};
use dstu_core::crypto_box512::{open, seal, PublicKey, SecretKey};
use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use std::ptr;

fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey, Failure> {
    let e = to_array::<64>(bytes, "secretKey")?;
    SecretKey::from_bytes(&e).ok_or_else(|| {
        Failure::Misuse("invalid secret key: must be in the range {2, ..., n-2}".to_string())
    })
}

fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, Failure> {
    let x = to_array::<64>(bytes, "publicKey")?;
    PublicKey::from_bytes(&x).ok_or_else(|| {
        Failure::Misuse(
            "invalid public key: not a valid field element, or not in the base point's subgroup"
                .to_string(),
        )
    })
}

/// Generates a fresh 64-byte `crypto_box512` secret key from the OS CSPRNG.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Box512_keygen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let key = SecretKey::generate().crypto()?;
        Ok(env
            .byte_array_from_slice(&key.to_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Derives the 64-byte public key for `secretKey` - safe to share/publish (the curve point's
/// `x`-coordinate only, see `dstu_core::crypto_box512`'s own module doc for why this is a safe
/// compression).
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Box512_publicKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    secret_key: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let secret_key_bytes = env
            .convert_byte_array(&secret_key)
            .expect("convert secretKey");
        let key = secret_key_from_bytes(&secret_key_bytes)?;
        Ok(env
            .byte_array_from_slice(&key.public_key().to_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Encrypts `message` (any length) to the holder of `publicKey`, drawing a fresh random seed and
/// ephemeral key internally. Not memory-bounded - the whole message is held in memory, matching
/// `uacrypt box-seal512`'s own documented limitation.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Box512_seal<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    public_key: JByteArray<'local>,
    message: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let public_key_bytes = env
            .convert_byte_array(&public_key)
            .expect("convert publicKey");
        let message_bytes = env.convert_byte_array(&message).expect("convert message");
        let key = public_key_from_bytes(&public_key_bytes)?;
        let sealed = seal(&message_bytes, &key).crypto()?;
        Ok(env
            .byte_array_from_slice(&sealed)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Decrypts `sealed` (as produced by `seal`) under `secretKey`. Throws `DstuException` if
/// authentication fails (wrong key, or any tampered wire segment - deliberately not distinguished
/// further, see `dstu_core::crypto_box512::OpenError`'s own doc comment) or `sealed` is too short
/// to be valid.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_Box512_open<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    secret_key: JByteArray<'local>,
    sealed: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, ptr::null_mut(), |env| {
        let secret_key_bytes = env
            .convert_byte_array(&secret_key)
            .expect("convert secretKey");
        let sealed_bytes = env.convert_byte_array(&sealed).expect("convert sealed");
        let key = secret_key_from_bytes(&secret_key_bytes)?;
        let plaintext = open(&sealed_bytes, &key).crypto()?;
        Ok(env
            .byte_array_from_slice(&plaintext)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}
