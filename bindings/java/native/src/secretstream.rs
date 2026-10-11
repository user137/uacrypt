//! `crypto_secretstream` wrapper - see [`dstu_core::crypto_secretstream`] for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (matching `bindings/python/src/secretstream.rs`'s own step-2
//! split); the idiomatic `InputStream`/`OutputStream` pair uses the codec functions below.
//!
//! JNI has no native multi-value return, so `push`/`pull` each concatenate their two logical
//! outputs into one `byte[]`: `push` returns `ciphertext || authTag` (the 16-byte tag is a fixed,
//! known length, so the Java side splits it back out); `pull` returns `tagByte(1) || plaintext`.
//!
//! Also the stream-file codec classes (T-284, D-235): the idiomatic stream wrapper drives
//! `FileEncryptor`/`FileDecryptor` through them and does only I/O; it no longer parses the
//! file format itself.

use crate::util::{guard, to_array, Failure, IntoCrypto};
use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, Key, PullState, PushState, Tag, CHUNK_BYTES, FILE_PREFIX_BYTES,
    MAX_RECORD_BYTES,
};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jboolean, jbyteArray, jint, jlong, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use std::ptr as std_ptr;

// `dstu_core::crypto_secretstream`'s own `TAG_LEN` const is private to that module - matches
// `bindings/python/python/dstu_core/secretstream.py`'s own hardcoded `_AUTH_TAG_BYTES = 16`,
// not an independent choice.
const TAG_LEN: usize = 16;

fn tag_from_byte(byte: u8) -> Result<Tag, Failure> {
    Tag::from_byte(byte)
        .ok_or_else(|| Failure::Misuse("unrecognized secretstream tag byte".to_string()))
}

/// Generates a fresh 32-byte `crypto_secretstream` master key from the OS CSPRNG.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStream_keygen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let key = Key::generate().map_err(|e| Failure::Crypto(e.to_string()))?;
        Ok(env
            .byte_array_from_slice(key.as_bytes())
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

type PushHandle = (PushState, [u8; 32]);

/// Starts a new encrypting stream under `key`. The header must be transmitted/stored alongside
/// the encrypted chunks - a `SecretStreamPullState` needs it to decrypt them.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPushState_nativeInit<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
) -> jlong {
    guard(&mut env, 0, |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let key = Key::from_bytes(to_array::<32>(&key_bytes, "key")?);
        let (state, header) = PushState::init(&key).map_err(|e| Failure::Crypto(e.to_string()))?;
        let boxed: Box<PushHandle> = Box::new((state, header));
        Ok(Box::into_raw(boxed) as jlong)
    })
}

/// Returns this push state's 32-byte header.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPushState_nativeHeader<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let (_, header) = unsafe { &*(handle as *const PushHandle) };
        Ok(env
            .byte_array_from_slice(header)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPushState_nativeIsFinalized<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    guard(&mut env, JNI_FALSE, |_env| {
        let (state, _) = unsafe { &*(handle as *const PushHandle) };
        Ok(if state.is_finalized() {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    })
}

/// Encrypts `plaintext` and returns `ciphertext || authTag` (the trailing 16 bytes are the tag).
/// `tagByte` must be one of the `SecretStreamTag` ordinal-matching wire values; the caller must
/// transmit `ciphertext`, `authTag`, and `tagByte` itself for a `SecretStreamPullState` to recover
/// the plaintext.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPushState_nativePush<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    tag_byte: jint,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let plaintext_bytes = env
            .convert_byte_array(&plaintext)
            .expect("convert plaintext");
        let tag = tag_from_byte(tag_byte as u8)?;
        let (state, _) = unsafe { &mut *(handle as *mut PushHandle) };
        let mut ciphertext = vec![0u8; plaintext_bytes.len()];
        let auth_tag = state
            .push(tag, &plaintext_bytes, &mut ciphertext)
            .map_err(|e| Failure::Crypto(e.to_string()))?;
        let mut out = ciphertext;
        out.extend_from_slice(&auth_tag);
        Ok(env
            .byte_array_from_slice(&out)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPushState_nativeFree<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            drop(Box::from_raw(handle as *mut PushHandle));
        }
    }
}

/// Re-derives the stream's initial subkey from `key` and `header` (as produced by
/// `SecretStreamPushState.header()`).
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPullState_nativeInit<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    header: JByteArray<'local>,
) -> jlong {
    guard(&mut env, 0, |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let header_bytes = env.convert_byte_array(&header).expect("convert header");
        let key = Key::from_bytes(to_array::<32>(&key_bytes, "key")?);
        let header = to_array::<32>(&header_bytes, "header")?;
        let state = PullState::init(&key, &header);
        Ok(Box::into_raw(Box::new(state)) as jlong)
    })
}

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPullState_nativeIsFinalized<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    guard(&mut env, JNI_FALSE, |_env| {
        let state = unsafe { &*(handle as *const PullState) };
        Ok(if state.is_finalized() {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    })
}

/// Verifies and decrypts one chunk. Returns `tagByte(1) || plaintext`. Throws `DstuException` if
/// authentication fails - a tampered, reordered, dropped, or spliced-from-another-stream chunk
/// all fail here rather than returning wrong plaintext.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPullState_nativePull<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    tag_byte: jint,
    ciphertext: JByteArray<'local>,
    auth_tag: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let ciphertext_bytes = env
            .convert_byte_array(&ciphertext)
            .expect("convert ciphertext");
        let auth_tag_bytes = env.convert_byte_array(&auth_tag).expect("convert authTag");
        if auth_tag_bytes.len() != TAG_LEN {
            return Err(Failure::Misuse(format!(
                "authTag must be exactly {TAG_LEN} bytes, got {}",
                auth_tag_bytes.len()
            )));
        }
        let state = unsafe { &mut *(handle as *mut PullState) };
        let mut plaintext = vec![0u8; ciphertext_bytes.len()];
        let tag = state
            .pull(
                tag_byte as u8,
                &ciphertext_bytes,
                &auth_tag_bytes,
                &mut plaintext,
            )
            .map_err(|e| Failure::Crypto(e.to_string()))?;
        let mut out = vec![tag.to_byte()];
        out.extend_from_slice(&plaintext);
        Ok(env
            .byte_array_from_slice(&out)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamPullState_nativeFree<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            drop(Box::from_raw(handle as *mut PullState));
        }
    }
}

// --- Stream-file codec (T-284): the D-208 framing from the core, driven by the
// --- SecretStreamEncryptor/SecretStreamDecryptor stream classes, which do only I/O.

fn to_signed(bytes: &[u8]) -> Vec<i8> {
    bytes.iter().map(|&b| b as i8).collect()
}

/// Starts a stream file under `key`, writing the 33-byte prefix into `prefix_out`. Returns the
/// encryptor handle.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamEncryptor_nativeInit<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    prefix_out: JByteArray<'local>,
) -> jlong {
    guard(&mut env, 0, |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let key = Key::from_bytes(to_array::<32>(&key_bytes, "key")?);
        if env.get_array_length(&prefix_out).expect("prefix length") as usize != FILE_PREFIX_BYTES {
            return Err(Failure::Misuse(format!(
                "prefixOut must be exactly {FILE_PREFIX_BYTES} bytes"
            )));
        }
        let (enc, prefix) = FileEncryptor::init(&key).crypto()?;
        env.set_byte_array_region(&prefix_out, 0, &to_signed(&prefix))
            .expect("set prefix");
        Ok(Box::into_raw(Box::new(enc)) as jlong)
    })
}

/// Seals `CHUNK_BYTES` bytes of `src` starting at `offset` as one non-final record. Only that
/// chunk is copied across JNI, so cutting one large array into records stays linear (T-276).
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamEncryptor_nativeSealChunk<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    src: JByteArray<'local>,
    offset: jint,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let src_len = env.get_array_length(&src).expect("src length");
        let in_bounds = offset >= 0 && i64::from(offset) + CHUNK_BYTES as i64 <= i64::from(src_len);
        if !in_bounds {
            return Err(Failure::Misuse(format!(
                "a full {CHUNK_BYTES}-byte chunk must start at offset {offset}"
            )));
        }
        let mut signed = [0i8; CHUNK_BYTES];
        env.get_byte_array_region(&src, offset, &mut signed)
            .expect("get chunk");
        let mut chunk = [0u8; CHUNK_BYTES];
        for (dst, &s) in chunk.iter_mut().zip(signed.iter()) {
            *dst = s as u8;
        }
        let enc = unsafe { &mut *(handle as *mut FileEncryptor) };
        let mut record = [0u8; MAX_RECORD_BYTES];
        enc.seal_chunk(&chunk, &mut record).crypto()?;
        Ok(env
            .byte_array_from_slice(&record)
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// Seals the first `len` bytes of `src` (at most `CHUNK_BYTES`) as the `Final` record.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamEncryptor_nativeSealFinal<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    src: JByteArray<'local>,
    len: jint,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let src_len = env.get_array_length(&src).expect("src length");
        let Ok(n) = usize::try_from(len) else {
            return Err(Failure::Misuse(format!("negative length {len}")));
        };
        if len > src_len || n > CHUNK_BYTES {
            return Err(Failure::Misuse(format!(
                "the last chunk must be at most {CHUNK_BYTES} bytes, got {len}"
            )));
        }
        let mut signed = vec![0i8; n];
        env.get_byte_array_region(&src, 0, &mut signed)
            .expect("get last chunk");
        let last: Vec<u8> = signed.iter().map(|&s| s as u8).collect();
        let enc = unsafe { &mut *(handle as *mut FileEncryptor) };
        let mut record = [0u8; MAX_RECORD_BYTES];
        let written = enc.seal_final(&last, &mut record).crypto()?;
        Ok(env
            .byte_array_from_slice(&record[..written])
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamEncryptor_nativeFree<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            drop(Box::from_raw(handle as *mut FileEncryptor));
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamDecryptor_nativeNew<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
) -> jlong {
    guard(&mut env, 0, |env| {
        let key_bytes = env.convert_byte_array(&key).expect("convert key");
        let key = Key::from_bytes(to_array::<32>(&key_bytes, "key")?);
        Ok(Box::into_raw(Box::new(FileDecryptor::new(&key))) as jlong)
    })
}

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamDecryptor_nativeNextLen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jint {
    guard(&mut env, 0, |_env| {
        let dec = unsafe { &*(handle as *const FileDecryptor) };
        // At most CHUNK_BYTES + 16.
        Ok(jint::try_from(dec.next_len()).unwrap_or(jint::MAX))
    })
}

/// Consumes exactly `nextLen()` bytes; returns the plaintext of a verified non-final record,
/// else an empty array. Throws `DstuException` with the core's message on a format or
/// authentication error.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamDecryptor_nativeFeed<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    data: JByteArray<'local>,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let data = env.convert_byte_array(&data).expect("convert data");
        let dec = unsafe { &mut *(handle as *mut FileDecryptor) };
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = dec.feed(&data, &mut plaintext).crypto()?;
        Ok(env
            .byte_array_from_slice(&plaintext[..n])
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

/// End of input: returns the `Final` chunk's plaintext, or throws if the stream is truncated.
#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamDecryptor_nativeFinish<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    guard(&mut env, std_ptr::null_mut(), |env| {
        let dec = unsafe { &mut *(handle as *mut FileDecryptor) };
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = dec.finish(&mut plaintext).crypto()?;
        Ok(env
            .byte_array_from_slice(&plaintext[..n])
            .expect("byte_array_from_slice")
            .into_raw())
    })
}

#[no_mangle]
pub extern "system" fn Java_ua_dstucrypto_dstucore_SecretStreamDecryptor_nativeFree<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            drop(Box::from_raw(handle as *mut FileDecryptor));
        }
    }
}
