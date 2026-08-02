//! `crypto_stream` C ABI (`dstu_core::crypto_stream`) - Strumok256 keystream, confidentiality
//! only. **No authentication whatsoever**: `dstu_stream_decrypt` never fails on tampered input -
//! it has no tag to check, so a modified `sealed` value decrypts to different, silently-wrong
//! plaintext instead of an error (see the wrapped Rust module's own doc comment). Prefer
//! `crypto_secretbox`/`crypto_secretstream` unless a bare keystream cipher with the caller
//! handling authentication itself is specifically what's needed.

use crate::error::DstuStatus;
use crate::util::{guard_ptr, guard_status, guard_void, slice_from_raw, slice_from_raw_mut};
use dstu_core::crypto_stream::{decrypt, encrypt, Key, StreamError};

pub const DSTU_STREAM_KEY_BYTES: usize = 32;
/// IV only - no tag, this primitive is unauthenticated by design.
pub const DSTU_STREAM_OVERHEAD: usize = 32;

/// Opaque `crypto_stream` key handle. `dstu_stream_key_free`'s `Box::from_raw` fires the wrapped
/// `Key`'s own `Zeroize`-on-`Drop` impl.
pub struct DstuStreamKey(Key);

/// Generates a fresh key from the OS CSPRNG. Returns `DSTU_OK` (writing `*out`) or
/// `DSTU_ERR_RANDOM`/`DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `out` must be a valid, non-null pointer to a `*mut DstuStreamKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_stream_key_generate(out: *mut *mut DstuStreamKey) -> DstuStatus {
    guard_status(|| {
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match Key::generate() {
            Ok(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuStreamKey(key))) };
                DstuStatus::DSTU_OK
            }
            Err(_) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Builds a key from exactly `DSTU_STREAM_KEY_BYTES` bytes. Infallible for a correct call;
/// returns NULL if `key` is NULL.
///
/// # Safety
///
/// `key` must be valid for reads of `DSTU_STREAM_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_stream_key_from_bytes(key: *const u8) -> *mut DstuStreamKey {
    guard_ptr(|| {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        let mut bytes = [0u8; DSTU_STREAM_KEY_BYTES];
        bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(key, DSTU_STREAM_KEY_BYTES) });
        Box::into_raw(Box::new(DstuStreamKey(Key::from_bytes(bytes))))
    })
}

/// Copies the key's `DSTU_STREAM_KEY_BYTES`-byte encoding into `out`. A NULL `key`/`out` is a
/// no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_STREAM_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_stream_key_bytes(key: *const DstuStreamKey, out: *mut u8) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_STREAM_KEY_BYTES) };
        out.copy_from_slice(key.0.as_bytes());
    })
}

/// Frees a key. NULL is a no-op.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by `dstu_stream_key_generate`/
/// `dstu_stream_key_from_bytes`, not already freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_stream_key_free(key: *mut DstuStreamKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// XORs `plaintext` with a fresh keystream under `key`, drawing a random IV internally.
/// `sealed_out` must have capacity >= `plaintext_len + DSTU_STREAM_OVERHEAD` - checked before any
/// crypto work runs; `DSTU_ERR_BUFFER_TOO_SMALL` if not.
///
/// # Safety
///
/// `key`/`sealed_len_out` must be non-null; `plaintext` must be valid for reads of
/// `plaintext_len` bytes when non-null and `plaintext_len > 0`; `sealed_out` must be valid for
/// writes of `sealed_out_cap` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_stream_encrypt(
    key: *const DstuStreamKey,
    plaintext: *const u8,
    plaintext_len: usize,
    sealed_out: *mut u8,
    sealed_out_cap: usize,
    sealed_len_out: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if key.is_null() || sealed_len_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(plaintext) = (unsafe { slice_from_raw(plaintext, plaintext_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let required = plaintext_len + DSTU_STREAM_OVERHEAD;
        if sealed_out_cap < required {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        let Some(sealed_out) = (unsafe { slice_from_raw_mut(sealed_out, sealed_out_cap) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let key = unsafe { &*key };
        match encrypt(&key.0, plaintext) {
            Ok(sealed) => {
                sealed_out[..sealed.len()].copy_from_slice(&sealed);
                unsafe { *sealed_len_out = sealed.len() };
                DstuStatus::DSTU_OK
            }
            Err(StreamError::Random(_)) => DstuStatus::DSTU_ERR_RANDOM,
            Err(StreamError::Truncated) => unreachable!("encrypt() never returns Truncated"),
        }
    })
}

/// Reverses [`dstu_stream_encrypt`]. `sealed_len < DSTU_STREAM_OVERHEAD` -> `DSTU_ERR_TRUNCATED`
/// (the only possible error - there is no tag to fail). `plaintext_out` must have capacity >=
/// `sealed_len - DSTU_STREAM_OVERHEAD` - checked before any work runs; `DSTU_ERR_BUFFER_TOO_SMALL`
/// if not. **Never fails on tampered input** - a modified `sealed` decrypts to different,
/// silently-wrong plaintext, not an error.
///
/// # Safety
///
/// `key`/`plaintext_len_out` must be non-null; `sealed` must be valid for reads of `sealed_len`
/// bytes when non-null and `sealed_len > 0`; `plaintext_out` must be valid for writes of
/// `plaintext_out_cap` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_stream_decrypt(
    key: *const DstuStreamKey,
    sealed: *const u8,
    sealed_len: usize,
    plaintext_out: *mut u8,
    plaintext_out_cap: usize,
    plaintext_len_out: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if key.is_null() || plaintext_len_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(sealed) = (unsafe { slice_from_raw(sealed, sealed_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        if sealed_len < DSTU_STREAM_OVERHEAD {
            return DstuStatus::DSTU_ERR_TRUNCATED;
        }
        let required = sealed_len - DSTU_STREAM_OVERHEAD;
        if plaintext_out_cap < required {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        let Some(plaintext_out) = (unsafe { slice_from_raw_mut(plaintext_out, plaintext_out_cap) })
        else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let key = unsafe { &*key };
        match decrypt(&key.0, sealed) {
            Ok(plaintext) => {
                plaintext_out[..plaintext.len()].copy_from_slice(&plaintext);
                unsafe { *plaintext_len_out = plaintext.len() };
                DstuStatus::DSTU_OK
            }
            Err(StreamError::Truncated) => unreachable!("checked sealed_len above"),
            Err(StreamError::Random(_)) => unreachable!("decrypt() never generates randomness"),
        }
    })
}
