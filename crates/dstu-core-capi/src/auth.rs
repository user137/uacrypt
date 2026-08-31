//! `crypto_auth` C ABI (`dstu_core::crypto_auth`) - MAC compute/verify under a 32-byte key.
//! `dstu_auth` is infallible (the key's fixed length forecloses `hazmat`'s `WrongKeyLength` case,
//! see the wrapped module's own doc comment); `dstu_auth_verify` fails only on tag mismatch, so it
//! keeps a `DstuStatus` return rather than plain `bool` (matches D-148's own "verify" naming
//! carve-out).

use crate::error::DstuStatus;
use crate::util::{guard_ptr, guard_status, guard_void, slice_from_raw};
use dstu_core::crypto_auth::{verify, Key};

pub const DSTU_AUTH_KEY_BYTES: usize = 32;
pub const DSTU_AUTH_TAG_BYTES: usize = 32;

/// Opaque `crypto_auth` key handle. `dstu_auth_key_free`'s `Box::from_raw` fires the wrapped
/// `Key`'s own `Zeroize`-on-`Drop` impl.
pub struct DstuAuthKey(Key);

/// Generates a fresh key from the OS CSPRNG. Returns `DSTU_OK` (writing `*out`) or
/// `DSTU_ERR_RANDOM`/`DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `out` must be a valid, non-null pointer to a `*mut DstuAuthKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_auth_key_generate(out: *mut *mut DstuAuthKey) -> DstuStatus {
    guard_status(|| {
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match Key::generate() {
            Ok(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuAuthKey(key))) };
                DstuStatus::DSTU_OK
            }
            Err(_) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Builds a key from exactly `DSTU_AUTH_KEY_BYTES` bytes. Infallible for a correct call; returns
/// NULL if `key` is NULL (a misuse case with no `DstuStatus` channel to report through here).
///
/// # Safety
///
/// `key` must be valid for reads of `DSTU_AUTH_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_auth_key_from_bytes(key: *const u8) -> *mut DstuAuthKey {
    guard_ptr(|| {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        let mut bytes = [0u8; DSTU_AUTH_KEY_BYTES];
        bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(key, DSTU_AUTH_KEY_BYTES) });
        Box::into_raw(Box::new(DstuAuthKey(Key::from_bytes(bytes))))
    })
}

/// Copies the key's `DSTU_AUTH_KEY_BYTES`-byte encoding into `out`. A NULL `key`/`out` is a no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_AUTH_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_auth_key_bytes(key: *const DstuAuthKey, out: *mut u8) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_AUTH_KEY_BYTES) };
        out.copy_from_slice(key.0.as_bytes());
    })
}

/// Frees a key. NULL is a no-op, matching `free()`'s own convention.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by `dstu_auth_key_generate`/
/// `dstu_auth_key_from_bytes`, not already freed - freeing an already-freed pointer is undefined behavior, not merely unsupported; this fn cannot detect or reject it.
#[no_mangle]
pub unsafe extern "C" fn dstu_auth_key_free(key: *mut DstuAuthKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// Computes the MAC of `message` under `key` - infallible. A NULL `key`/`tag_out`, or a NULL
/// `message` with `message_len > 0`, is a no-op (leaves `tag_out` unwritten).
///
/// # Safety
///
/// `message` must be valid for reads of `message_len` bytes when non-null and `message_len > 0`;
/// `tag_out` must be valid for writes of `DSTU_AUTH_TAG_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_auth(
    key: *const DstuAuthKey,
    message: *const u8,
    message_len: usize,
    tag_out: *mut u8,
) {
    guard_void(|| {
        if key.is_null() || tag_out.is_null() {
            return;
        }
        let Some(message) = (unsafe { slice_from_raw(message, message_len) }) else {
            return;
        };
        let key = unsafe { &*key };
        let tag = dstu_core::crypto_auth::auth(&key.0, message);
        let tag_out = unsafe { std::slice::from_raw_parts_mut(tag_out, DSTU_AUTH_TAG_BYTES) };
        tag_out.copy_from_slice(&tag);
    })
}

/// Verifies `tag` against `message` under `key`. Returns `DSTU_OK` or `DSTU_ERR_TAG_MISMATCH` on
/// an actual verification failure. `DSTU_ERR_NULL_POINTER` for a NULL `key`/`tag`, or a NULL
/// `message` with `message_len > 0` - consistent with this crate's own null-hygiene convention
/// (`lib.rs`'s doc comment): a `DstuStatus` channel exists here, so a NULL pointer is reported
/// through it rather than folded into `DSTU_ERR_TAG_MISMATCH`.
///
/// # Safety
///
/// `message` must be valid for reads of `message_len` bytes when non-null and `message_len > 0`;
/// `tag`, when non-null, must be valid for reads of `DSTU_AUTH_TAG_BYTES` bytes.
#[no_mangle]
pub unsafe extern "C" fn dstu_auth_verify(
    key: *const DstuAuthKey,
    message: *const u8,
    message_len: usize,
    tag: *const u8,
) -> DstuStatus {
    guard_status(|| {
        if key.is_null() || tag.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(message) = (unsafe { slice_from_raw(message, message_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let mut tag_bytes = [0u8; DSTU_AUTH_TAG_BYTES];
        tag_bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(tag, DSTU_AUTH_TAG_BYTES) });
        let key = unsafe { &*key };
        match verify(&key.0, message, &tag_bytes) {
            Ok(()) => DstuStatus::DSTU_OK,
            Err(_) => DstuStatus::DSTU_ERR_TAG_MISMATCH,
        }
    })
}
