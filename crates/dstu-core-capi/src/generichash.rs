//! `crypto_generichash` C ABI (`dstu_core::crypto_generichash`) - one-shot Kupyna-256/512, plus
//! streaming `Kupyna{256,512}Hasher` wrappers. `finalize` consumes the wrapped Rust `Hasher` by
//! value, so the opaque handle here holds an `Option<Hasher>`, `.take()`n on finalize - a second
//! `finalize()` call returns `DSTU_ERR_FINALIZED` rather than panicking (matches Python's own
//! `pyclass` wrapper precedent, D-148's own file-layout note).

use crate::error::DstuStatus;
use crate::util::{guard_ptr, guard_status, guard_void, slice_from_raw};
use dstu_core::crypto_generichash::{Kupyna256, Kupyna256Hasher, Kupyna512, Kupyna512Hasher};

pub const DSTU_GENERICHASH_256_BYTES: usize = 32;
pub const DSTU_GENERICHASH_512_BYTES: usize = 64;

/// One-shot Kupyna-256 digest of `message`. A NULL `message` with `message_len > 0`, or a NULL
/// `out`, is a no-op.
///
/// # Safety
///
/// `message` must be valid for reads of `message_len` bytes when non-null and `message_len > 0`;
/// `out` must be valid for writes of `DSTU_GENERICHASH_256_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_generichash_256(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
) {
    guard_void(|| {
        if out.is_null() {
            return;
        }
        let Some(message) = (unsafe { slice_from_raw(message, message_len) }) else {
            return;
        };
        let digest = Kupyna256::digest(message);
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_GENERICHASH_256_BYTES) };
        out.copy_from_slice(&digest);
    })
}

/// One-shot Kupyna-512 digest of `message`. Same null/zero-length convention as
/// [`dstu_generichash_256`].
///
/// # Safety
///
/// `message` must be valid for reads of `message_len` bytes when non-null and `message_len > 0`;
/// `out` must be valid for writes of `DSTU_GENERICHASH_512_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_generichash_512(
    message: *const u8,
    message_len: usize,
    out: *mut u8,
) {
    guard_void(|| {
        if out.is_null() {
            return;
        }
        let Some(message) = (unsafe { slice_from_raw(message, message_len) }) else {
            return;
        };
        let digest = Kupyna512::digest(message);
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_GENERICHASH_512_BYTES) };
        out.copy_from_slice(&digest);
    })
}

/// Opaque streaming Kupyna-256 hasher handle.
pub struct DstuKupyna256Hasher(Option<Kupyna256Hasher>);

/// Creates a new streaming hasher - infallible.
#[no_mangle]
pub extern "C" fn dstu_kupyna256_hasher_new() -> *mut DstuKupyna256Hasher {
    guard_ptr(|| Box::into_raw(Box::new(DstuKupyna256Hasher(Some(Kupyna256Hasher::new())))))
}

/// Feeds `data` into the hasher. A no-op if `hasher` is NULL, already finalized, or `data` is NULL
/// with `len > 0`.
///
/// # Safety
///
/// `hasher` must be a valid, non-null pointer from `dstu_kupyna256_hasher_new`; `data` must be
/// valid for reads of `len` bytes when non-null and `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn dstu_kupyna256_hasher_update(
    hasher: *mut DstuKupyna256Hasher,
    data: *const u8,
    len: usize,
) {
    guard_void(|| {
        if hasher.is_null() {
            return;
        }
        let Some(data) = (unsafe { slice_from_raw(data, len) }) else {
            return;
        };
        let hasher = unsafe { &mut *hasher };
        if let Some(inner) = hasher.0.as_mut() {
            inner.update(data);
        }
    })
}

/// Consumes the hasher's accumulated state into `out`. Returns `DSTU_OK`, `DSTU_ERR_FINALIZED` if
/// already finalized, or `DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `hasher` must be a valid, non-null pointer from `dstu_kupyna256_hasher_new`; `out` must be
/// valid for writes of `DSTU_GENERICHASH_256_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_kupyna256_hasher_finalize(
    hasher: *mut DstuKupyna256Hasher,
    out: *mut u8,
) -> DstuStatus {
    guard_status(|| {
        if hasher.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let hasher = unsafe { &mut *hasher };
        let Some(inner) = hasher.0.take() else {
            return DstuStatus::DSTU_ERR_FINALIZED;
        };
        let digest = inner.finalize();
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_GENERICHASH_256_BYTES) };
        out.copy_from_slice(&digest);
        DstuStatus::DSTU_OK
    })
}

/// Frees a hasher (finalized or not). NULL is a no-op.
///
/// # Safety
///
/// `hasher` must be either NULL or a pointer previously returned by `dstu_kupyna256_hasher_new`,
/// not already freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_kupyna256_hasher_free(hasher: *mut DstuKupyna256Hasher) {
    guard_void(|| {
        if !hasher.is_null() {
            drop(unsafe { Box::from_raw(hasher) });
        }
    })
}

/// Opaque streaming Kupyna-512 hasher handle. Same shape as [`DstuKupyna256Hasher`].
pub struct DstuKupyna512Hasher(Option<Kupyna512Hasher>);

/// Creates a new streaming hasher - infallible.
#[no_mangle]
pub extern "C" fn dstu_kupyna512_hasher_new() -> *mut DstuKupyna512Hasher {
    guard_ptr(|| Box::into_raw(Box::new(DstuKupyna512Hasher(Some(Kupyna512Hasher::new())))))
}

/// Feeds `data` into the hasher. Same convention as [`dstu_kupyna256_hasher_update`].
///
/// # Safety
///
/// `hasher` must be a valid, non-null pointer from `dstu_kupyna512_hasher_new`; `data` must be
/// valid for reads of `len` bytes when non-null and `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn dstu_kupyna512_hasher_update(
    hasher: *mut DstuKupyna512Hasher,
    data: *const u8,
    len: usize,
) {
    guard_void(|| {
        if hasher.is_null() {
            return;
        }
        let Some(data) = (unsafe { slice_from_raw(data, len) }) else {
            return;
        };
        let hasher = unsafe { &mut *hasher };
        if let Some(inner) = hasher.0.as_mut() {
            inner.update(data);
        }
    })
}

/// Consumes the hasher's accumulated state into `out`. Same convention as
/// [`dstu_kupyna256_hasher_finalize`].
///
/// # Safety
///
/// `hasher` must be a valid, non-null pointer from `dstu_kupyna512_hasher_new`; `out` must be
/// valid for writes of `DSTU_GENERICHASH_512_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_kupyna512_hasher_finalize(
    hasher: *mut DstuKupyna512Hasher,
    out: *mut u8,
) -> DstuStatus {
    guard_status(|| {
        if hasher.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let hasher = unsafe { &mut *hasher };
        let Some(inner) = hasher.0.take() else {
            return DstuStatus::DSTU_ERR_FINALIZED;
        };
        let digest = inner.finalize();
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_GENERICHASH_512_BYTES) };
        out.copy_from_slice(&digest);
        DstuStatus::DSTU_OK
    })
}

/// Frees a hasher (finalized or not). NULL is a no-op.
///
/// # Safety
///
/// `hasher` must be either NULL or a pointer previously returned by `dstu_kupyna512_hasher_new`,
/// not already freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_kupyna512_hasher_free(hasher: *mut DstuKupyna512Hasher) {
    guard_void(|| {
        if !hasher.is_null() {
            drop(unsafe { Box::from_raw(hasher) });
        }
    })
}
