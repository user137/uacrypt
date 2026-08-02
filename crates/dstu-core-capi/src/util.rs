//! Shared FFI-boundary helpers (`docs/DECISIONS.md` D-148 point 5): the `catch_unwind` wrappers
//! every exported function body uses, the `(ptr, len)` -> `&[u8]`/`&mut [u8]` conversion that never
//! calls `slice::from_raw_parts[_mut]` on a null pointer even for `len == 0`, and `dstu_memzero`
//! (libsodium's `sodium_memzero` equivalent).

use crate::error::DstuStatus;
use std::panic::{self, AssertUnwindSafe};

/// Converts a `(ptr, len)` pair into `&[u8]`. `len == 0` always succeeds with an empty slice
/// without ever touching `ptr` - `slice::from_raw_parts(null, 0)` is UB regardless of `len`, so
/// the null check only applies once `len > 0`. Returns `None` (caller maps to
/// `DSTU_ERR_NULL_POINTER`) if `ptr` is null and `len > 0`.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes when non-null and `len > 0`.
pub(crate) unsafe fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Mutable counterpart of [`slice_from_raw`] - same null/zero-length convention.
///
/// # Safety
///
/// `ptr` must be valid for reads and writes of `len` bytes when non-null and `len > 0`, and must
/// not alias any other reference live for the duration of the returned slice's use.
pub(crate) unsafe fn slice_from_raw_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

/// Wraps a `DstuStatus`-returning function body in `catch_unwind` - a caught panic becomes
/// `DSTU_ERR_PANIC` instead of unwinding across the `extern "C"` boundary (which aborts the
/// caller's whole process outright since Rust 1.81).
pub(crate) fn guard_status(f: impl FnOnce() -> DstuStatus) -> DstuStatus {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(DstuStatus::DSTU_ERR_PANIC)
}

/// Same as [`guard_status`] for a function returning an owned pointer - a caught panic yields
/// NULL, since there is no status code to carry the panic signal through.
pub(crate) fn guard_ptr<T>(f: impl FnOnce() -> *mut T) -> *mut T {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(std::ptr::null_mut())
}

/// Same as [`guard_status`] for a function returning `bool` - a caught panic yields `false`
/// ("did not verify"), the same safe default a real verification failure would produce.
pub(crate) fn guard_bool(f: impl FnOnce() -> bool) -> bool {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(false)
}

/// Same as [`guard_status`] for a `void`-returning function - a caught panic leaves whatever
/// output buffer the function was about to write untouched; there is no channel to report
/// anything through.
pub(crate) fn guard_void(f: impl FnOnce()) {
    let _ = panic::catch_unwind(AssertUnwindSafe(f));
}

/// Overwrites `buf[0..len]` with zero bytes, then fences so the compiler cannot optimize the write
/// away as dead (libsodium's `sodium_memzero` equivalent, D-148 point 5's gap-filler): the
/// `Zeroize`-on-`Drop` impls this crate's opaque handles wrap fire automatically on `dstu_*_free`,
/// but a value copied *out* into a caller-owned buffer (e.g. `dstu_sign_key_bytes`) is the
/// caller's own responsibility to wipe once done - this function is how.
///
/// A NULL `buf` or `len == 0` is a no-op, not an error - there is no `DstuStatus` return here to
/// report one through.
///
/// # Safety
///
/// `buf` must be valid for writes of `len` bytes when non-null and `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn dstu_memzero(buf: *mut core::ffi::c_void, len: usize) {
    guard_void(|| {
        if buf.is_null() || len == 0 {
            return;
        }
        unsafe {
            std::ptr::write_bytes(buf.cast::<u8>(), 0, len);
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    });
}
