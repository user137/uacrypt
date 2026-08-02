//! `dstu_randombytes_buf` - C ABI wrapper over `dstu_core::randombytes::randombytes_buf`.

use crate::error::DstuStatus;
use crate::util::{guard_status, slice_from_raw_mut};

/// Fills `buf[0..len]` with cryptographically secure random bytes from the OS CSPRNG.
///
/// Returns `DSTU_OK`, or `DSTU_ERR_RANDOM` if the OS CSPRNG fails. `DSTU_ERR_NULL_POINTER` if
/// `buf` is NULL while `len > 0`; `len == 0` is a no-op success regardless of `buf`.
///
/// # Safety
///
/// `buf` must be valid for writes of `len` bytes when non-null and `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn dstu_randombytes_buf(buf: *mut u8, len: usize) -> DstuStatus {
    guard_status(|| {
        let Some(slice) = (unsafe { slice_from_raw_mut(buf, len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        match dstu_core::randombytes::randombytes_buf(slice) {
            Ok(()) => DstuStatus::DSTU_OK,
            Err(_) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}
