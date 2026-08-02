//! `dstu_selftest` - C ABI wrapper over `dstu_core::selftest::run()` (T-161). A C caller gets
//! pass/fail only - the Rust `Report`'s rich per-primitive failure detail is not exposed here,
//! matching every other language binding's own selftest wrapper's minimal surface.

use crate::error::DstuStatus;
use crate::util::guard_status;

/// Re-verifies one official test vector per primitive (Kalyna, Kupyna, Strumok, DSTU 4145)
/// against the live compiled build. Returns `DSTU_OK` on success, `DSTU_ERR_SELFTEST_FAILED`
/// otherwise.
#[no_mangle]
pub extern "C" fn dstu_selftest() -> DstuStatus {
    guard_status(|| match dstu_core::selftest::run() {
        Ok(()) => DstuStatus::DSTU_OK,
        Err(_) => DstuStatus::DSTU_ERR_SELFTEST_FAILED,
    })
}
