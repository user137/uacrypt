//! Node.js bindings for `dstu-core`, via napi-rs (T-50, following the Python binding's template -
//! see `docs/bindings-strategy.md`). One Rust module per `dstu_core::crypto_*` module will be added
//! in step 2; this scaffold wraps only [`self_test`], matching T-49 step 1's own split (prove the
//! workspace -> build -> load -> call pipeline before wrapping the real surface).
//!
//! Provisional status: Kalyna modes are not primary-text-confirmed, Strumok vectors are
//! UAPKI-attributed - see the root README/crate docs for the full banner (T-112).

#[macro_use]
extern crate napi_derive;

/// Re-runs the official KAT vectors against the live compiled binary and reports pass/fail - see
/// `dstu_core::selftest` on the Rust side for what this does and does not cover.
#[napi(js_name = "selfTest")]
pub fn self_test() -> napi::Result<()> {
    dstu_core::selftest::run().map_err(|report| napi::Error::from_reason(report.to_string()))
}
