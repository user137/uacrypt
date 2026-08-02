// Nightly required on Windows only - some PHP internal functions use the `vectorcall` calling
// convention, which is a nightly-only unstable Rust feature (ext-php-rs README, "Windows
// Requirements"). Linux/macOS build on stable.
#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::prelude::*;

/// Runs `dstu_core::selftest::run()` against every embedded official test vector and returns
/// `true` if all primitives pass. Mirrors Python's/Node's/Ruby's own `selftest()` wrapper (T-161)
/// - this scaffold step only proves the build/link/bindgen pipeline end to end; the full
/// `crypto_*` surface is step 2, not yet done.
#[php_function]
pub fn self_test() -> bool {
    dstu_core::selftest::run().is_ok()
}

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module.function(wrap_function!(self_test))
}
