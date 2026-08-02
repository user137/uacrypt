//! `dstu_core_rb` - Ruby bindings for `dstu-core` via `magnus`/`rb_sys`.
//!
//! Step 1 (this file, scaffold pipeline proof): wraps only [`self_test`], mirroring
//! `bindings/python`/`bindings/nodejs`'s own step-1 split. The full `crypto_*` surface is step 2.
//! Ruby's own `snake_case` convention needs no per-function casing override, unlike Node's
//! `js_name` requirement (D-126) - method names pass through as written.

use magnus::{function, prelude::*, Error, Ruby};

/// See `dstu_core::selftest` on the Rust side for what this does and does not cover.
fn self_test() -> Result<(), Error> {
    dstu_core::selftest::run()
        .map_err(|report| Error::new(magnus::exception::runtime_error(), report.to_string()))
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("DstuCore")?;
    module.define_singleton_method("self_test", function!(self_test, 0))?;
    Ok(())
}
