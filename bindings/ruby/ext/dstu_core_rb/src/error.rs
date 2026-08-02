//! Shared Ruby exception class for this extension - `docs/cross-language-style-guide.md`'s
//! "errors are an explicit, typed result" principle, Ruby form (`DstuCore::Error < StandardError`).
//! One exception class across every `crypto_*` wrapper, not one per module: every failure raised
//! here already carries a specific message from the wrapped `dstu_core` error type's own `Display`
//! impl, so a caller who needs to distinguish cases matches on that message - the same shape
//! `ArgumentError`/`RuntimeError` already have in Ruby's own stdlib, rather than a bespoke class
//! per function.

use magnus::{prelude::*, value::Lazy, ExceptionClass, Ruby};

static DSTU_ERROR: Lazy<ExceptionClass> = Lazy::new(|ruby| {
    ruby.define_module("DstuCore")
        .and_then(|m| m.define_error("Error", ruby.exception_standard_error()))
        .expect("DstuCore::Error must be defined during init")
});

/// Raised for any `dstu_core` crypto operation failure (authentication/tamper rejection, OS
/// CSPRNG failure, malformed input, etc.) - see the raised message for the specific cause.
pub fn dstu_error(ruby: &Ruby) -> ExceptionClass {
    ruby.get_inner(&DSTU_ERROR)
}

/// Forces `DstuCore::Error` to be defined immediately (called from `init()`) rather than lazily
/// on first raise, so the class always exists as soon as the extension loads.
pub fn force(ruby: &Ruby) {
    Lazy::force(&DSTU_ERROR, ruby);
}
