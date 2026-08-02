//! PHP bindings for `dstu-core` (`docs/bindings-strategy.md` T-159, `docs/TASKS.md`'s Phase 3
//! "Language bindings" section). Provisional, not yet published to PECL/Packagist - see the root
//! project's `docs/SECURITY.md`/`docs/DECISIONS.md` for the full threat model and per-construction
//! status.
//!
//! Flat `dstu_core_*`-prefixed global function naming (`dstu_core_secretbox_seal()`, etc.), one
//! Rust module per `dstu_core::crypto_*` module plus [`self_test`] (step 1) - matches the naming
//! convention PHP's own bundled `ext-sodium` extension already uses (`sodium_crypto_secretbox()`,
//! `SodiumException`), the closest same-domain, same-runtime precedent (`docs/DECISIONS.md`
//! D-142). Keys/ciphertexts/tags cross the boundary as `Binary<u8>` (a real binary string, not
//! UTF-8-validated); failures throw `DstuCoreException` (or PHP's own built-in `\ValueError` for a
//! caller-input mistake like a wrong-length key, not a crypto failure). A more idiomatic PHP
//! `crypto_secretstream` wrapper is deferred to step 3, matching every other binding's own step
//! 2/3 split.
//!
//! Nightly required on Windows only - some PHP internal functions use the `vectorcall` calling
//! convention, a nightly-only unstable Rust feature (ext-php-rs README, "Windows Requirements").
//! Linux/macOS build on stable.
#![cfg_attr(windows, feature(abi_vectorcall))]

mod auth;
mod error;
mod generichash;
mod kdf;
mod pwhash;
mod randombytes;
mod secretbox;
mod secretstream;
mod sign;
mod stream;
mod util;

use ext_php_rs::{
    builders::ModuleBuilder, exception::PhpException, php_const, php_function, prelude::*,
};

/// Re-runs `dstu_core`'s official-vector self-check against this exact compiled build.
///
/// Throws `DstuCoreException` naming which primitive(s) failed, if any - see
/// `dstu_core::selftest` on the Rust side for what this does and does not cover.
#[php_function]
pub fn dstu_core_self_test() -> Result<(), PhpException> {
    dstu_core::selftest::run()
        .map_err(|report| PhpException::from_class::<error::DstuCoreException>(report.to_string()))
}

// `i32`, not `u8` - `IntoConst` is only implemented for signed integer/float types (PHP has no
// unsigned integer type at all; its own `int` is a 64-bit signed type), confirmed by a real build
// error rather than assumed.
#[php_const]
pub const DSTU_CORE_PWHASH_INTERACTIVE: i32 = 0;
#[php_const]
pub const DSTU_CORE_PWHASH_MODERATE: i32 = 1;
#[php_const]
pub const DSTU_CORE_PWHASH_SENSITIVE: i32 = 2;

#[php_const]
pub const DSTU_CORE_SECRETSTREAM_TAG_MESSAGE: i32 = 0x00;
#[php_const]
pub const DSTU_CORE_SECRETSTREAM_TAG_PUSH: i32 = 0x01;
#[php_const]
pub const DSTU_CORE_SECRETSTREAM_TAG_REKEY: i32 = 0x02;
#[php_const]
pub const DSTU_CORE_SECRETSTREAM_TAG_FINAL: i32 = 0x03;

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    let module = module
        .function(wrap_function!(dstu_core_self_test))
        .constant(wrap_constant!(DSTU_CORE_PWHASH_INTERACTIVE))
        .constant(wrap_constant!(DSTU_CORE_PWHASH_MODERATE))
        .constant(wrap_constant!(DSTU_CORE_PWHASH_SENSITIVE))
        .constant(wrap_constant!(DSTU_CORE_SECRETSTREAM_TAG_MESSAGE))
        .constant(wrap_constant!(DSTU_CORE_SECRETSTREAM_TAG_PUSH))
        .constant(wrap_constant!(DSTU_CORE_SECRETSTREAM_TAG_REKEY))
        .constant(wrap_constant!(DSTU_CORE_SECRETSTREAM_TAG_FINAL))
        .class::<error::DstuCoreException>();

    let module = error::register(module);
    let module = secretbox::register(module);
    let module = sign::register(module);
    let module = auth::register(module);
    let module = kdf::register(module);
    let module = generichash::register(module);
    let module = stream::register(module);
    let module = pwhash::register(module);
    let module = randombytes::register(module);
    secretstream::register(module)
}
