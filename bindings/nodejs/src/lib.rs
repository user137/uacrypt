//! Node.js bindings for `dstu-core` (`docs/bindings-strategy.md` T-50, `docs/TASKS.md`'s Phase 3
//! "Language bindings" section). Not independently audited - see the root project's
//! `docs/SECURITY.md`/`docs/DECISIONS.md` for the full threat model and per-construction status.
//!
//! Step 2 of `docs/bindings-strategy.md`'s standard binding template: wraps the full `crypto_*`
//! surface, zero-config (`docs/DECISIONS.md` D-116 - no nonce/IV/mode parameter exposed to the
//! JS caller), one Rust module per `dstu_core::crypto_*` module plus [`self_test`] (step 1).
//! Keys/ciphertexts/tags cross the boundary as `Buffer`; failures throw a plain `Error` carrying
//! the underlying `dstu_core` error's message, or a caller-input `Error` for a mistake like a
//! wrong-length key (not a crypto failure). A more idiomatic `crypto_secretstream`
//! `stream.Transform` wrapper is deferred to step 3, matching `bindings/python`'s own split.

mod auth;
mod box512;
mod crypto_box;
mod generichash;
mod kdf;
mod pwhash;
mod randombytes;
mod secretbox;
mod secretstream;
mod sign;
mod sign257;
mod stream;
mod util;

pub use auth::*;
pub use box512::*;
pub use crypto_box::*;
pub use generichash::*;
pub use kdf::*;
pub use pwhash::*;
pub use randombytes::*;
pub use secretbox::*;
pub use secretstream::*;
pub use sign::*;
pub use sign257::*;
pub use stream::*;

use napi_derive::napi;

/// Re-runs `dstu_core`'s official-vector self-check against this exact compiled build.
///
/// Throws naming which primitive(s) failed, if any - see `dstu_core::selftest` on the Rust side
/// for what this does and does not cover.
#[napi(js_name = "selfTest")]
pub fn self_test() -> napi::Result<()> {
    dstu_core::selftest::run().map_err(|report| napi::Error::from_reason(report.to_string()))
}

#[napi]
pub const PWHASH_INTERACTIVE: u8 = 0;
#[napi]
pub const PWHASH_MODERATE: u8 = 1;
#[napi]
pub const PWHASH_SENSITIVE: u8 = 2;

#[napi]
pub const SECRETSTREAM_TAG_MESSAGE: u8 = 0x00;
#[napi]
pub const SECRETSTREAM_TAG_PUSH: u8 = 0x01;
#[napi]
pub const SECRETSTREAM_TAG_REKEY: u8 = 0x02;
#[napi]
pub const SECRETSTREAM_TAG_FINAL: u8 = 0x03;
