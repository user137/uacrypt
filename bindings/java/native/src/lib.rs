//! Java (JNI) bindings for `dstu-core` (`docs/bindings-strategy.md` T-51, `docs/TASKS.md`'s Phase
//! 3 "Language bindings" section). Provisional, not yet published to Maven Central - see the root
//! project's `docs/SECURITY.md`/`docs/DECISIONS.md` for the full threat model and per-construction
//! status.
//!
//! Direct-Rust binding against `dstu_core`'s own API via the `jni` crate (0.21, deliberately not
//! 0.22 - see `docs/DECISIONS.md` D-153), not JNI-over-`crates/dstu-core-capi` - the step-0 spike
//! that decided this is recorded in D-153. One Rust module per `dstu_core::crypto_*` module plus
//! [`selftest`]; every entry point is wrapped in [`util::guard`], which is the panic-safety layer
//! `napi`/`PyO3`/`magnus` give the other direct-Rust bindings automatically and plain `jni` does
//! not.
//!
//! `#![allow(non_snake_case)]`: JNI mandates the exact `Java_<package>_<Class>_<method>` symbol
//! name for every native entry point (package/class/method names embedded verbatim, including
//! their original case) - these are not stylistic identifiers this crate chose, so the lint is
//! silenced crate-wide rather than fighting it function-by-function. The Java package
//! (`ua.dstucrypto.dstucore`) and every class/method name in this binding deliberately avoid
//! underscores for the same reason: JNI encodes a literal `_` in a package/class/method name as
//! `_1`, and mixing that escaping into already-underscore-heavy generated symbol names is a real
//! source of hard-to-read mismatches - simpler to just not have any.
#![allow(non_snake_case)]

mod auth;
mod generichash;
mod kdf;
mod pwhash;
mod randombytes;
mod secretbox;
mod secretstream;
mod selftest;
mod sign;
mod stream;
mod util;
