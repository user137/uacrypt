//! C ABI for `dstu-core` (`docs/bindings-strategy.md` T-158, `docs/DECISIONS.md` D-119/D-148) -
//! the foundation binding C++/.NET/Java(-via-JNI)/Go consume next, via the generated
//! `include/dstu_core.h` header (`cargo xtask capi` regenerates it into a temp path and diffs
//! against the committed copy, D-148 point 2 - `cbindgen` is invoked from `xtask`, never added as
//! a build-dependency of this crate itself).
//!
//! **Pre-release and provisional, same status as `dstu-core` itself** - see that crate's own
//! top-level doc comment and `docs/SECURITY.md`/`docs/DECISIONS.md` for the full threat model and
//! per-construction status. This crate adds no new cryptographic logic of its own, only a C-ABI
//! shape over already-implemented primitives.
//!
//! # Conventions (D-148)
//!
//! - Every exported symbol uses the `dstu_`/`Dstu` prefix, not `dstu_core_` (D-148 point 1 - a
//!   different choice than the PHP binding's own `dstu_core_*`, `ext-sodium`-modeled naming;
//!   the two bindings had independent reasons to land on different prefixes).
//! - A fallible constructor is `DstuStatus dstu_xxx(..., DstuXxx **out)` (only writes `*out` on
//!   `DSTU_OK`); an infallible constructor returns `DstuXxx *` directly (never NULL for a correct
//!   call - a NULL input is a documented misuse-case exception, see each such function's own doc
//!   comment); an infallible operation with a fixed-size output is `void dstu_xxx(..., out)`; a
//!   fallible one is `DstuStatus dstu_xxx(..., out)`; a `verify`-shaped function mirroring a Rust
//!   `bool` return (`crypto_sign`'s `verify`/`verify_digest`) returns plain `bool`, not
//!   `DstuStatus` - a signature either verifies or it doesn't, that is the actual answer, not an
//!   error condition (`crypto_auth`'s own `verify` is the one exception, kept as `DstuStatus`
//!   since tag mismatch already is its only failure mode).
//! - **Output-buffer convention (D-148 point 3): caller-allocates, this library never allocates
//!   or frees a Rust-owned buffer C could free with `free()`.** A variable-length output
//!   (`crypto_secretbox`/`crypto_stream`'s sealed blobs) takes an explicit `_cap` parameter,
//!   checked against the exact required length *before* any crypto work runs -
//!   `DSTU_ERR_BUFFER_TOO_SMALL` if insufficient, never a partial write.
//! - **Opaque handles** (`DstuAuthKey`, `DstuSecretboxKey`, `DstuPushState`, ...) are real,
//!   non-`repr(C)` Rust structs wrapping the corresponding `dstu_core::crypto_*` type, only ever
//!   crossing this boundary as `*mut`/`*const` via `Box::into_raw`/`Box::from_raw`. Every
//!   `dstu_*_free` is exactly `drop(Box::from_raw(ptr))` (NULL is a no-op, matching `free()`'s own
//!   convention) - the wrapped types' existing `Zeroize`-on-`Drop` impls fire automatically, no
//!   separate zeroize call needed in this layer. The one gap those `Drop` impls cannot reach: a
//!   function that copies secret bytes *out* into a caller-owned buffer (`dstu_sign_key_bytes`)
//!   leaves that copy for the caller to wipe - see [`dstu_memzero`] (libsodium's `sodium_memzero`
//!   equivalent).
//! - **Every exported function body is wrapped in `catch_unwind`** (`util::guard_status`/
//!   `guard_ptr`/`guard_bool`/`guard_void`): an unwind crossing an `extern "C"` boundary aborts
//!   the caller's whole process outright since Rust 1.81, so this converts a hypothetical internal
//!   panic into `DstuStatus::DSTU_ERR_PANIC` (or a documented safe default - NULL/`false`/no-op -
//!   for a function with no `DstuStatus` channel) instead. This should never actually fire in
//!   correct code.
//! - **Null/zero-length hygiene**: every `(ptr, len)` pair branches to an empty slice for
//!   `len == 0` without ever calling `slice::from_raw_parts[_mut]` on a null pointer (`util::
//!   slice_from_raw`/`slice_from_raw_mut`) - that call is itself UB regardless of `len`. A NULL
//!   pointer for any *required* argument (a handle, or a `(ptr, len)` pair with `len > 0`) is
//!   rejected with `DSTU_ERR_NULL_POINTER` before dereferencing anything, wherever a `DstuStatus`
//!   channel exists to report it through.
//!
//! Full API surface (every exported function/type/constant) is specified in the implementation
//! itself and the generated header, not duplicated here - see `docs/DECISIONS.md` D-148 for the
//! design forks this crate resolves, and each module below for its own function-level detail.

pub mod auth;
pub mod crypto_box;
pub mod error;
pub mod generichash;
pub mod kdf;
pub mod pwhash;
pub mod randombytes;
pub mod secretbox;
pub mod secretstream;
pub mod selftest;
pub mod sign;
pub mod stream;
mod util;

pub use error::DstuStatus;
pub use util::dstu_memzero;
