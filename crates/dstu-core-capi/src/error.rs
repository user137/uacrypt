//! C ABI status codes (`docs/DECISIONS.md` D-148) - every fallible function that doesn't already
//! return a fixed-size output or a plain `bool` (see each module's own function doc comments)
//! returns one of these.
//!
//! Variant names are written in the exact `DSTU_*` form the generated header carries them under
//! verbatim (`cbindgen` does not rename them) rather than Rust's own `UpperCamelCase` convention -
//! `#[allow(non_camel_case_types)]` below is deliberate, not an oversight.

#![allow(non_camel_case_types)]

/// Status/error code returned by most fallible functions in this crate's C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstuStatus {
    DSTU_OK = 0,
    /// OS CSPRNG failure (`dstu_core::randombytes::RandomError`).
    DSTU_ERR_RANDOM = 1,
    /// AEAD/MAC authentication failed: wrong key, or tampered ciphertext/tag/nonce/header.
    DSTU_ERR_TAG_MISMATCH = 2,
    /// Input shorter than the minimum possible valid output (e.g. below `crypto_secretbox`'s
    /// nonce+tag overhead).
    DSTU_ERR_TRUNCATED = 3,
    /// An exact-match length requirement was violated (`crypto_secretstream` push/pull).
    DSTU_ERR_INVALID_LENGTH = 4,
    /// The caller-supplied output buffer's declared capacity is insufficient - checked before any
    /// crypto work runs, so a caller never gets a partial write.
    DSTU_ERR_BUFFER_TOO_SMALL = 5,
    /// `crypto_secretstream`: `tag_byte` isn't one of the four valid values.
    DSTU_ERR_UNKNOWN_TAG = 6,
    /// A `crypto_secretstream` push/pull state, or a Kupyna hasher, was already finalized.
    DSTU_ERR_FINALIZED = 7,
    /// `dstu_selftest()`'s own known-answer self-check failed.
    DSTU_ERR_SELFTEST_FAILED = 8,
    /// `crypto_pwhash`'s internal Argon2/PHC-encoding failure - not expected in practice.
    DSTU_ERR_HASH_ERROR = 9,
    /// e.g. a DSTU 4145 signing-key scalar that is zero or greater than or equal to the curve
    /// order.
    DSTU_ERR_INVALID_KEY = 10,
    /// A required pointer argument was NULL (or NULL together with a nonzero declared length).
    DSTU_ERR_NULL_POINTER = 11,
    /// An internal panic was caught at the FFI boundary - should never happen in correct code. See
    /// this crate's top-level doc comment for why every exported function is wrapped in
    /// `catch_unwind`.
    DSTU_ERR_PANIC = 12,
}
