//! PyO3 extension module for `dstu-core` (`docs/bindings-strategy.md` T-49, `docs/TASKS.md`'s
//! Phase 3 "Language bindings" section). Not independently audited - see the root project's
//! `docs/SECURITY.md`/`docs/DECISIONS.md` for the full threat model and per-construction status.
//!
//! This module is the compiled `_dstu_core` extension; `python/dstu_core/__init__.py` is the
//! public-facing pure-Python package a consumer actually imports.
//!
//! Step 2 of `docs/bindings-strategy.md`'s standard binding template: wraps the full `crypto_*`
//! surface, zero-config (`docs/DECISIONS.md` D-116 - no nonce/IV/mode parameter exposed to the
//! Python caller), one Rust module per `dstu_core::crypto_*` module plus [`selftest`] (step 1).
//! Keys/ciphertexts/tags cross the boundary as plain `bytes`; failures raise [`error::DstuError`]
//! (or the stdlib `ValueError` for a caller-input mistake like a wrong-length key, not a crypto
//! failure). A more idiomatic Python surface (context managers, a file-like
//! `crypto_secretstream` wrapper) is deferred to later steps.

mod auth;
mod box512;
mod crypto_box;
mod error;
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

use pyo3::prelude::*;

/// Re-runs `dstu_core`'s official-vector self-check against this exact compiled build.
///
/// Raises `DstuError` naming which primitive(s) failed, if any - see
/// `dstu_core::selftest` on the Rust side for what this does and does not cover.
#[pyfunction]
fn selftest() -> PyResult<()> {
    dstu_core::selftest::run().map_err(|report| error::DstuError::new_err(report.to_string()))
}

#[pymodule]
fn _dstu_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("DstuError", m.py().get_type::<error::DstuError>())?;
    m.add_function(wrap_pyfunction!(selftest, m)?)?;

    m.add_function(wrap_pyfunction!(secretbox::secretbox_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(secretbox::secretbox_seal, m)?)?;
    m.add_function(wrap_pyfunction!(secretbox::secretbox_open, m)?)?;

    m.add_function(wrap_pyfunction!(crypto_box::box_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_box::box_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_box::box_seal, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_box::box_open, m)?)?;

    m.add_function(wrap_pyfunction!(box512::box512_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(box512::box512_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(box512::box512_seal, m)?)?;
    m.add_function(wrap_pyfunction!(box512::box512_open, m)?)?;

    m.add_function(wrap_pyfunction!(secretstream::secretstream_keygen, m)?)?;
    m.add_class::<secretstream::SecretStreamPushState>()?;
    m.add_class::<secretstream::SecretStreamPullState>()?;
    m.add("SECRETSTREAM_TAG_MESSAGE", 0x00u8)?;
    m.add("SECRETSTREAM_TAG_PUSH", 0x01u8)?;
    m.add("SECRETSTREAM_TAG_REKEY", 0x02u8)?;
    m.add("SECRETSTREAM_TAG_FINAL", 0x03u8)?;

    m.add_function(wrap_pyfunction!(auth::auth_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(auth::auth, m)?)?;
    m.add_function(wrap_pyfunction!(auth::auth_verify, m)?)?;

    m.add_function(wrap_pyfunction!(kdf::kdf_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(kdf::kdf_derive_subkey, m)?)?;

    m.add_function(wrap_pyfunction!(generichash::kupyna256, m)?)?;
    m.add_function(wrap_pyfunction!(generichash::kupyna512, m)?)?;
    m.add_class::<generichash::Kupyna256Hasher>()?;
    m.add_class::<generichash::Kupyna512Hasher>()?;

    m.add_function(wrap_pyfunction!(stream::stream_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(stream::stream_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(stream::stream_decrypt, m)?)?;

    m.add_function(wrap_pyfunction!(sign::sign_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(sign::sign_verifying_key, m)?)?;
    m.add_function(wrap_pyfunction!(sign::sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(sign::sign_verify, m)?)?;

    m.add_function(wrap_pyfunction!(sign257::sign257_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(sign257::sign257_verifying_key, m)?)?;
    m.add_function(wrap_pyfunction!(sign257::sign257_message, m)?)?;
    m.add_function(wrap_pyfunction!(sign257::sign257_verify, m)?)?;

    m.add_function(wrap_pyfunction!(pwhash::pwhash_hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(pwhash::pwhash_verify_password, m)?)?;
    m.add("PWHASH_INTERACTIVE", 0u8)?;
    m.add("PWHASH_MODERATE", 1u8)?;
    m.add("PWHASH_SENSITIVE", 2u8)?;

    m.add_function(wrap_pyfunction!(randombytes::randombytes_buf, m)?)?;

    Ok(())
}
