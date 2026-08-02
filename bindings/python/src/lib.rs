//! PyO3 extension module for `dstu-core` (`docs/bindings-strategy.md` T-49, `docs/TASKS.md`'s
//! Phase 3 "Language bindings" section). Provisional, not yet published to PyPI - see the root
//! project's `docs/SECURITY.md`/`docs/DECISIONS.md` for the full threat model and per-construction
//! status.
//!
//! This module is the compiled `_dstu_core` extension; `python/dstu_core/__init__.py` is the
//! public-facing pure-Python package a consumer actually imports.
//!
//! Step 1 of `docs/bindings-strategy.md`'s standard binding template (scaffold only): wraps
//! [`dstu_core::selftest::run`] as the one function that proves the whole pipeline - workspace
//! (own, per D-119) -> build -> package -> test -> examples -> CI - before the full `crypto_*`
//! surface (step 2) is wrapped.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

/// Re-runs `dstu_core`'s official-vector self-check against this exact compiled build.
///
/// Raises `RuntimeError` naming which primitive(s) failed, if any - see
/// `dstu_core::selftest` on the Rust side for what this does and does not cover.
#[pyfunction]
fn selftest() -> PyResult<()> {
    dstu_core::selftest::run().map_err(|report| PyRuntimeError::new_err(report.to_string()))
}

#[pymodule]
fn _dstu_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(selftest, m)?)?;
    Ok(())
}
