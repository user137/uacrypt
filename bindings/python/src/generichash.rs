//! `crypto_generichash` wrapper - see [`dstu_core::crypto_generichash`] (Kupyna-256/512). One-shot
//! functions for a whole in-memory message, plus incremental `*Hasher` classes for a large or
//! streamed one - both produce the same digest for the same bytes.

use dstu_core::crypto_generichash as core;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Computes the 32-byte Kupyna-256 digest of `message`.
#[pyfunction]
pub fn kupyna256(message: &[u8]) -> Vec<u8> {
    core::Kupyna256::digest(message).to_vec()
}

/// Computes the 64-byte Kupyna-512 digest of `message`.
#[pyfunction]
pub fn kupyna512(message: &[u8]) -> Vec<u8> {
    core::Kupyna512::digest(message).to_vec()
}

/// Incremental Kupyna-256 hasher - call `update` any number of times, then `finalize` once.
#[pyclass]
pub struct Kupyna256Hasher(Option<core::Kupyna256Hasher>);

#[pymethods]
impl Kupyna256Hasher {
    #[new]
    fn new() -> Self {
        Self(Some(core::Kupyna256Hasher::new()))
    }

    fn update(&mut self, data: &[u8]) -> PyResult<()> {
        match &mut self.0 {
            Some(hasher) => {
                hasher.update(data);
                Ok(())
            }
            None => Err(PyValueError::new_err("hasher already finalized")),
        }
    }

    /// Consumes the accumulated state and returns the 32-byte digest. Raises `ValueError` if
    /// called more than once.
    fn finalize(&mut self) -> PyResult<Vec<u8>> {
        match self.0.take() {
            Some(hasher) => Ok(hasher.finalize().to_vec()),
            None => Err(PyValueError::new_err("hasher already finalized")),
        }
    }
}

/// Incremental Kupyna-512 hasher - call `update` any number of times, then `finalize` once.
#[pyclass]
pub struct Kupyna512Hasher(Option<core::Kupyna512Hasher>);

#[pymethods]
impl Kupyna512Hasher {
    #[new]
    fn new() -> Self {
        Self(Some(core::Kupyna512Hasher::new()))
    }

    fn update(&mut self, data: &[u8]) -> PyResult<()> {
        match &mut self.0 {
            Some(hasher) => {
                hasher.update(data);
                Ok(())
            }
            None => Err(PyValueError::new_err("hasher already finalized")),
        }
    }

    /// Consumes the accumulated state and returns the 64-byte digest. Raises `ValueError` if
    /// called more than once.
    fn finalize(&mut self) -> PyResult<Vec<u8>> {
        match self.0.take() {
            Some(hasher) => Ok(hasher.finalize().to_vec()),
            None => Err(PyValueError::new_err("hasher already finalized")),
        }
    }
}
