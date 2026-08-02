//! `crypto_generichash` wrapper - see `dstu_core::crypto_generichash` (Kupyna-256/512). One-shot
//! functions for a whole in-memory message, plus incremental `*Hasher` classes for a large or
//! streamed one - both produce the same digest for the same bytes.

use dstu_core::crypto_generichash as core;
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

/// Computes the 32-byte Kupyna-256 digest of `message`.
#[napi(js_name = "kupyna256")]
pub fn kupyna256(message: Buffer) -> Buffer {
    Buffer::from(core::Kupyna256::digest(&message).to_vec())
}

/// Computes the 64-byte Kupyna-512 digest of `message`.
#[napi(js_name = "kupyna512")]
pub fn kupyna512(message: Buffer) -> Buffer {
    Buffer::from(core::Kupyna512::digest(&message).to_vec())
}

/// Incremental Kupyna-256 hasher - call `update` any number of times, then `finalize` once.
#[napi]
pub struct Kupyna256Hasher(Option<core::Kupyna256Hasher>);

impl Default for Kupyna256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl Kupyna256Hasher {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self(Some(core::Kupyna256Hasher::new()))
    }

    #[napi]
    pub fn update(&mut self, data: Buffer) -> Result<()> {
        match &mut self.0 {
            Some(hasher) => {
                hasher.update(&data);
                Ok(())
            }
            None => Err(Error::from_reason("hasher already finalized")),
        }
    }

    /// Consumes the accumulated state and returns the 32-byte digest. Throws if called more than
    /// once.
    #[napi]
    pub fn finalize(&mut self) -> Result<Buffer> {
        match self.0.take() {
            Some(hasher) => Ok(Buffer::from(hasher.finalize().to_vec())),
            None => Err(Error::from_reason("hasher already finalized")),
        }
    }
}

/// Incremental Kupyna-512 hasher - call `update` any number of times, then `finalize` once.
#[napi]
pub struct Kupyna512Hasher(Option<core::Kupyna512Hasher>);

impl Default for Kupyna512Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl Kupyna512Hasher {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self(Some(core::Kupyna512Hasher::new()))
    }

    #[napi]
    pub fn update(&mut self, data: Buffer) -> Result<()> {
        match &mut self.0 {
            Some(hasher) => {
                hasher.update(&data);
                Ok(())
            }
            None => Err(Error::from_reason("hasher already finalized")),
        }
    }

    /// Consumes the accumulated state and returns the 64-byte digest. Throws if called more than
    /// once.
    #[napi]
    pub fn finalize(&mut self) -> Result<Buffer> {
        match self.0.take() {
            Some(hasher) => Ok(Buffer::from(hasher.finalize().to_vec())),
            None => Err(Error::from_reason("hasher already finalized")),
        }
    }
}
