//! `crypto_secretstream` wrapper - see [`dstu_core::crypto_secretstream`] for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (a `Tag` byte passed/returned as a plain `int`, matching the
//! Rust API's own `Tag::to_byte`/`Tag::from_byte` wire convention) - a more idiomatic Python
//! file-like wrapper is deliberately deferred to a later step
//! (`docs/bindings-strategy.md` T-49 step 3), so this step only has to prove the full surface is
//! reachable, not make it pretty yet.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_secretstream::{Key, PullState, PushState, Tag};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Generates a fresh 32-byte `crypto_secretstream` master key from the OS CSPRNG.
#[pyfunction]
pub fn secretstream_keygen() -> PyResult<Vec<u8>> {
    Key::generate().dstu().map(|key| key.as_bytes().to_vec())
}

fn tag_from_byte(byte: u8) -> PyResult<Tag> {
    Tag::from_byte(byte).ok_or_else(|| PyValueError::new_err("unrecognized secretstream tag byte"))
}

/// Encrypting half of a `crypto_secretstream` session - see [`PushState`].
#[pyclass]
pub struct SecretStreamPushState {
    inner: PushState,
    header: [u8; 32],
}

#[pymethods]
impl SecretStreamPushState {
    /// Starts a new stream under `key`. The `.header` property must be transmitted/stored
    /// alongside the encrypted chunks - [`SecretStreamPullState`] needs it to decrypt them.
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        let key = Key::from_bytes(to_array::<32>(key, "key")?);
        let (inner, header) = PushState::init(&key).dstu()?;
        Ok(Self { inner, header })
    }

    #[getter]
    fn header(&self) -> Vec<u8> {
        self.header.to_vec()
    }

    fn is_finalized(&self) -> bool {
        self.inner.is_finalized()
    }

    /// Encrypts `plaintext` and returns `(ciphertext, auth_tag)`. `tag` must be one of the
    /// `SECRETSTREAM_TAG_*` module constants; the caller must transmit `ciphertext`, `auth_tag`,
    /// and `tag` itself for [`SecretStreamPullState.pull`] to recover the plaintext.
    fn push(&mut self, tag: u8, plaintext: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let tag = tag_from_byte(tag)?;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let auth_tag = self.inner.push(tag, plaintext, &mut ciphertext).dstu()?;
        Ok((ciphertext, auth_tag.to_vec()))
    }
}

/// Decrypting half of a `crypto_secretstream` session - see [`PullState`].
#[pyclass]
pub struct SecretStreamPullState {
    inner: PullState,
}

#[pymethods]
impl SecretStreamPullState {
    /// Re-derives the stream's initial subkey from `key` and `header` (as produced by
    /// [`SecretStreamPushState.header`]).
    #[new]
    fn new(key: &[u8], header: &[u8]) -> PyResult<Self> {
        let key = Key::from_bytes(to_array::<32>(key, "key")?);
        let header = to_array::<32>(header, "header")?;
        Ok(Self {
            inner: PullState::init(&key, &header),
        })
    }

    fn is_finalized(&self) -> bool {
        self.inner.is_finalized()
    }

    /// Verifies and decrypts one chunk. Returns `(tag, plaintext)`. Raises `DstuError` if
    /// authentication fails - a tampered, reordered, dropped, or spliced-from-another-stream
    /// chunk all fail here rather than returning wrong plaintext.
    fn pull(
        &mut self,
        tag_byte: u8,
        ciphertext: &[u8],
        auth_tag: &[u8],
    ) -> PyResult<(u8, Vec<u8>)> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let tag = self
            .inner
            .pull(tag_byte, ciphertext, auth_tag, &mut plaintext)
            .dstu()?;
        Ok((tag.to_byte(), plaintext))
    }
}
