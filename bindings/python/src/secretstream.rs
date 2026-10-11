//! `crypto_secretstream` wrapper - see [`dstu_core::crypto_secretstream`] for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (a `Tag` byte passed/returned as a plain `int`, matching the
//! Rust API's own `Tag::to_byte`/`Tag::from_byte` wire convention) - a more idiomatic Python
//! file-like wrapper is deliberately deferred to a later step
//! (`docs/bindings-strategy.md` T-49 step 3), so this step only has to prove the full surface is
//! reachable, not make it pretty yet.
//!
//! Also the stream-file codec classes (T-284, D-235): the idiomatic stream wrapper drives
//! `FileEncryptor`/`FileDecryptor` through them and does only I/O; it no longer parses the
//! file format itself.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, Key, PullState, PushState, Tag, CHUNK_BYTES, FILE_PREFIX_BYTES,
    MAX_RECORD_BYTES,
};
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

/// Stream-file writer (T-284): the D-208 framing from the core codec. `secretstream.py`'s
/// `SecretStreamEncryptor` drives it and does only I/O.
#[pyclass]
pub struct SecretStreamFileEncryptor {
    inner: FileEncryptor,
    prefix: [u8; FILE_PREFIX_BYTES],
}

#[pymethods]
impl SecretStreamFileEncryptor {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        let key = Key::from_bytes(to_array::<32>(key, "key")?);
        let (inner, prefix) = FileEncryptor::init(&key).dstu()?;
        Ok(Self { inner, prefix })
    }

    /// The format version byte and header - write these first.
    #[getter]
    fn prefix(&self) -> Vec<u8> {
        self.prefix.to_vec()
    }

    /// Seals exactly `CHUNK_BYTES` bytes as one non-final record.
    fn seal_chunk(&mut self, chunk: &[u8]) -> PyResult<Vec<u8>> {
        let chunk = to_array::<CHUNK_BYTES>(chunk, "chunk")?;
        let mut record = vec![0u8; MAX_RECORD_BYTES];
        let Ok(out) = <&mut [u8; MAX_RECORD_BYTES]>::try_from(record.as_mut_slice()) else {
            unreachable!("record is MAX_RECORD_BYTES long")
        };
        self.inner.seal_chunk(&chunk, out).dstu()?;
        Ok(record)
    }

    /// Seals the last `0..=CHUNK_BYTES` bytes as the `Final` record.
    fn seal_final(&mut self, last: &[u8]) -> PyResult<Vec<u8>> {
        let mut record = vec![0u8; MAX_RECORD_BYTES];
        let n = self.inner.seal_final(last, &mut record).dstu()?;
        record.truncate(n);
        Ok(record)
    }
}

/// Stream-file reader (T-284): read exactly `next_len()` bytes and `feed` them; at end of input
/// call `finish()`. Raises `DstuError` with the core's message on any format or authentication
/// error.
#[pyclass]
pub struct SecretStreamFileDecryptor {
    inner: FileDecryptor,
}

#[pymethods]
impl SecretStreamFileDecryptor {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        let key = Key::from_bytes(to_array::<32>(key, "key")?);
        Ok(Self {
            inner: FileDecryptor::new(&key),
        })
    }

    fn next_len(&self) -> usize {
        self.inner.next_len()
    }

    /// Consumes exactly `next_len()` bytes; returns the plaintext of a verified non-final
    /// record, else empty bytes.
    fn feed(&mut self, data: &[u8]) -> PyResult<Vec<u8>> {
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = self.inner.feed(data, &mut plaintext).dstu()?;
        plaintext.truncate(n);
        Ok(plaintext)
    }

    /// End of input: returns the `Final` chunk's plaintext, or raises if the stream is truncated.
    fn finish(&mut self) -> PyResult<Vec<u8>> {
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = self.inner.finish(&mut plaintext).dstu()?;
        plaintext.truncate(n);
        Ok(plaintext)
    }
}
