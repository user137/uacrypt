//! `crypto_secretstream` wrapper - see `dstu_core::crypto_secretstream` for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (a `Tag` byte passed/returned as a plain `number`, matching the
//! Rust API's own `Tag::to_byte`/`Tag::from_byte` wire convention) - a more idiomatic Node
//! `stream.Transform` wrapper is deliberately deferred to a later step
//! (`docs/bindings-strategy.md` T-50 step 3), so this step only has to prove the full surface is
//! reachable, not make it pretty yet. Mirrors `bindings/python/src/secretstream.rs`'s own step-2
//! scope exactly.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_secretstream::{Key, PullState, PushState, Tag};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

/// Generates a fresh 32-byte `crypto_secretstream` master key from the OS CSPRNG.
#[napi(js_name = "secretstreamKeygen")]
pub fn secretstream_keygen() -> Result<Buffer> {
    Key::generate()
        .dstu()
        .map(|key| Buffer::from(key.as_bytes().to_vec()))
}

fn tag_from_byte(byte: u8) -> Result<Tag> {
    Tag::from_byte(byte).ok_or_else(|| Error::from_reason("unrecognized secretstream tag byte"))
}

/// The result of [`SecretStreamPushState::push`] - `ciphertext` and `authTag` must both be
/// transmitted, alongside the `tag` byte passed in, for [`SecretStreamPullState::pull`] to recover
/// the plaintext.
#[napi(object)]
pub struct SecretStreamPushResult {
    pub ciphertext: Buffer,
    #[napi(js_name = "authTag")]
    pub auth_tag: Buffer,
}

/// The result of [`SecretStreamPullState::pull`].
#[napi(object)]
pub struct SecretStreamPullResult {
    pub tag: u8,
    pub plaintext: Buffer,
}

/// Encrypting half of a `crypto_secretstream` session - see `dstu_core`'s `PushState`.
#[napi]
pub struct SecretStreamPushState {
    inner: PushState,
    header: [u8; 32],
}

#[napi]
impl SecretStreamPushState {
    /// Starts a new stream under `key`. The `.header` property must be transmitted/stored
    /// alongside the encrypted chunks - [`SecretStreamPullState`] needs it to decrypt them.
    #[napi(constructor)]
    pub fn new(key: Buffer) -> Result<Self> {
        let key = Key::from_bytes(to_array::<32>(&key, "key")?);
        let (inner, header) = PushState::init(&key).dstu()?;
        Ok(Self { inner, header })
    }

    #[napi(getter)]
    pub fn header(&self) -> Buffer {
        Buffer::from(self.header.to_vec())
    }

    #[napi(js_name = "isFinalized")]
    pub fn is_finalized(&self) -> bool {
        self.inner.is_finalized()
    }

    /// Encrypts `plaintext`. `tag` must be one of the `SECRETSTREAM_TAG_*` module constants; the
    /// caller must transmit the returned `ciphertext`/`authTag` plus `tag` itself for
    /// [`SecretStreamPullState::pull`] to recover the plaintext.
    #[napi]
    pub fn push(&mut self, tag: u8, plaintext: Buffer) -> Result<SecretStreamPushResult> {
        let tag = tag_from_byte(tag)?;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let auth_tag = self.inner.push(tag, &plaintext, &mut ciphertext).dstu()?;
        Ok(SecretStreamPushResult {
            ciphertext: Buffer::from(ciphertext),
            auth_tag: Buffer::from(auth_tag.to_vec()),
        })
    }
}

/// Decrypting half of a `crypto_secretstream` session - see `dstu_core`'s `PullState`.
#[napi]
pub struct SecretStreamPullState {
    inner: PullState,
}

#[napi]
impl SecretStreamPullState {
    /// Re-derives the stream's initial subkey from `key` and `header` (as produced by
    /// `SecretStreamPushState.header`).
    #[napi(constructor)]
    pub fn new(key: Buffer, header: Buffer) -> Result<Self> {
        let key = Key::from_bytes(to_array::<32>(&key, "key")?);
        let header = to_array::<32>(&header, "header")?;
        Ok(Self {
            inner: PullState::init(&key, &header),
        })
    }

    #[napi(js_name = "isFinalized")]
    pub fn is_finalized(&self) -> bool {
        self.inner.is_finalized()
    }

    /// Verifies and decrypts one chunk. Throws if authentication fails - a tampered, reordered,
    /// dropped, or spliced-from-another-stream chunk all fail here rather than returning wrong
    /// plaintext.
    #[napi]
    pub fn pull(
        &mut self,
        tag_byte: u8,
        ciphertext: Buffer,
        auth_tag: Buffer,
    ) -> Result<SecretStreamPullResult> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let tag = self
            .inner
            .pull(tag_byte, &ciphertext, &auth_tag, &mut plaintext)
            .dstu()?;
        Ok(SecretStreamPullResult {
            tag: tag.to_byte(),
            plaintext: Buffer::from(plaintext),
        })
    }
}
