//! `crypto_secretstream` wrapper - see `dstu_core::crypto_secretstream` for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (a `Tag` byte passed/returned as a plain `number`, matching the
//! Rust API's own `Tag::to_byte`/`Tag::from_byte` wire convention) - a more idiomatic Node
//! `stream.Transform` wrapper is deliberately deferred to a later step
//! (`docs/bindings-strategy.md` T-50 step 3), so this step only has to prove the full surface is
//! reachable, not make it pretty yet. Mirrors `bindings/python/src/secretstream.rs`'s own step-2
//! scope exactly.
//!
//! Also the stream-file codec classes (T-284, D-235): the idiomatic stream wrapper drives
//! `FileEncryptor`/`FileDecryptor` through them and does only I/O; it no longer parses the
//! file format itself.

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_pwhash::passphrase_file::{self, Header, HEADER_BYTES};
use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, Key, PullState, PushState, Tag, CHUNK_BYTES, MAX_RECORD_BYTES,
};
use dstu_core::{crypto_box, crypto_box384, crypto_box512};
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

/// Stream-file writer (T-284): the D-208 framing from the core codec. `js/secretstream.js`'s
/// `SecretStreamEncryptor` drives it and does only buffering. The constructor takes a stream key;
/// the `boxSeal`/`box384Seal`/`box512Seal`/`passphraseSeal` factories (T-269) start the same codec under a
/// `crypto_box` KEM prefix or a passphrase-file header, and `prefix` then includes it.
#[napi]
pub struct SecretStreamFileEncryptor {
    inner: FileEncryptor,
    prefix: Vec<u8>,
}

#[napi]
impl SecretStreamFileEncryptor {
    #[napi(constructor)]
    pub fn new(key: Buffer) -> Result<Self> {
        let key = Key::from_bytes(to_array::<32>(&key, "key")?);
        let (inner, prefix) = FileEncryptor::init(&key).dstu()?;
        Ok(Self {
            inner,
            prefix: prefix.to_vec(),
        })
    }

    /// Starts a `crypto_box` (format v3) stream to `publicKey`.
    #[napi(factory, js_name = "boxSeal")]
    pub fn box_seal(public_key: Buffer) -> Result<Self> {
        let recipient = crate::crypto_box::public_key_from_bytes(&public_key)?;
        let (inner, prefix) = crypto_box::seal_stream(&recipient).dstu()?;
        Ok(Self {
            inner,
            prefix: prefix.to_vec(),
        })
    }

    /// Starts a `crypto_box384` (format v3) stream to `publicKey`.
    #[napi(factory, js_name = "box384Seal")]
    pub fn box384_seal(public_key: Buffer) -> Result<Self> {
        let recipient = crate::box384::public_key_from_bytes(&public_key)?;
        let (inner, prefix) = crypto_box384::seal_stream(&recipient).dstu()?;
        Ok(Self {
            inner,
            prefix: prefix.to_vec(),
        })
    }

    /// Starts a `crypto_box512` (format v3) stream to `publicKey`.
    #[napi(factory, js_name = "box512Seal")]
    pub fn box512_seal(public_key: Buffer) -> Result<Self> {
        let recipient = crate::box512::public_key_from_bytes(&public_key)?;
        let (inner, prefix) = crypto_box512::seal_stream(&recipient).dstu()?;
        Ok(Self {
            inner,
            prefix: prefix.to_vec(),
        })
    }

    /// Starts a passphrase file (D-219/D-240); runs Argon2 (256 MiB, t=3) on the calling thread,
    /// as `pwhashHashPassword` does.
    #[napi(factory, js_name = "passphraseSeal")]
    pub fn passphrase_seal(passphrase: Buffer) -> Result<Self> {
        let (inner, prefix) = passphrase_file::seal_stream(&passphrase).dstu()?;
        Ok(Self {
            inner,
            prefix: prefix.to_vec(),
        })
    }

    /// Everything to write before the first record.
    #[napi(getter)]
    pub fn prefix(&self) -> Buffer {
        Buffer::from(self.prefix.to_vec())
    }

    /// Seals exactly `CHUNK_BYTES` bytes as one non-final record.
    #[napi(js_name = "sealChunk")]
    pub fn seal_chunk(&mut self, chunk: Buffer) -> Result<Buffer> {
        let chunk = to_array::<CHUNK_BYTES>(&chunk, "chunk")?;
        let mut record = vec![0u8; MAX_RECORD_BYTES];
        let Ok(out) = <&mut [u8; MAX_RECORD_BYTES]>::try_from(record.as_mut_slice()) else {
            unreachable!("record is MAX_RECORD_BYTES long")
        };
        self.inner.seal_chunk(&chunk, out).dstu()?;
        Ok(Buffer::from(record))
    }

    /// Seals the last `0..=CHUNK_BYTES` bytes as the `Final` record.
    #[napi(js_name = "sealFinal")]
    pub fn seal_final(&mut self, last: Buffer) -> Result<Buffer> {
        let mut record = vec![0u8; MAX_RECORD_BYTES];
        let n = self.inner.seal_final(&last, &mut record).dstu()?;
        record.truncate(n);
        Ok(Buffer::from(record))
    }
}

/// Stream-file reader (T-284): feed exactly `nextLen()` bytes at a time; at end of input call
/// `finish()`. Throws with the core's message on any format or authentication error.
#[napi]
pub struct SecretStreamFileDecryptor {
    inner: FileDecryptor,
}

#[napi]
impl SecretStreamFileDecryptor {
    #[napi(constructor)]
    pub fn new(key: Buffer) -> Result<Self> {
        let key = Key::from_bytes(to_array::<32>(&key, "key")?);
        Ok(Self {
            inner: FileDecryptor::new(&key),
        })
    }

    /// Opens a `crypto_box` stream: `prefix` is its first `BOX_OPEN_STREAM_PREFIX_BYTES` bytes;
    /// feed the rest.
    #[napi(factory, js_name = "boxOpen")]
    pub fn box_open(secret_key: Buffer, prefix: Buffer) -> Result<Self> {
        let secret = crate::crypto_box::secret_key_from_bytes(&secret_key)?;
        let prefix = to_array::<{ crypto_box::OPEN_STREAM_PREFIX_BYTES }>(&prefix, "prefix")?;
        let inner = crypto_box::open_stream(&prefix, &secret).dstu()?;
        Ok(Self { inner })
    }

    /// Opens a `crypto_box384` stream: `prefix` is its first `BOX384_OPEN_STREAM_PREFIX_BYTES`
    /// bytes; feed the rest.
    #[napi(factory, js_name = "box384Open")]
    pub fn box384_open(secret_key: Buffer, prefix: Buffer) -> Result<Self> {
        let secret = crate::box384::secret_key_from_bytes(&secret_key)?;
        let prefix = to_array::<{ crypto_box384::OPEN_STREAM_PREFIX_BYTES }>(&prefix, "prefix")?;
        let inner = crypto_box384::open_stream(&prefix, &secret).dstu()?;
        Ok(Self { inner })
    }

    /// Opens a `crypto_box512` stream: `prefix` is its first `BOX512_OPEN_STREAM_PREFIX_BYTES`
    /// bytes; feed the rest.
    #[napi(factory, js_name = "box512Open")]
    pub fn box512_open(secret_key: Buffer, prefix: Buffer) -> Result<Self> {
        let secret = crate::box512::secret_key_from_bytes(&secret_key)?;
        let prefix = to_array::<{ crypto_box512::OPEN_STREAM_PREFIX_BYTES }>(&prefix, "prefix")?;
        let inner = crypto_box512::open_stream(&prefix, &secret).dstu()?;
        Ok(Self { inner })
    }

    /// Opens a passphrase file: `header` is its first `PASSPHRASE_FILE_HEADER_BYTES` bytes,
    /// checked before Argon2 runs; feed the rest. A wrong passphrase fails at the first record.
    #[napi(factory, js_name = "passphraseOpen")]
    pub fn passphrase_open(header: Buffer, passphrase: Buffer) -> Result<Self> {
        let header = to_array::<HEADER_BYTES>(&header, "header")?;
        let inner = Header::parse(&header)
            .and_then(|h| h.open_stream(&passphrase))
            .dstu()?;
        Ok(Self { inner })
    }

    #[napi(js_name = "nextLen")]
    pub fn next_len(&self) -> u32 {
        // At most CHUNK_BYTES + 16, always far below u32::MAX.
        u32::try_from(self.inner.next_len()).unwrap_or(u32::MAX)
    }

    /// Consumes exactly `nextLen()` bytes; returns the plaintext of a verified non-final record,
    /// else an empty buffer.
    #[napi]
    pub fn feed(&mut self, data: Buffer) -> Result<Buffer> {
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = self.inner.feed(&data, &mut plaintext).dstu()?;
        plaintext.truncate(n);
        Ok(Buffer::from(plaintext))
    }

    /// End of input: returns the `Final` chunk's plaintext, or throws if the stream is truncated.
    #[napi]
    pub fn finish(&mut self) -> Result<Buffer> {
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = self.inner.finish(&mut plaintext).dstu()?;
        plaintext.truncate(n);
        Ok(Buffer::from(plaintext))
    }
}
