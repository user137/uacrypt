//! `crypto_secretstream` wrapper - see [`dstu_core::crypto_secretstream`] for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (a `Tag` byte passed/returned as a plain PHP `int`, matching
//! the Rust API's own `Tag::to_byte`/`Tag::from_byte` wire convention) - a more idiomatic PHP
//! stream wrapper is deliberately deferred to a later step (`docs/bindings-strategy.md` T-159
//! step 3), so this step only has to prove the full surface is reachable, not make it pretty yet.
//!
//! Also the stream-file codec classes (T-284, D-235): the idiomatic stream wrapper drives
//! `FileEncryptor`/`FileDecryptor` through them and does only I/O; it no longer parses the
//! file format itself.

use std::cell::RefCell;

use ext_php_rs::{
    binary::Binary, boxed::ZBox, builders::ModuleBuilder, exception::PhpException, php_class,
    php_function, php_impl, types::ZendHashTable, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, Key, PullState, PushState, Tag, CHUNK_BYTES, FILE_PREFIX_BYTES,
    MAX_RECORD_BYTES,
};

fn tag_from_byte(byte: u8) -> Result<Tag, PhpException> {
    Tag::from_byte(byte).ok_or_else(|| {
        PhpException::new(
            "unrecognized secretstream tag byte".to_string(),
            0,
            crate::error::value_error(),
        )
    })
}

/// Generates a fresh 32-byte `crypto_secretstream` master key from the OS CSPRNG.
#[php_function]
pub fn dstu_core_secretstream_keygen() -> Result<Binary<u8>, PhpException> {
    let key = Key::generate().dstu()?;
    Ok(Binary::from(key.as_bytes().to_vec()))
}

/// Encrypting half of a `crypto_secretstream` session - see [`PushState`]. Class name is
/// prefixed `DstuCore*` (not namespaced), matching `generichash`'s own convention.
#[php_class]
#[php(name = "DstuCoreSecretStreamPushState")]
pub struct SecretStreamPushState(RefCell<PushState>, [u8; 32]);

#[php_impl]
#[php(change_method_case = "snake_case")]
impl SecretStreamPushState {
    /// Starts a new stream under `key`. The `header` must be transmitted/stored alongside the
    /// encrypted chunks - `DstuCoreSecretStreamPullState` needs it to decrypt them.
    pub fn __construct(key: Binary<u8>) -> Result<Self, PhpException> {
        let key = Key::from_bytes(to_array::<32>(&key, "key")?);
        let (inner, header) = PushState::init(&key).dstu()?;
        Ok(Self(RefCell::new(inner), header))
    }

    pub fn header(&self) -> Binary<u8> {
        Binary::from(self.1.to_vec())
    }

    pub fn is_finalized(&self) -> bool {
        self.0.borrow().is_finalized()
    }

    /// Encrypts `plaintext` and returns `[ciphertext, auth_tag]`. `tag` must be one of the
    /// `DSTU_CORE_SECRETSTREAM_TAG_*` global constants; the caller must transmit `ciphertext`,
    /// `auth_tag`, and `tag` itself for `DstuCoreSecretStreamPullState::pull` to recover the
    /// plaintext.
    pub fn push(&self, tag: u8, plaintext: Binary<u8>) -> Result<Vec<Binary<u8>>, PhpException> {
        let tag = tag_from_byte(tag)?;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let auth_tag = self
            .0
            .borrow_mut()
            .push(tag, &plaintext, &mut ciphertext)
            .dstu()?;
        Ok(vec![
            Binary::from(ciphertext),
            Binary::from(auth_tag.to_vec()),
        ])
    }
}

/// Decrypting half of a `crypto_secretstream` session - see [`PullState`].
#[php_class]
#[php(name = "DstuCoreSecretStreamPullState")]
pub struct SecretStreamPullState(RefCell<PullState>);

#[php_impl]
#[php(change_method_case = "snake_case")]
impl SecretStreamPullState {
    /// Re-derives the stream's initial subkey from `key` and `header` (as produced by
    /// `DstuCoreSecretStreamPushState::header`).
    pub fn __construct(key: Binary<u8>, header: Binary<u8>) -> Result<Self, PhpException> {
        let key = Key::from_bytes(to_array::<32>(&key, "key")?);
        let header = to_array::<32>(&header, "header")?;
        Ok(Self(RefCell::new(PullState::init(&key, &header))))
    }

    pub fn is_finalized(&self) -> bool {
        self.0.borrow().is_finalized()
    }

    /// Verifies and decrypts one chunk. Returns `[tag, plaintext]`. Throws `DstuCoreException` if
    /// authentication fails - a tampered, reordered, dropped, or spliced-from-another-stream
    /// chunk all fail here rather than returning wrong plaintext.
    pub fn pull(
        &self,
        tag_byte: u8,
        ciphertext: Binary<u8>,
        auth_tag: Binary<u8>,
    ) -> Result<ZBox<ZendHashTable>, PhpException> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let tag = self
            .0
            .borrow_mut()
            .pull(tag_byte, &ciphertext, &auth_tag, &mut plaintext)
            .dstu()?;
        let mut result = ZendHashTable::new();
        result.push(tag.to_byte()).map_err(|e| {
            PhpException::from_message(format!("failed to build result array: {e}"))
        })?;
        result.push(Binary::from(plaintext)).map_err(|e| {
            PhpException::from_message(format!("failed to build result array: {e}"))
        })?;
        Ok(result)
    }
}

/// Stream-file writer (T-284): the D-208 framing from the core codec.
/// `lib/DstuCoreSecretStream.php`'s `DstuCoreSecretStreamWriter` drives it and does only I/O.
#[php_class]
#[php(name = "DstuCoreSecretStreamFileEncryptor")]
pub struct SecretStreamFileEncryptor(RefCell<FileEncryptor>, [u8; FILE_PREFIX_BYTES]);

#[php_impl]
#[php(change_method_case = "snake_case")]
impl SecretStreamFileEncryptor {
    pub fn __construct(key: Binary<u8>) -> Result<Self, PhpException> {
        let key = Key::from_bytes(to_array::<32>(&key, "key")?);
        let (inner, prefix) = FileEncryptor::init(&key).dstu()?;
        Ok(Self(RefCell::new(inner), prefix))
    }

    /// The format version byte and header - write these first.
    pub fn prefix(&self) -> Binary<u8> {
        Binary::from(self.1.to_vec())
    }

    /// Seals exactly `CHUNK_BYTES` bytes as one non-final record.
    pub fn seal_chunk(&self, chunk: Binary<u8>) -> Result<Binary<u8>, PhpException> {
        let chunk = to_array::<CHUNK_BYTES>(&chunk, "chunk")?;
        let mut record = vec![0u8; MAX_RECORD_BYTES];
        let Ok(out) = <&mut [u8; MAX_RECORD_BYTES]>::try_from(record.as_mut_slice()) else {
            unreachable!("record is MAX_RECORD_BYTES long")
        };
        self.0.borrow_mut().seal_chunk(&chunk, out).dstu()?;
        Ok(Binary::from(record))
    }

    /// Seals the last `0..=CHUNK_BYTES` bytes as the `Final` record.
    pub fn seal_final(&self, last: Binary<u8>) -> Result<Binary<u8>, PhpException> {
        let mut record = vec![0u8; MAX_RECORD_BYTES];
        let n = self.0.borrow_mut().seal_final(&last, &mut record).dstu()?;
        record.truncate(n);
        Ok(Binary::from(record))
    }
}

/// Stream-file reader (T-284): feed exactly `next_len()` bytes at a time; at end of input call
/// `finish()`. Throws `DstuCoreException` with the core's message on any format or
/// authentication error.
#[php_class]
#[php(name = "DstuCoreSecretStreamFileDecryptor")]
pub struct SecretStreamFileDecryptor(RefCell<FileDecryptor>);

#[php_impl]
#[php(change_method_case = "snake_case")]
impl SecretStreamFileDecryptor {
    pub fn __construct(key: Binary<u8>) -> Result<Self, PhpException> {
        let key = Key::from_bytes(to_array::<32>(&key, "key")?);
        Ok(Self(RefCell::new(FileDecryptor::new(&key))))
    }

    pub fn next_len(&self) -> u32 {
        // At most CHUNK_BYTES + 16.
        u32::try_from(self.0.borrow().next_len()).unwrap_or(u32::MAX)
    }

    /// Consumes exactly `next_len()` bytes; returns the plaintext of a verified non-final record,
    /// else an empty string.
    pub fn feed(&self, data: Binary<u8>) -> Result<Binary<u8>, PhpException> {
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = self.0.borrow_mut().feed(&data, &mut plaintext).dstu()?;
        plaintext.truncate(n);
        Ok(Binary::from(plaintext))
    }

    /// End of input: returns the `Final` chunk's plaintext, or throws if the stream is truncated.
    pub fn finish(&self) -> Result<Binary<u8>, PhpException> {
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = self.0.borrow_mut().finish(&mut plaintext).dstu()?;
        plaintext.truncate(n);
        Ok(Binary::from(plaintext))
    }
}

/// Registers this module's functions and classes - see `secretbox::register`'s doc comment for
/// why each module registers its own functions.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_secretstream_keygen))
        .class::<SecretStreamPushState>()
        .class::<SecretStreamPullState>()
        .class::<SecretStreamFileEncryptor>()
        .class::<SecretStreamFileDecryptor>()
}
