//! `crypto_secretstream` wrapper - see [`dstu_core::crypto_secretstream`] for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (a `Tag` byte passed/returned as a plain PHP `int`, matching
//! the Rust API's own `Tag::to_byte`/`Tag::from_byte` wire convention) - a more idiomatic PHP
//! stream wrapper is deliberately deferred to a later step (`docs/bindings-strategy.md` T-159
//! step 3), so this step only has to prove the full surface is reachable, not make it pretty yet.

use std::cell::RefCell;

use ext_php_rs::{
    binary::Binary, boxed::ZBox, builders::ModuleBuilder, exception::PhpException, php_class,
    php_function, php_impl, types::ZendHashTable, wrap_function,
};

use crate::{error::IntoDstuException, util::to_array};
use dstu_core::crypto_secretstream::{Key, PullState, PushState, Tag};

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
        result
            .push(tag.to_byte())
            .map_err(|e| PhpException::default(format!("failed to build result array: {e}")))?;
        result
            .push(Binary::from(plaintext))
            .map_err(|e| PhpException::default(format!("failed to build result array: {e}")))?;
        Ok(result)
    }
}

/// Registers this module's functions and classes - see `secretbox::register`'s doc comment for
/// why each module registers its own functions.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_secretstream_keygen))
        .class::<SecretStreamPushState>()
        .class::<SecretStreamPullState>()
}
