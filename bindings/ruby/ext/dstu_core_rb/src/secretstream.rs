//! `crypto_secretstream` wrapper - see [`dstu_core::crypto_secretstream`] for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (a `Tag` byte passed/returned as a plain `Integer`, matching
//! the Rust API's own `Tag::to_byte`/`Tag::from_byte` wire convention) - a more idiomatic Ruby
//! `IO`-like wrapper is deliberately deferred to a later step (`docs/bindings-strategy.md` T-160
//! step 3), so this step only has to prove the full surface is reachable, not make it pretty yet.

use std::cell::RefCell;

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_secretstream::{Key, PullState, PushState, Tag};
use magnus::{wrap, Error, RArray, RString, Ruby};

fn tag_from_byte(ruby: &Ruby, byte: u8) -> Result<Tag, Error> {
    Tag::from_byte(byte).ok_or_else(|| {
        Error::new(
            ruby.exception_arg_error(),
            "unrecognized secretstream tag byte",
        )
    })
}

/// Generates a fresh 32-byte `crypto_secretstream` master key from the OS CSPRNG.
pub fn secretstream_keygen(ruby: &Ruby) -> Result<RString, Error> {
    let key = Key::generate().dstu(ruby)?;
    Ok(ruby.str_from_slice(key.as_bytes()))
}

/// Encrypting half of a `crypto_secretstream` session - see [`PushState`].
#[wrap(class = "DstuCore::SecretStreamPushState")]
pub struct SecretStreamPushState(RefCell<PushState>, [u8; 32]);

impl SecretStreamPushState {
    /// Starts a new stream under `key`. The `#header` must be transmitted/stored alongside the
    /// encrypted chunks - [`SecretStreamPullState`] needs it to decrypt them.
    fn new(ruby: &Ruby, key: RString) -> Result<Self, Error> {
        let key = Key::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
        let (inner, header) = PushState::init(&key).dstu(ruby)?;
        Ok(Self(RefCell::new(inner), header))
    }

    fn header(&self) -> RString {
        Ruby::get()
            .expect("must run on a Ruby thread")
            .str_from_slice(&self.1)
    }

    fn is_finalized(&self) -> bool {
        self.0.borrow().is_finalized()
    }

    /// Encrypts `plaintext` and returns `[ciphertext, auth_tag]`. `tag` must be one of the
    /// `SECRETSTREAM_TAG_*` module constants; the caller must transmit `ciphertext`, `auth_tag`,
    /// and `tag` itself for [`SecretStreamPullState#pull`] to recover the plaintext.
    fn push(&self, tag: u8, plaintext: RString) -> Result<RArray, Error> {
        let ruby = Ruby::get().expect("must run on a Ruby thread");
        let tag = tag_from_byte(&ruby, tag)?;
        let plaintext = plaintext.to_bytes();
        let mut ciphertext = vec![0u8; plaintext.len()];
        let auth_tag = self
            .0
            .borrow_mut()
            .push(tag, &plaintext, &mut ciphertext)
            .dstu(&ruby)?;
        let result = ruby.ary_new_capa(2);
        result.push(ruby.str_from_slice(&ciphertext))?;
        result.push(ruby.str_from_slice(&auth_tag))?;
        Ok(result)
    }
}

/// Decrypting half of a `crypto_secretstream` session - see [`PullState`].
#[wrap(class = "DstuCore::SecretStreamPullState")]
pub struct SecretStreamPullState(RefCell<PullState>);

impl SecretStreamPullState {
    /// Re-derives the stream's initial subkey from `key` and `header` (as produced by
    /// [`SecretStreamPushState#header`]).
    fn new(ruby: &Ruby, key: RString, header: RString) -> Result<Self, Error> {
        let key = Key::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
        let header = to_array::<32>(ruby, &header.to_bytes(), "header")?;
        Ok(Self(RefCell::new(PullState::init(&key, &header))))
    }

    fn is_finalized(&self) -> bool {
        self.0.borrow().is_finalized()
    }

    /// Verifies and decrypts one chunk. Returns `[tag, plaintext]`. Raises `DstuCore::Error` if
    /// authentication fails - a tampered, reordered, dropped, or spliced-from-another-stream chunk
    /// all fail here rather than returning wrong plaintext.
    fn pull(&self, tag_byte: u8, ciphertext: RString, auth_tag: RString) -> Result<RArray, Error> {
        let ruby = Ruby::get().expect("must run on a Ruby thread");
        let ciphertext = ciphertext.to_bytes();
        let auth_tag = auth_tag.to_bytes();
        let mut plaintext = vec![0u8; ciphertext.len()];
        let tag = self
            .0
            .borrow_mut()
            .pull(tag_byte, &ciphertext, &auth_tag, &mut plaintext)
            .dstu(&ruby)?;
        let result = ruby.ary_new_capa(2);
        result.push(tag.to_byte())?;
        result.push(ruby.str_from_slice(&plaintext))?;
        Ok(result)
    }
}

pub fn init(ruby: &Ruby, module: magnus::RModule) -> Result<(), Error> {
    use magnus::{function, method, prelude::*};

    module.define_singleton_method("secretstream_keygen", function!(secretstream_keygen, 0))?;

    let push_state = module.define_class("SecretStreamPushState", ruby.class_object())?;
    push_state.define_singleton_method("new", function!(SecretStreamPushState::new, 1))?;
    push_state.define_method("header", method!(SecretStreamPushState::header, 0))?;
    push_state.define_method(
        "is_finalized",
        method!(SecretStreamPushState::is_finalized, 0),
    )?;
    push_state.define_method("push", method!(SecretStreamPushState::push, 2))?;

    let pull_state = module.define_class("SecretStreamPullState", ruby.class_object())?;
    pull_state.define_singleton_method("new", function!(SecretStreamPullState::new, 2))?;
    pull_state.define_method(
        "is_finalized",
        method!(SecretStreamPullState::is_finalized, 0),
    )?;
    pull_state.define_method("pull", method!(SecretStreamPullState::pull, 3))?;

    Ok(())
}
