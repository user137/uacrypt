//! `crypto_secretstream` wrapper - see [`dstu_core::crypto_secretstream`] for the underlying
//! chunked/streaming AEAD construction. This is a direct, function-for-function wrapper of the
//! Rust `PushState`/`PullState` API (a `Tag` byte passed/returned as a plain `Integer`, matching
//! the Rust API's own `Tag::to_byte`/`Tag::from_byte` wire convention) - a more idiomatic Ruby
//! `IO`-like wrapper is deliberately deferred to a later step (`docs/bindings-strategy.md` T-160
//! step 3), so this step only has to prove the full surface is reachable, not make it pretty yet.
//!
//! Also the stream-file codec classes (T-284, D-235): the idiomatic stream wrapper drives
//! `FileEncryptor`/`FileDecryptor` through them and does only I/O; it no longer parses the
//! file format itself.

use std::cell::RefCell;

use crate::util::{to_array, IntoDstuError};
use dstu_core::crypto_pwhash::passphrase_file::{self, Header, HEADER_BYTES};
use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, Key, PullState, PushState, Tag, CHUNK_BYTES, MAX_RECORD_BYTES,
};
use dstu_core::{crypto_box, crypto_box512};
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

/// Stream-file writer (T-284): the D-208 framing from the core codec. `secretstream.rb`'s
/// `SecretStreamWriter` drives it and does only I/O. `new` takes a stream key; `box_seal`/
/// `box512_seal`/`passphrase_seal` (T-269) start the same codec under a `crypto_box` KEM prefix or
/// a passphrase-file header, and `prefix` then includes it.
#[wrap(class = "DstuCore::SecretStreamFileEncryptor")]
pub struct SecretStreamFileEncryptor(RefCell<FileEncryptor>, Vec<u8>);

impl SecretStreamFileEncryptor {
    fn new(ruby: &Ruby, key: RString) -> Result<Self, Error> {
        let key = Key::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
        let (inner, prefix) = FileEncryptor::init(&key).dstu(ruby)?;
        Ok(Self(RefCell::new(inner), prefix.to_vec()))
    }

    /// Starts a `crypto_box` (format v3) stream to `public_key`.
    fn box_seal(ruby: &Ruby, public_key: RString) -> Result<Self, Error> {
        let recipient = crate::crypto_box::public_key_from_bytes(ruby, &public_key.to_bytes())?;
        let (inner, prefix) = crypto_box::seal_stream(&recipient).dstu(ruby)?;
        Ok(Self(RefCell::new(inner), prefix.to_vec()))
    }

    /// Starts a `crypto_box512` (format v3) stream to `public_key`.
    fn box512_seal(ruby: &Ruby, public_key: RString) -> Result<Self, Error> {
        let recipient = crate::box512::public_key_from_bytes(ruby, &public_key.to_bytes())?;
        let (inner, prefix) = crypto_box512::seal_stream(&recipient).dstu(ruby)?;
        Ok(Self(RefCell::new(inner), prefix.to_vec()))
    }

    /// Starts a passphrase file (D-219/D-240); runs Argon2 (256 MiB, t=3) holding the GVL, as
    /// `pwhash_hash_password` does.
    fn passphrase_seal(ruby: &Ruby, passphrase: RString) -> Result<Self, Error> {
        let (inner, prefix) = passphrase_file::seal_stream(&passphrase.to_bytes()).dstu(ruby)?;
        Ok(Self(RefCell::new(inner), prefix.to_vec()))
    }

    /// Everything to write before the first record.
    fn prefix(&self) -> RString {
        Ruby::get()
            .expect("must run on a Ruby thread")
            .str_from_slice(&self.1)
    }

    /// Seals exactly `SECRETSTREAM_CHUNK_BYTES` bytes as one non-final record.
    fn seal_chunk(&self, chunk: RString) -> Result<RString, Error> {
        let ruby = Ruby::get().expect("must run on a Ruby thread");
        let chunk = to_array::<CHUNK_BYTES>(&ruby, &chunk.to_bytes(), "chunk")?;
        let mut record = [0u8; MAX_RECORD_BYTES];
        self.0
            .borrow_mut()
            .seal_chunk(&chunk, &mut record)
            .dstu(&ruby)?;
        Ok(ruby.str_from_slice(&record))
    }

    /// Seals the last `0..=SECRETSTREAM_CHUNK_BYTES` bytes as the `Final` record.
    fn seal_final(&self, last: RString) -> Result<RString, Error> {
        let ruby = Ruby::get().expect("must run on a Ruby thread");
        let mut record = [0u8; MAX_RECORD_BYTES];
        let n = self
            .0
            .borrow_mut()
            .seal_final(&last.to_bytes(), &mut record)
            .dstu(&ruby)?;
        Ok(ruby.str_from_slice(&record[..n]))
    }
}

/// Stream-file reader (T-284): feed exactly `next_len` bytes at a time; at end of input call
/// `finish`. Raises `DstuCore::Error` with the core's message on any format or authentication
/// error.
#[wrap(class = "DstuCore::SecretStreamFileDecryptor")]
pub struct SecretStreamFileDecryptor(RefCell<FileDecryptor>);

impl SecretStreamFileDecryptor {
    fn new(ruby: &Ruby, key: RString) -> Result<Self, Error> {
        let key = Key::from_bytes(to_array::<32>(ruby, &key.to_bytes(), "key")?);
        Ok(Self(RefCell::new(FileDecryptor::new(&key))))
    }

    /// Opens a `crypto_box` stream: `prefix` is its first `BOX_OPEN_STREAM_PREFIX_BYTES` bytes.
    fn box_open(ruby: &Ruby, secret_key: RString, prefix: RString) -> Result<Self, Error> {
        let secret = crate::crypto_box::secret_key_from_bytes(ruby, &secret_key.to_bytes())?;
        let prefix = to_array::<{ crypto_box::OPEN_STREAM_PREFIX_BYTES }>(
            ruby,
            &prefix.to_bytes(),
            "prefix",
        )?;
        let inner = crypto_box::open_stream(&prefix, &secret).dstu(ruby)?;
        Ok(Self(RefCell::new(inner)))
    }

    /// Opens a `crypto_box512` stream: `prefix` is its first `BOX512_OPEN_STREAM_PREFIX_BYTES`
    /// bytes.
    fn box512_open(ruby: &Ruby, secret_key: RString, prefix: RString) -> Result<Self, Error> {
        let secret = crate::box512::secret_key_from_bytes(ruby, &secret_key.to_bytes())?;
        let prefix = to_array::<{ crypto_box512::OPEN_STREAM_PREFIX_BYTES }>(
            ruby,
            &prefix.to_bytes(),
            "prefix",
        )?;
        let inner = crypto_box512::open_stream(&prefix, &secret).dstu(ruby)?;
        Ok(Self(RefCell::new(inner)))
    }

    /// Opens a passphrase file: `header` is its first `PASSPHRASE_FILE_HEADER_BYTES` bytes,
    /// checked before Argon2 runs. A wrong passphrase fails at the first record.
    fn passphrase_open(ruby: &Ruby, header: RString, passphrase: RString) -> Result<Self, Error> {
        let header = to_array::<HEADER_BYTES>(ruby, &header.to_bytes(), "header")?;
        let inner = Header::parse(&header)
            .and_then(|h| h.open_stream(&passphrase.to_bytes()))
            .dstu(ruby)?;
        Ok(Self(RefCell::new(inner)))
    }

    fn next_len(&self) -> usize {
        self.0.borrow().next_len()
    }

    /// Consumes exactly `next_len` bytes; returns the plaintext of a verified non-final record,
    /// else an empty string.
    fn feed(&self, data: RString) -> Result<RString, Error> {
        let ruby = Ruby::get().expect("must run on a Ruby thread");
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = self
            .0
            .borrow_mut()
            .feed(&data.to_bytes(), &mut plaintext)
            .dstu(&ruby)?;
        Ok(ruby.str_from_slice(&plaintext[..n]))
    }

    /// End of input: returns the `Final` chunk's plaintext, or raises if the stream is truncated.
    fn finish(&self) -> Result<RString, Error> {
        let ruby = Ruby::get().expect("must run on a Ruby thread");
        let mut plaintext = vec![0u8; CHUNK_BYTES];
        let n = self.0.borrow_mut().finish(&mut plaintext).dstu(&ruby)?;
        Ok(ruby.str_from_slice(&plaintext[..n]))
    }
}

pub fn init(ruby: &Ruby, module: magnus::RModule) -> Result<(), Error> {
    use magnus::{function, method, prelude::*};

    module.define_singleton_method("secretstream_keygen", function!(secretstream_keygen, 0))?;

    let push_state = module.define_class("SecretStreamPushState", ruby.class_object())?;
    push_state.define_singleton_method("new", function!(SecretStreamPushState::new, 1))?;
    push_state.define_method("header", method!(SecretStreamPushState::header, 0))?;
    push_state.define_method(
        "finalized?",
        method!(SecretStreamPushState::is_finalized, 0),
    )?;
    push_state.define_method("push", method!(SecretStreamPushState::push, 2))?;

    let pull_state = module.define_class("SecretStreamPullState", ruby.class_object())?;
    pull_state.define_singleton_method("new", function!(SecretStreamPullState::new, 2))?;
    pull_state.define_method(
        "finalized?",
        method!(SecretStreamPullState::is_finalized, 0),
    )?;
    pull_state.define_method("pull", method!(SecretStreamPullState::pull, 3))?;

    let file_enc = module.define_class("SecretStreamFileEncryptor", ruby.class_object())?;
    file_enc.define_singleton_method("new", function!(SecretStreamFileEncryptor::new, 1))?;
    file_enc.define_singleton_method(
        "box_seal",
        function!(SecretStreamFileEncryptor::box_seal, 1),
    )?;
    file_enc.define_singleton_method(
        "box512_seal",
        function!(SecretStreamFileEncryptor::box512_seal, 1),
    )?;
    file_enc.define_singleton_method(
        "passphrase_seal",
        function!(SecretStreamFileEncryptor::passphrase_seal, 1),
    )?;
    file_enc.define_method("prefix", method!(SecretStreamFileEncryptor::prefix, 0))?;
    file_enc.define_method(
        "seal_chunk",
        method!(SecretStreamFileEncryptor::seal_chunk, 1),
    )?;
    file_enc.define_method(
        "seal_final",
        method!(SecretStreamFileEncryptor::seal_final, 1),
    )?;

    let file_dec = module.define_class("SecretStreamFileDecryptor", ruby.class_object())?;
    file_dec.define_singleton_method("new", function!(SecretStreamFileDecryptor::new, 1))?;
    file_dec.define_singleton_method(
        "box_open",
        function!(SecretStreamFileDecryptor::box_open, 2),
    )?;
    file_dec.define_singleton_method(
        "box512_open",
        function!(SecretStreamFileDecryptor::box512_open, 2),
    )?;
    file_dec.define_singleton_method(
        "passphrase_open",
        function!(SecretStreamFileDecryptor::passphrase_open, 2),
    )?;
    module.const_set(
        "BOX_OPEN_STREAM_PREFIX_BYTES",
        crypto_box::OPEN_STREAM_PREFIX_BYTES,
    )?;
    module.const_set(
        "BOX512_OPEN_STREAM_PREFIX_BYTES",
        crypto_box512::OPEN_STREAM_PREFIX_BYTES,
    )?;
    module.const_set("PASSPHRASE_FILE_HEADER_BYTES", HEADER_BYTES)?;
    file_dec.define_method("next_len", method!(SecretStreamFileDecryptor::next_len, 0))?;
    file_dec.define_method("feed", method!(SecretStreamFileDecryptor::feed, 1))?;
    file_dec.define_method("finish", method!(SecretStreamFileDecryptor::finish, 0))?;

    Ok(())
}
