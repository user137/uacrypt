//! `crypto_secretstream` C ABI (`dstu_core::crypto_secretstream`) - raw push/pull matching the Rust
//! API 1:1, plus the stream-file codec (`dstu_secretstream_file_*`, T-284/D-235) that .NET/Go/C++
//! drive for the file format. No idiomatic-C stream wrapper (a later consumer's job, D-148). `tag_byte`
//! passed into `dstu_secretstream_pull` is untrusted wire input - see the wrapped Rust module's own
//! doc comment for why it is folded into the AAD verified against `auth_tag`.

use crate::error::DstuStatus;
use crate::util::{
    guard_bool, guard_const_ptr, guard_ptr, guard_status, guard_usize, guard_void, overlaps,
    slice_from_raw, slice_from_raw_mut,
};
use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, FileError, Key, PullState, PushState, SecretstreamError, Tag,
    CHUNK_BYTES, MAX_RECORD_BYTES, RECORD_OVERHEAD_BYTES,
};
use std::ffi::{c_char, CString};

pub const DSTU_SECRETSTREAM_KEY_BYTES: usize = 32;
pub const DSTU_SECRETSTREAM_HEADER_BYTES: usize = 32;
pub const DSTU_SECRETSTREAM_TAG_BYTES: usize = 16;

/// A chunk's role in the stream - byte values match libsodium's own encoding, see the wrapped
/// Rust module's doc comment.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstuTag {
    DSTU_TAG_MESSAGE = 0,
    DSTU_TAG_PUSH = 1,
    DSTU_TAG_REKEY = 2,
    DSTU_TAG_FINAL = 3,
}

impl DstuTag {
    /// Maps a raw `DstuTag` value from C - see `pwhash.rs`'s `strength_from_raw` for why the
    /// parameter is a `u32` (T-240).
    fn core_from_raw(tag: u32) -> Option<Tag> {
        match tag {
            x if x == DstuTag::DSTU_TAG_MESSAGE as u32 => Some(Tag::Message),
            x if x == DstuTag::DSTU_TAG_PUSH as u32 => Some(Tag::Push),
            x if x == DstuTag::DSTU_TAG_REKEY as u32 => Some(Tag::Rekey),
            x if x == DstuTag::DSTU_TAG_FINAL as u32 => Some(Tag::Final),
            _ => None,
        }
    }

    fn from_core(tag: Tag) -> Self {
        match tag {
            Tag::Message => DstuTag::DSTU_TAG_MESSAGE,
            Tag::Push => DstuTag::DSTU_TAG_PUSH,
            Tag::Rekey => DstuTag::DSTU_TAG_REKEY,
            Tag::Final => DstuTag::DSTU_TAG_FINAL,
        }
    }
}

/// Opaque `crypto_secretstream` master-key handle.
pub struct DstuSecretstreamKey(Key);

/// Generates a fresh key from the OS CSPRNG. Returns `DSTU_OK` (writing `*out`) or
/// `DSTU_ERR_RANDOM`/`DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `out` must be a valid, non-null pointer to a `*mut DstuSecretstreamKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_key_generate(
    out: *mut *mut DstuSecretstreamKey,
) -> DstuStatus {
    guard_status(|| {
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match Key::generate() {
            Ok(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuSecretstreamKey(key))) };
                DstuStatus::DSTU_OK
            }
            Err(_) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Builds a key from exactly `DSTU_SECRETSTREAM_KEY_BYTES` bytes. Infallible for a correct call;
/// returns NULL if `key` is NULL.
///
/// # Safety
///
/// `key` must be valid for reads of `DSTU_SECRETSTREAM_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_key_from_bytes(
    key: *const u8,
) -> *mut DstuSecretstreamKey {
    guard_ptr(|| {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        // T-242: the stack copy of the key is wiped when this returns.
        let mut bytes = zeroize::Zeroizing::new([0u8; DSTU_SECRETSTREAM_KEY_BYTES]);
        bytes.copy_from_slice(unsafe {
            std::slice::from_raw_parts(key, DSTU_SECRETSTREAM_KEY_BYTES)
        });
        Box::into_raw(Box::new(DstuSecretstreamKey(Key::from_bytes(*bytes))))
    })
}

/// Copies the key's `DSTU_SECRETSTREAM_KEY_BYTES`-byte encoding into `out`. A NULL `key`/`out` is
/// a no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_SECRETSTREAM_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_key_bytes(
    key: *const DstuSecretstreamKey,
    out: *mut u8,
) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_SECRETSTREAM_KEY_BYTES) };
        out.copy_from_slice(key.0.as_bytes());
    })
}

/// Frees a key. NULL is a no-op.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by
/// `dstu_secretstream_key_generate`/`dstu_secretstream_key_from_bytes`, not already freed - freeing an already-freed pointer is undefined behavior, not merely unsupported; this fn cannot detect or reject it.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_key_free(key: *mut DstuSecretstreamKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// Opaque push-side (encrypting) stream-state handle.
pub struct DstuPushState(PushState);

/// Starts a new stream under `key`, drawing a fresh random header and writing it to `header_out`.
/// Returns `DSTU_OK` (writing `*out`/`header_out`), `DSTU_ERR_RANDOM`, or
/// `DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `key`/`out` must be non-null; `header_out` must be valid for writes of
/// `DSTU_SECRETSTREAM_HEADER_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_push_init(
    key: *const DstuSecretstreamKey,
    out: *mut *mut DstuPushState,
    header_out: *mut u8,
) -> DstuStatus {
    guard_status(|| {
        if key.is_null() || out.is_null() || header_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let key = unsafe { &*key };
        match PushState::init(&key.0) {
            Ok((state, header)) => {
                let header_out = unsafe {
                    std::slice::from_raw_parts_mut(header_out, DSTU_SECRETSTREAM_HEADER_BYTES)
                };
                header_out.copy_from_slice(&header);
                unsafe { *out = Box::into_raw(Box::new(DstuPushState(state))) };
                DstuStatus::DSTU_OK
            }
            Err(SecretstreamError::Random(_)) => DstuStatus::DSTU_ERR_RANDOM,
            Err(_) => unreachable!("PushState::init only ever returns Random"),
        }
    })
}

/// Returns whether this push state has already emitted a `Tag::Final` chunk. A NULL `state`
/// reports `false` (arbitrary but safe - there is no distinct "invalid handle" outcome for a
/// plain `bool` return).
///
/// # Safety
///
/// `state` must be either NULL or a valid pointer from `dstu_secretstream_push_init`.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_push_is_finalized(state: *const DstuPushState) -> bool {
    guard_bool(|| {
        if state.is_null() {
            return false;
        }
        unsafe { &*state }.0.is_finalized()
    })
}

/// Encrypts one chunk. `ciphertext_out_len` must equal `plaintext_len` exactly -
/// `DSTU_ERR_INVALID_LENGTH` otherwise. `DSTU_ERR_FINALIZED` if a previous chunk already used
/// `DSTU_TAG_FINAL`. `tag` must be one of the `DSTU_TAG_*` values - `DSTU_ERR_INVALID_ARGUMENT`
/// otherwise, checked before the state is touched.
///
/// # Safety
///
/// `state`/`tag_out` must be non-null; `plaintext` must be valid for reads of `plaintext_len`
/// bytes when non-null and `plaintext_len > 0`; `ciphertext_out` must be valid for writes of
/// `ciphertext_out_len` bytes when non-null and `ciphertext_out_len > 0`; `tag_out` must be valid
/// for writes of `DSTU_SECRETSTREAM_TAG_BYTES` bytes.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_push(
    state: *mut DstuPushState,
    tag: u32,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    tag_out: *mut u8,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(
            plaintext.cast::<u8>(),
            plaintext_len,
            ciphertext_out.cast_const().cast::<u8>(),
            ciphertext_out_len,
        ) || overlaps(
            plaintext.cast::<u8>(),
            plaintext_len,
            tag_out.cast_const().cast::<u8>(),
            DSTU_SECRETSTREAM_TAG_BYTES,
        ) || overlaps(
            ciphertext_out.cast::<u8>(),
            ciphertext_out_len,
            tag_out.cast_const().cast::<u8>(),
            DSTU_SECRETSTREAM_TAG_BYTES,
        ) {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        if state.is_null() || tag_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(plaintext) = (unsafe { slice_from_raw(plaintext, plaintext_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let Some(ciphertext_out) =
            (unsafe { slice_from_raw_mut(ciphertext_out, ciphertext_out_len) })
        else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let state = unsafe { &mut *state };
        let Some(tag) = DstuTag::core_from_raw(tag) else {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        };
        match state.0.push(tag, plaintext, ciphertext_out) {
            Ok(full_tag) => {
                let tag_out =
                    unsafe { std::slice::from_raw_parts_mut(tag_out, DSTU_SECRETSTREAM_TAG_BYTES) };
                tag_out.copy_from_slice(&full_tag);
                DstuStatus::DSTU_OK
            }
            Err(SecretstreamError::InvalidLength) => DstuStatus::DSTU_ERR_INVALID_LENGTH,
            Err(SecretstreamError::StreamFinalized | SecretstreamError::CounterExhausted) => {
                DstuStatus::DSTU_ERR_FINALIZED
            }
            Err(_) => unreachable!(
                "push() only ever returns InvalidLength/StreamFinalized/CounterExhausted"
            ),
        }
    })
}

/// Frees a push state. NULL is a no-op.
///
/// # Safety
///
/// `state` must be either NULL or a pointer previously returned by
/// `dstu_secretstream_push_init`, not already freed - freeing an already-freed pointer is undefined behavior, not merely unsupported; this fn cannot detect or reject it.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_push_free(state: *mut DstuPushState) {
    guard_void(|| {
        if !state.is_null() {
            drop(unsafe { Box::from_raw(state) });
        }
    })
}

/// Opaque pull-side (decrypting) stream-state handle.
pub struct DstuPullState(PullState);

/// Re-derives the stream's initial subkey from `key` and `header` (as produced by
/// `dstu_secretstream_push_init`) - infallible. Returns NULL if `key`/`header` is NULL.
///
/// # Safety
///
/// `key` must be valid when non-null; `header` must be valid for reads of
/// `DSTU_SECRETSTREAM_HEADER_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_pull_init(
    key: *const DstuSecretstreamKey,
    header: *const u8,
) -> *mut DstuPullState {
    guard_ptr(|| {
        if key.is_null() || header.is_null() {
            return std::ptr::null_mut();
        }
        let key = unsafe { &*key };
        let mut header_bytes = [0u8; DSTU_SECRETSTREAM_HEADER_BYTES];
        header_bytes.copy_from_slice(unsafe {
            std::slice::from_raw_parts(header, DSTU_SECRETSTREAM_HEADER_BYTES)
        });
        Box::into_raw(Box::new(DstuPullState(PullState::init(
            &key.0,
            &header_bytes,
        ))))
    })
}

/// Returns whether this pull state has already consumed a `Tag::Final` chunk. Same NULL
/// convention as [`dstu_secretstream_push_is_finalized`].
///
/// # Safety
///
/// `state` must be either NULL or a valid pointer from `dstu_secretstream_pull_init`.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_pull_is_finalized(state: *const DstuPullState) -> bool {
    guard_bool(|| {
        if state.is_null() {
            return false;
        }
        unsafe { &*state }.0.is_finalized()
    })
}

/// Verifies and decrypts one chunk. `plaintext_out_len` must equal `ciphertext_len` exactly -
/// `DSTU_ERR_INVALID_LENGTH` otherwise. `DSTU_ERR_UNKNOWN_TAG` if `tag_byte` isn't 0-3,
/// `DSTU_ERR_FINALIZED` if already finalized, `DSTU_ERR_TAG_MISMATCH` on auth failure
/// (`plaintext_out` left zeroed). On `DSTU_OK`, `*tag_out` holds the authenticated tag.
///
/// # Safety
///
/// `state`/`auth_tag`/`tag_out` must be non-null; `ciphertext` must be valid for reads of
/// `ciphertext_len` bytes when non-null and `ciphertext_len > 0`; `auth_tag` must be valid for
/// reads of `DSTU_SECRETSTREAM_TAG_BYTES` bytes; `plaintext_out` must be valid for writes of
/// `plaintext_out_len` bytes when non-null and `plaintext_out_len > 0`.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_pull(
    state: *mut DstuPullState,
    tag_byte: u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    auth_tag: *const u8,
    plaintext_out: *mut u8,
    plaintext_out_len: usize,
    tag_out: *mut DstuTag,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(
            ciphertext.cast::<u8>(),
            ciphertext_len,
            plaintext_out.cast_const().cast::<u8>(),
            plaintext_out_len,
        ) || overlaps(
            auth_tag.cast::<u8>(),
            DSTU_SECRETSTREAM_TAG_BYTES,
            plaintext_out.cast_const().cast::<u8>(),
            plaintext_out_len,
        ) {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        if state.is_null() || auth_tag.is_null() || tag_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(ciphertext) = (unsafe { slice_from_raw(ciphertext, ciphertext_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let Some(plaintext_out) = (unsafe { slice_from_raw_mut(plaintext_out, plaintext_out_len) })
        else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let auth_tag = unsafe { std::slice::from_raw_parts(auth_tag, DSTU_SECRETSTREAM_TAG_BYTES) };
        let state = unsafe { &mut *state };
        match state.0.pull(tag_byte, ciphertext, auth_tag, plaintext_out) {
            Ok(tag) => {
                unsafe { *tag_out = DstuTag::from_core(tag) };
                DstuStatus::DSTU_OK
            }
            Err(SecretstreamError::UnknownTag) => DstuStatus::DSTU_ERR_UNKNOWN_TAG,
            Err(SecretstreamError::InvalidLength) => DstuStatus::DSTU_ERR_INVALID_LENGTH,
            Err(SecretstreamError::StreamFinalized | SecretstreamError::CounterExhausted) => {
                DstuStatus::DSTU_ERR_FINALIZED
            }
            Err(SecretstreamError::TagMismatch) => DstuStatus::DSTU_ERR_TAG_MISMATCH,
            Err(_) => unreachable!("pull() has no Random variant reachable here"),
        }
    })
}

/// Frees a pull state. NULL is a no-op.
///
/// # Safety
///
/// `state` must be either NULL or a pointer previously returned by
/// `dstu_secretstream_pull_init`, not already freed - freeing an already-freed pointer is undefined behavior, not merely unsupported; this fn cannot detect or reject it.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_pull_free(state: *mut DstuPullState) {
    guard_void(|| {
        if !state.is_null() {
            drop(unsafe { Box::from_raw(state) });
        }
    })
}

/// Plaintext bytes in every non-final stream-file record (T-284, D-208).
/// Literal values (cbindgen cannot evaluate a path); `ffi_secretstream_file.rs` checks they
/// equal the core's.
pub const DSTU_SECRETSTREAM_CHUNK_BYTES: usize = 8192;
/// A stream file's first bytes: the format version byte plus the 32-byte header.
pub const DSTU_SECRETSTREAM_FILE_PREFIX_BYTES: usize = 33;
/// A record's bytes beyond its ciphertext: tag byte, 4-byte length, auth tag.
pub const DSTU_SECRETSTREAM_RECORD_OVERHEAD_BYTES: usize = 21;
/// The longest record: a full chunk plus the record overhead.
pub const DSTU_SECRETSTREAM_MAX_RECORD_BYTES: usize = 8213;

fn file_status(err: &FileError) -> DstuStatus {
    match err {
        FileError::UnsupportedVersion(_) => DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION,
        FileError::Truncated => DstuStatus::DSTU_ERR_TRUNCATED,
        FileError::ChunkTooLarge(_) => DstuStatus::DSTU_ERR_CHUNK_TOO_LARGE,
        FileError::BadChunkLength(_) => DstuStatus::DSTU_ERR_BAD_CHUNK_LENGTH,
        FileError::UnknownTag => DstuStatus::DSTU_ERR_UNKNOWN_TAG,
        FileError::TrailingData => DstuStatus::DSTU_ERR_TRAILING_DATA,
        FileError::Auth => DstuStatus::DSTU_ERR_TAG_MISMATCH,
        FileError::Finished | FileError::CounterExhausted => DstuStatus::DSTU_ERR_FINALIZED,
        FileError::InvalidLength => DstuStatus::DSTU_ERR_INVALID_LENGTH,
        FileError::Random(_) => DstuStatus::DSTU_ERR_RANDOM,
    }
}

/// Opaque stream-file writer (T-284): the D-208 framing over a push state.
pub struct DstuFileEncryptor(FileEncryptor);

impl DstuFileEncryptor {
    /// For `dstu_box_seal_stream`/`dstu_box512_seal_stream` (T-265), which start the stream under
    /// a key that never leaves the core.
    pub(crate) fn from_core(enc: FileEncryptor) -> Self {
        DstuFileEncryptor(enc)
    }
}

/// Starts a stream file under `key` with a fresh random header. Writes the
/// `DSTU_SECRETSTREAM_FILE_PREFIX_BYTES`-byte prefix (write it first) to `prefix_out`. Returns
/// `DSTU_OK`, `DSTU_ERR_RANDOM` or `DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `key`/`out` must be valid and non-null; `prefix_out` must be valid for writes of
/// `DSTU_SECRETSTREAM_FILE_PREFIX_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_encryptor_new(
    key: *const DstuSecretstreamKey,
    prefix_out: *mut u8,
    out: *mut *mut DstuFileEncryptor,
) -> DstuStatus {
    guard_status(|| {
        if key.is_null() || prefix_out.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match FileEncryptor::init(&unsafe { &*key }.0) {
            Ok((enc, prefix)) => {
                unsafe { std::slice::from_raw_parts_mut(prefix_out, prefix.len()) }
                    .copy_from_slice(&prefix);
                unsafe { *out = Box::into_raw(Box::new(DstuFileEncryptor(enc))) };
                DstuStatus::DSTU_OK
            }
            Err(e) => file_status(&e),
        }
    })
}

/// Seals one full non-final chunk: `chunk_len` must be `DSTU_SECRETSTREAM_CHUNK_BYTES`
/// (`DSTU_ERR_INVALID_LENGTH`), `record_out_cap` at least `DSTU_SECRETSTREAM_MAX_RECORD_BYTES`
/// (`DSTU_ERR_BUFFER_TOO_SMALL`). On `DSTU_OK` the first `DSTU_SECRETSTREAM_MAX_RECORD_BYTES`
/// bytes of `record_out` are the record. `DSTU_ERR_FINALIZED` after `_seal_final`.
///
/// # Safety
///
/// `enc` must be a valid encryptor; `chunk` valid for reads of `chunk_len` bytes and
/// `record_out` for writes of `record_out_cap` bytes when non-null and their lengths are nonzero.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_encryptor_seal_chunk(
    enc: *mut DstuFileEncryptor,
    chunk: *const u8,
    chunk_len: usize,
    record_out: *mut u8,
    record_out_cap: usize,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(
            chunk.cast::<u8>(),
            chunk_len,
            record_out.cast_const().cast::<u8>(),
            record_out_cap,
        ) {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        if enc.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(chunk) = (unsafe { slice_from_raw(chunk, chunk_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let Some(record_out) = (unsafe { slice_from_raw_mut(record_out, record_out_cap) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let Ok(chunk) = <&[u8; CHUNK_BYTES]>::try_from(chunk) else {
            return DstuStatus::DSTU_ERR_INVALID_LENGTH;
        };
        let Some(Ok(record)) = record_out
            .get_mut(..MAX_RECORD_BYTES)
            .map(<&mut [u8; MAX_RECORD_BYTES]>::try_from)
        else {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        };
        match unsafe { &mut *enc }.0.seal_chunk(chunk, record) {
            Ok(()) => DstuStatus::DSTU_OK,
            Err(e) => file_status(&e),
        }
    })
}

/// Seals the last `0..=DSTU_SECRETSTREAM_CHUNK_BYTES` bytes as the `Final` record
/// (`DSTU_ERR_INVALID_LENGTH` if longer). `record_out_cap` must be at least `last_len +
/// DSTU_SECRETSTREAM_RECORD_OVERHEAD_BYTES` (`DSTU_ERR_BUFFER_TOO_SMALL`); the record's length is
/// written to `*record_len`. `DSTU_ERR_FINALIZED` if called twice.
///
/// # Safety
///
/// `enc`/`record_len` must be valid and non-null; `last` valid for reads of `last_len` bytes and
/// `record_out` for writes of `record_out_cap` bytes when non-null and their lengths are nonzero.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_encryptor_seal_final(
    enc: *mut DstuFileEncryptor,
    last: *const u8,
    last_len: usize,
    record_out: *mut u8,
    record_out_cap: usize,
    record_len: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(
            last.cast::<u8>(),
            last_len,
            record_out.cast_const().cast::<u8>(),
            record_out_cap,
        ) {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        if enc.is_null() || record_len.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(last) = (unsafe { slice_from_raw(last, last_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let Some(record_out) = (unsafe { slice_from_raw_mut(record_out, record_out_cap) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        if last.len() > CHUNK_BYTES {
            return DstuStatus::DSTU_ERR_INVALID_LENGTH;
        }
        if record_out.len() < last.len() + RECORD_OVERHEAD_BYTES {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        match unsafe { &mut *enc }.0.seal_final(last, record_out) {
            Ok(n) => {
                unsafe { *record_len = n };
                DstuStatus::DSTU_OK
            }
            Err(e) => file_status(&e),
        }
    })
}

/// Frees a stream-file encryptor. NULL is a no-op.
///
/// # Safety
///
/// `enc` must be NULL or a pointer from `dstu_secretstream_file_encryptor_new`, not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_encryptor_free(enc: *mut DstuFileEncryptor) {
    guard_void(|| {
        if !enc.is_null() {
            drop(unsafe { Box::from_raw(enc) });
        }
    })
}

/// Opaque stream-file reader (T-284). Contract: read exactly `_next_len` bytes and `_feed` them;
/// if the input ends first, call `_finish`. After a format or authentication error every later
/// call returns `DSTU_ERR_FINALIZED`, and `_last_error` gives the core's message.
pub struct DstuFileDecryptor {
    inner: FileDecryptor,
    last_error: Option<CString>,
}

impl DstuFileDecryptor {
    /// For `dstu_box_open_stream`/`dstu_box512_open_stream` (T-265).
    pub(crate) fn from_core(inner: FileDecryptor) -> Self {
        DstuFileDecryptor {
            inner,
            last_error: None,
        }
    }

    fn record(&mut self, result: Result<usize, FileError>, len_out: *mut usize) -> DstuStatus {
        match result {
            Ok(n) => {
                unsafe { *len_out = n };
                DstuStatus::DSTU_OK
            }
            Err(e) => {
                if self.last_error.is_none() && !matches!(e, FileError::InvalidLength) {
                    self.last_error = CString::new(e.to_string()).ok();
                }
                file_status(&e)
            }
        }
    }
}

/// Starts reading a stream file under `key`. Returns NULL if `key` is NULL.
///
/// # Safety
///
/// `key` must be NULL or a valid key handle.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_decryptor_new(
    key: *const DstuSecretstreamKey,
) -> *mut DstuFileDecryptor {
    guard_ptr(|| {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        Box::into_raw(Box::new(DstuFileDecryptor {
            inner: FileDecryptor::new(&unsafe { &*key }.0),
            last_error: None,
        }))
    })
}

/// How many bytes `_feed` wants next; 0 once finished or failed, and for NULL.
///
/// # Safety
///
/// `dec` must be NULL or a valid decryptor.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_decryptor_next_len(
    dec: *const DstuFileDecryptor,
) -> usize {
    guard_usize(|| {
        if dec.is_null() {
            return 0;
        }
        unsafe { &*dec }.inner.next_len()
    })
}

/// Consumes exactly `_next_len` bytes (`DSTU_ERR_INVALID_LENGTH` otherwise, and the call is
/// ignored). `plaintext_out_cap` must be at least `DSTU_SECRETSTREAM_CHUNK_BYTES`
/// (`DSTU_ERR_BUFFER_TOO_SMALL`). On `DSTU_OK`, `*plaintext_len` plaintext bytes (0 unless a
/// non-final record just verified) are at the start of `plaintext_out`.
///
/// # Safety
///
/// `dec`/`plaintext_len` must be valid and non-null; `input` valid for reads of `input_len` bytes
/// and `plaintext_out` for writes of `plaintext_out_cap` bytes when non-null and nonzero.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_decryptor_feed(
    dec: *mut DstuFileDecryptor,
    input: *const u8,
    input_len: usize,
    plaintext_out: *mut u8,
    plaintext_out_cap: usize,
    plaintext_len: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(
            input.cast::<u8>(),
            input_len,
            plaintext_out.cast_const().cast::<u8>(),
            plaintext_out_cap,
        ) {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        if dec.is_null() || plaintext_len.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(input) = (unsafe { slice_from_raw(input, input_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let Some(plaintext_out) = (unsafe { slice_from_raw_mut(plaintext_out, plaintext_out_cap) })
        else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        if plaintext_out.len() < CHUNK_BYTES {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        let dec = unsafe { &mut *dec };
        let result = dec.inner.feed(input, plaintext_out);
        dec.record(result, plaintext_len)
    })
}

/// Call when the input ended before `_next_len` bytes arrived. `DSTU_ERR_TRUNCATED` if no
/// `Final` record verified; otherwise `DSTU_OK` with the `Final` chunk's plaintext
/// (`*plaintext_len` bytes) in `plaintext_out`. Same buffer rules as `_feed`.
///
/// # Safety
///
/// As `dstu_secretstream_file_decryptor_feed`.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_decryptor_finish(
    dec: *mut DstuFileDecryptor,
    plaintext_out: *mut u8,
    plaintext_out_cap: usize,
    plaintext_len: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if dec.is_null() || plaintext_len.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(plaintext_out) = (unsafe { slice_from_raw_mut(plaintext_out, plaintext_out_cap) })
        else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        if plaintext_out.len() < CHUNK_BYTES {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        let dec = unsafe { &mut *dec };
        let result = dec.inner.finish(plaintext_out);
        dec.record(result, plaintext_len)
    })
}

/// The core's message for the error that failed this decryptor (NUL-terminated, owned by the
/// handle, valid until it is freed), or NULL if it has not failed (or `dec` is NULL).
///
/// # Safety
///
/// `dec` must be NULL or a valid decryptor.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_decryptor_last_error(
    dec: *const DstuFileDecryptor,
) -> *const c_char {
    guard_const_ptr(|| {
        if dec.is_null() {
            return std::ptr::null();
        }
        unsafe { &*dec }
            .last_error
            .as_ref()
            .map_or(std::ptr::null(), |m| m.as_ptr())
    })
}

/// Frees a stream-file decryptor. NULL is a no-op.
///
/// # Safety
///
/// `dec` must be NULL or a pointer from `dstu_secretstream_file_decryptor_new`, not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretstream_file_decryptor_free(dec: *mut DstuFileDecryptor) {
    guard_void(|| {
        if !dec.is_null() {
            drop(unsafe { Box::from_raw(dec) });
        }
    })
}
