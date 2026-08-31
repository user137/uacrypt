//! `crypto_secretstream` C ABI (`dstu_core::crypto_secretstream`) - raw push/pull only, matching
//! the Rust API 1:1 (no idiomatic-C stream wrapper - that is a later consumer's job, per D-148/
//! `docs/bindings-strategy.md`'s own note that this crate has no idiomatic-language step). `tag_byte`
//! passed into `dstu_secretstream_pull` is untrusted wire input - see the wrapped Rust module's own
//! doc comment for why it is folded into the AAD verified against `auth_tag`.

use crate::error::DstuStatus;
use crate::util::{
    guard_bool, guard_ptr, guard_status, guard_void, slice_from_raw, slice_from_raw_mut,
};
use dstu_core::crypto_secretstream::{Key, PullState, PushState, SecretstreamError, Tag};

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
    fn to_core(self) -> Tag {
        match self {
            DstuTag::DSTU_TAG_MESSAGE => Tag::Message,
            DstuTag::DSTU_TAG_PUSH => Tag::Push,
            DstuTag::DSTU_TAG_REKEY => Tag::Rekey,
            DstuTag::DSTU_TAG_FINAL => Tag::Final,
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
        let mut bytes = [0u8; DSTU_SECRETSTREAM_KEY_BYTES];
        bytes.copy_from_slice(unsafe {
            std::slice::from_raw_parts(key, DSTU_SECRETSTREAM_KEY_BYTES)
        });
        Box::into_raw(Box::new(DstuSecretstreamKey(Key::from_bytes(bytes))))
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
/// `DSTU_TAG_FINAL`.
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
    tag: DstuTag,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    tag_out: *mut u8,
) -> DstuStatus {
    guard_status(|| {
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
        match state.0.push(tag.to_core(), plaintext, ciphertext_out) {
            Ok(full_tag) => {
                let tag_out =
                    unsafe { std::slice::from_raw_parts_mut(tag_out, DSTU_SECRETSTREAM_TAG_BYTES) };
                tag_out.copy_from_slice(&full_tag);
                DstuStatus::DSTU_OK
            }
            Err(SecretstreamError::InvalidLength) => DstuStatus::DSTU_ERR_INVALID_LENGTH,
            Err(SecretstreamError::StreamFinalized) => DstuStatus::DSTU_ERR_FINALIZED,
            Err(_) => unreachable!("push() only ever returns InvalidLength/StreamFinalized"),
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
            Err(SecretstreamError::StreamFinalized) => DstuStatus::DSTU_ERR_FINALIZED,
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
