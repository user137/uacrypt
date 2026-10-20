//! `crypto_box384` C ABI (`dstu_core::crypto_box384`) - the `l(p)=384` (E384/1) sibling of
//! [`crate::crypto_box`] and [`crate::box384`] (T-297, `docs/DECISIONS.md` D-245), generated from
//! `box384.rs`: same names with `384`, same handles and statuses. Format v3 only; no format 2
//! exists at this size.
//!
//! **`DSTU_ERR_TAG_MISMATCH` is reused for [`OpenError::InvalidCiphertext`]**, as in
//! [`crate::crypto_box`]: `dstu_core::crypto_box384::OpenError` already collapses wrong key,
//! tampered segment and bad recovered seed length into one variant.

use crate::error::DstuStatus;
use crate::secretstream::{DstuFileDecryptor, DstuFileEncryptor};
use crate::util::{
    guard_ptr, guard_status, guard_void, overlaps, slice_from_raw, slice_from_raw_mut,
};
use dstu_core::crypto_box384::{
    open, open_stream, seal, seal_stream, sealed_len, OpenError, PublicKey, SealError, SecretKey,
    OPEN_STREAM_PREFIX_BYTES,
};

pub const DSTU_BOX384_SECRETKEY_BYTES: usize = 48;
pub const DSTU_BOX384_PUBLICKEY_BYTES: usize = 48;
/// The smallest sealed message (T-265, D-239: format v3, `version (1) || KEM ciphertext (176) ||
/// stream file` with one empty `Final` record). `dstu_box384_open`'s plaintext is at most `sealed_len -
/// DSTU_BOX384_OPEN_MIN_OVERHEAD` bytes; `dstu_box384_sealed_len` gives `dstu_box384_seal`'s exact output size.
pub const DSTU_BOX384_OPEN_MIN_OVERHEAD: usize = 231;
/// The bytes `dstu_box384_seal_stream` writes first: the box prefix and the stream file's own prefix.
pub const DSTU_BOX384_SEAL_STREAM_PREFIX_BYTES: usize = 210;
/// The bytes `dstu_box384_open_stream` reads: the version byte and the KEM ciphertext.
pub const DSTU_BOX384_OPEN_STREAM_PREFIX_BYTES: usize = 177;

/// Opaque `crypto_box384` secret-key handle. `dstu_box384_secretkey_free`'s `Box::from_raw` fires
/// the wrapped `SecretKey`'s own `Zeroize`-on-`Drop` impl.
pub struct DstuBox384SecretKey(SecretKey);

/// Opaque `crypto_box384` public-key handle.
pub struct DstuBox384PublicKey(PublicKey);

/// Generates a fresh secret key from the OS CSPRNG. Returns `DSTU_OK` (writing `*out`) or
/// `DSTU_ERR_RANDOM`/`DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `out` must be a valid, non-null pointer to a `*mut DstuBox384SecretKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_secretkey_generate(
    out: *mut *mut DstuBox384SecretKey,
) -> DstuStatus {
    guard_status(|| {
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match SecretKey::generate() {
            Ok(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuBox384SecretKey(key))) };
                DstuStatus::DSTU_OK
            }
            Err(_) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Builds a secret key from a big-endian `DSTU_BOX384_SECRETKEY_BYTES`-byte scalar. Returns
/// `DSTU_ERR_INVALID_KEY` if it's outside the valid range `{2, ..., n-2}`,
/// `DSTU_ERR_NULL_POINTER` if `bytes`/`out` is NULL.
///
/// # Safety
///
/// `bytes` must be valid for reads of `DSTU_BOX384_SECRETKEY_BYTES` bytes when non-null; `out`
/// must be a valid, non-null pointer to a `*mut DstuBox384SecretKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_secretkey_from_bytes(
    bytes: *const u8,
    out: *mut *mut DstuBox384SecretKey,
) -> DstuStatus {
    guard_status(|| {
        if bytes.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        // T-242: the stack copy of the key is wiped when this returns.
        let mut arr = zeroize::Zeroizing::new([0u8; DSTU_BOX384_SECRETKEY_BYTES]);
        arr.copy_from_slice(unsafe {
            std::slice::from_raw_parts(bytes, DSTU_BOX384_SECRETKEY_BYTES)
        });
        match SecretKey::from_bytes(&arr) {
            Some(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuBox384SecretKey(key))) };
                DstuStatus::DSTU_OK
            }
            None => DstuStatus::DSTU_ERR_INVALID_KEY,
        }
    })
}

/// Copies the key's big-endian `DSTU_BOX384_SECRETKEY_BYTES`-byte encoding into `out`. **The
/// caller must `dstu_memzero()` this once done** - same gap `dstu_box_secretkey_bytes` has. A NULL
/// `key`/`out` is a no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_BOX384_SECRETKEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_secretkey_bytes(
    key: *const DstuBox384SecretKey,
    out: *mut u8,
) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let bytes = key.0.to_bytes();
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_BOX384_SECRETKEY_BYTES) };
        out.copy_from_slice(&bytes);
    })
}

/// Derives the public key for `key` - infallible. Returns NULL if `key` is NULL.
///
/// # Safety
///
/// `key` must be either NULL or a valid pointer from `dstu_box384_secretkey_generate`/
/// `dstu_box384_secretkey_from_bytes`.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_secretkey_public_key(
    key: *const DstuBox384SecretKey,
) -> *mut DstuBox384PublicKey {
    guard_ptr(|| {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        let key = unsafe { &*key };
        Box::into_raw(Box::new(DstuBox384PublicKey(key.0.public_key())))
    })
}

/// Frees a secret key. NULL is a no-op.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by `dstu_box384_secretkey_generate`/
/// `dstu_box384_secretkey_from_bytes`, not already freed - freeing an already-freed pointer is undefined behavior, not merely unsupported; this fn cannot detect or reject it.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_secretkey_free(key: *mut DstuBox384SecretKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// Builds a public key from its compressed `DSTU_BOX384_PUBLICKEY_BYTES`-byte `x`-coordinate
/// encoding (`crypto_box384`'s own module doc explains why `x` alone is a safe compression).
/// Returns `DSTU_ERR_INVALID_KEY` if `bytes` isn't a valid field element, or doesn't reconstruct to
/// a point inside the base point's own prime-order subgroup; `DSTU_ERR_NULL_POINTER` if
/// `bytes`/`out` is NULL.
///
/// # Safety
///
/// `bytes` must be valid for reads of `DSTU_BOX384_PUBLICKEY_BYTES` bytes when non-null; `out`
/// must be a valid, non-null pointer to a `*mut DstuBox384PublicKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_publickey_from_bytes(
    bytes: *const u8,
    out: *mut *mut DstuBox384PublicKey,
) -> DstuStatus {
    guard_status(|| {
        if bytes.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let mut arr = [0u8; DSTU_BOX384_PUBLICKEY_BYTES];
        arr.copy_from_slice(unsafe {
            std::slice::from_raw_parts(bytes, DSTU_BOX384_PUBLICKEY_BYTES)
        });
        match PublicKey::from_bytes(&arr) {
            Some(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuBox384PublicKey(key))) };
                DstuStatus::DSTU_OK
            }
            None => DstuStatus::DSTU_ERR_INVALID_KEY,
        }
    })
}

/// Copies the key's `DSTU_BOX384_PUBLICKEY_BYTES`-byte encoding into `out` - not secret, no
/// `dstu_memzero` needed afterward. A NULL `key`/`out` is a no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_BOX384_PUBLICKEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_publickey_bytes(
    key: *const DstuBox384PublicKey,
    out: *mut u8,
) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let bytes = key.0.to_bytes();
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_BOX384_PUBLICKEY_BYTES) };
        out.copy_from_slice(&bytes);
    })
}

/// Frees a public key. NULL is a no-op.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by
/// `dstu_box384_secretkey_public_key`/`dstu_box384_publickey_from_bytes`, not already freed - freeing an already-freed pointer is undefined behavior, not merely unsupported; this fn cannot detect or reject it.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_publickey_free(key: *mut DstuBox384PublicKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// Encrypts `message` (any length) to `recipient` in one call (format v3, T-265) - the whole
/// message is read from `message` and held in `sealed_out`; `dstu_box384_seal_stream` is the
/// bounded-memory form. `sealed_out` must have capacity >= `dstu_box384_sealed_len(message_len)` -
/// checked before any crypto work runs; `DSTU_ERR_BUFFER_TOO_SMALL` if not. On `DSTU_OK`,
/// `*sealed_len_out` is exactly that length.
///
/// # Safety
///
/// `recipient`/`sealed_len_out` must be non-null; `message` must be valid for reads of
/// `message_len` bytes when non-null and `message_len > 0`; `sealed_out` must be valid for writes
/// of `sealed_out_cap` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_seal(
    recipient: *const DstuBox384PublicKey,
    message: *const u8,
    message_len: usize,
    sealed_out: *mut u8,
    sealed_out_cap: usize,
    sealed_len_out: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(
            message.cast::<u8>(),
            message_len,
            sealed_out.cast_const().cast::<u8>(),
            sealed_out_cap,
        ) {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        if recipient.is_null() || sealed_len_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(message) = (unsafe { slice_from_raw(message, message_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let Some(required) = sealed_len(message_len) else {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        };
        if sealed_out_cap < required {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        let Some(sealed_out) = (unsafe { slice_from_raw_mut(sealed_out, sealed_out_cap) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let recipient = unsafe { &*recipient };
        match seal(message, &recipient.0) {
            Ok(sealed) => {
                sealed_out[..sealed.len()].copy_from_slice(&sealed);
                unsafe { *sealed_len_out = sealed.len() };
                DstuStatus::DSTU_OK
            }
            Err(SealError::Random(_)) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Decrypts `sealed` (format v3, from [`dstu_box384_seal`] or [`dstu_box384_seal_stream`]) under `secret`
/// in one call - `dstu_box384_open_stream` is the bounded-memory form. `plaintext_out` must have
/// capacity >= `sealed_len - DSTU_BOX384_OPEN_MIN_OVERHEAD` (0 when `sealed_len` is smaller) - checked
/// before any crypto work runs; `DSTU_ERR_BUFFER_TOO_SMALL` if not. On `DSTU_OK`,
/// `*plaintext_len_out` is the plaintext length, at most that capacity (the record framing makes
/// it shorter for multi-chunk messages). `DSTU_ERR_UNSUPPORTED_VERSION` for a blob whose first byte
/// is not 3 (D-239); `DSTU_ERR_TRUNCATED` if it is too short or its
/// stream ends early. On `DSTU_ERR_TAG_MISMATCH` (wrong key, or any tampered wire segment -
/// deliberately not distinguished further, see this module's own top doc comment), `plaintext_out`
/// is left zeroed, never partially-trusted plaintext.
///
/// # Safety
///
/// `secret`/`plaintext_len_out` must be non-null; `sealed` must be valid for reads of
/// `sealed_len` bytes when non-null and `sealed_len > 0`; `plaintext_out` must be valid for
/// writes of `plaintext_out_cap` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_open(
    secret: *const DstuBox384SecretKey,
    sealed: *const u8,
    sealed_len: usize,
    plaintext_out: *mut u8,
    plaintext_out_cap: usize,
    plaintext_len_out: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(
            sealed.cast::<u8>(),
            sealed_len,
            plaintext_out.cast_const().cast::<u8>(),
            plaintext_out_cap,
        ) {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        if secret.is_null() || plaintext_len_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(sealed) = (unsafe { slice_from_raw(sealed, sealed_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let required = sealed_len.saturating_sub(DSTU_BOX384_OPEN_MIN_OVERHEAD);
        if plaintext_out_cap < required {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        let Some(plaintext_out) = (unsafe { slice_from_raw_mut(plaintext_out, plaintext_out_cap) })
        else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let secret = unsafe { &*secret };
        match open(sealed, &secret.0) {
            Ok(plaintext) => {
                plaintext_out[..plaintext.len()].copy_from_slice(&plaintext);
                unsafe { *plaintext_len_out = plaintext.len() };
                DstuStatus::DSTU_OK
            }
            Err(OpenError::InvalidCiphertext) => {
                plaintext_out.fill(0);
                DstuStatus::DSTU_ERR_TAG_MISMATCH
            }
            Err(OpenError::UnsupportedVersion) => DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION,
            Err(OpenError::Truncated) => DstuStatus::DSTU_ERR_TRUNCATED,
        }
    })
}

/// Writes `dstu_box384_seal`'s exact output length for a `message_len`-byte message to `*len_out`.
/// Returns `DSTU_OK`, `DSTU_ERR_INVALID_LENGTH` if it would overflow `size_t`, or
/// `DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `len_out` must be NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_sealed_len(
    message_len: usize,
    len_out: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if len_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match sealed_len(message_len) {
            Some(len) => {
                unsafe { *len_out = len };
                DstuStatus::DSTU_OK
            }
            None => DstuStatus::DSTU_ERR_INVALID_LENGTH,
        }
    })
}

/// Starts sealing a message of any length to `recipient` with bounded memory (T-265): writes the
/// `DSTU_BOX384_SEAL_STREAM_PREFIX_BYTES`-byte prefix (write it first) to `prefix_out` and a stream-file
/// encryptor to `*out` - drive it with `dstu_secretstream_file_encryptor_seal_chunk`/`_seal_final`
/// and free it with `dstu_secretstream_file_encryptor_free`. The output is what `dstu_box384_seal`
/// returns. Returns `DSTU_OK`, `DSTU_ERR_RANDOM` or `DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `recipient` must be NULL or a valid public-key handle; `prefix_out` must be NULL or valid for
/// writes of `DSTU_BOX384_SEAL_STREAM_PREFIX_BYTES` bytes; `out` must be NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_seal_stream(
    recipient: *const DstuBox384PublicKey,
    prefix_out: *mut u8,
    out: *mut *mut DstuFileEncryptor,
) -> DstuStatus {
    guard_status(|| {
        if recipient.is_null() || prefix_out.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match seal_stream(&unsafe { &*recipient }.0) {
            Ok((enc, prefix)) => {
                unsafe { std::slice::from_raw_parts_mut(prefix_out, prefix.len()) }
                    .copy_from_slice(&prefix);
                unsafe { *out = Box::into_raw(Box::new(DstuFileEncryptor::from_core(enc))) };
                DstuStatus::DSTU_OK
            }
            Err(SealError::Random(_)) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Starts opening a sealed message with bounded memory (T-265): `prefix` is its first
/// `DSTU_BOX384_OPEN_STREAM_PREFIX_BYTES` bytes. On `DSTU_OK`, `*out` is a stream-file decryptor for
/// everything after them - drive it with `dstu_secretstream_file_decryptor_next_len`/`_feed`/
/// `_finish` and free it with `dstu_secretstream_file_decryptor_free`. Returns
/// `DSTU_ERR_UNSUPPORTED_VERSION` if `prefix` does not start with 3 (checked before `secret` is
/// used), `DSTU_ERR_TAG_MISMATCH` if the KEM ciphertext does not open under `secret`, or
/// `DSTU_ERR_NULL_POINTER`; `*out` is not written on failure.
///
/// # Safety
///
/// `secret` must be NULL or a valid secret-key handle; `prefix` must be NULL or valid for reads of
/// `DSTU_BOX384_OPEN_STREAM_PREFIX_BYTES` bytes; `out` must be NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn dstu_box384_open_stream(
    secret: *const DstuBox384SecretKey,
    prefix: *const u8,
    out: *mut *mut DstuFileDecryptor,
) -> DstuStatus {
    guard_status(|| {
        if secret.is_null() || prefix.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let mut prefix_bytes = [0u8; OPEN_STREAM_PREFIX_BYTES];
        prefix_bytes.copy_from_slice(unsafe {
            std::slice::from_raw_parts(prefix, OPEN_STREAM_PREFIX_BYTES)
        });
        match open_stream(&prefix_bytes, &unsafe { &*secret }.0) {
            Ok(dec) => {
                unsafe { *out = Box::into_raw(Box::new(DstuFileDecryptor::from_core(dec))) };
                DstuStatus::DSTU_OK
            }
            Err(OpenError::UnsupportedVersion) => DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION,
            Err(OpenError::InvalidCiphertext) => DstuStatus::DSTU_ERR_TAG_MISMATCH,
            Err(OpenError::Truncated) => DstuStatus::DSTU_ERR_TRUNCATED,
        }
    })
}
