//! `crypto_secretbox` C ABI (`dstu_core::crypto_secretbox`) - seal/open a whole in-memory message
//! under a 32-byte key. Caller-allocates output buffers (D-148 point 3): `sealed_out`/
//! `plaintext_out` must have capacity checked *before* any crypto work runs, never a partial
//! write on `DSTU_ERR_BUFFER_TOO_SMALL`.

use crate::error::DstuStatus;
use crate::util::{guard_ptr, guard_status, guard_void, slice_from_raw, slice_from_raw_mut};
use dstu_core::crypto_secretbox::{open, seal, SecretKey, SecretboxError};

pub const DSTU_SECRETBOX_KEY_BYTES: usize = 32;
/// 32-byte nonce + 16-byte tag.
pub const DSTU_SECRETBOX_OVERHEAD: usize = 48;

/// Opaque `crypto_secretbox` key handle. `dstu_secretbox_key_free`'s `Box::from_raw` fires the
/// wrapped `SecretKey`'s own `Zeroize`-on-`Drop` impl.
pub struct DstuSecretboxKey(SecretKey);

/// Generates a fresh key from the OS CSPRNG. Returns `DSTU_OK` (writing `*out`) or
/// `DSTU_ERR_RANDOM`/`DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `out` must be a valid, non-null pointer to a `*mut DstuSecretboxKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretbox_key_generate(
    out: *mut *mut DstuSecretboxKey,
) -> DstuStatus {
    guard_status(|| {
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match SecretKey::generate() {
            Ok(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuSecretboxKey(key))) };
                DstuStatus::DSTU_OK
            }
            Err(_) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Builds a key from exactly `DSTU_SECRETBOX_KEY_BYTES` bytes. Infallible for a correct call;
/// returns NULL if `key` is NULL.
///
/// # Safety
///
/// `key` must be valid for reads of `DSTU_SECRETBOX_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretbox_key_from_bytes(key: *const u8) -> *mut DstuSecretboxKey {
    guard_ptr(|| {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        let mut bytes = [0u8; DSTU_SECRETBOX_KEY_BYTES];
        bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(key, DSTU_SECRETBOX_KEY_BYTES) });
        Box::into_raw(Box::new(DstuSecretboxKey(SecretKey::from_bytes(bytes))))
    })
}

/// Copies the key's `DSTU_SECRETBOX_KEY_BYTES`-byte encoding into `out`. A NULL `key`/`out` is a
/// no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_SECRETBOX_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretbox_key_bytes(key: *const DstuSecretboxKey, out: *mut u8) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_SECRETBOX_KEY_BYTES) };
        out.copy_from_slice(key.0.as_bytes());
    })
}

/// Frees a key. NULL is a no-op.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by `dstu_secretbox_key_generate`/
/// `dstu_secretbox_key_from_bytes`, not already freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretbox_key_free(key: *mut DstuSecretboxKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// Encrypts and authenticates `plaintext` under `key`, drawing a fresh random nonce internally.
/// `sealed_out` must have capacity >= `plaintext_len + DSTU_SECRETBOX_OVERHEAD` - checked before
/// any crypto work runs; `DSTU_ERR_BUFFER_TOO_SMALL` if not. On `DSTU_OK`,
/// `*sealed_len_out == plaintext_len + DSTU_SECRETBOX_OVERHEAD` exactly.
///
/// # Safety
///
/// `key`/`sealed_len_out` must be non-null; `plaintext` must be valid for reads of
/// `plaintext_len` bytes when non-null and `plaintext_len > 0`; `sealed_out` must be valid for
/// writes of `sealed_out_cap` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretbox_seal(
    key: *const DstuSecretboxKey,
    plaintext: *const u8,
    plaintext_len: usize,
    sealed_out: *mut u8,
    sealed_out_cap: usize,
    sealed_len_out: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if key.is_null() || sealed_len_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(plaintext) = (unsafe { slice_from_raw(plaintext, plaintext_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let required = plaintext_len + DSTU_SECRETBOX_OVERHEAD;
        if sealed_out_cap < required {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        let Some(sealed_out) = (unsafe { slice_from_raw_mut(sealed_out, sealed_out_cap) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let key = unsafe { &*key };
        match seal(&key.0, plaintext) {
            Ok(sealed) => {
                sealed_out[..sealed.len()].copy_from_slice(&sealed);
                unsafe { *sealed_len_out = sealed.len() };
                DstuStatus::DSTU_OK
            }
            Err(SecretboxError::Random(_)) => DstuStatus::DSTU_ERR_RANDOM,
            Err(_) => unreachable!("seal() only ever returns Random"),
        }
    })
}

/// Verifies and decrypts `sealed` (as produced by [`dstu_secretbox_seal`]) under `key`.
/// `sealed_len < DSTU_SECRETBOX_OVERHEAD` -> `DSTU_ERR_TRUNCATED`. `plaintext_out` must have
/// capacity >= `sealed_len - DSTU_SECRETBOX_OVERHEAD` - checked before any crypto work runs;
/// `DSTU_ERR_BUFFER_TOO_SMALL` if not. On `DSTU_OK`,
/// `*plaintext_len_out == sealed_len - DSTU_SECRETBOX_OVERHEAD` exactly. On
/// `DSTU_ERR_TAG_MISMATCH`, `plaintext_out` is left zeroed, never partially-trusted plaintext.
///
/// # Safety
///
/// `key`/`plaintext_len_out` must be non-null; `sealed` must be valid for reads of `sealed_len`
/// bytes when non-null and `sealed_len > 0`; `plaintext_out` must be valid for writes of
/// `plaintext_out_cap` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_secretbox_open(
    key: *const DstuSecretboxKey,
    sealed: *const u8,
    sealed_len: usize,
    plaintext_out: *mut u8,
    plaintext_out_cap: usize,
    plaintext_len_out: *mut usize,
) -> DstuStatus {
    guard_status(|| {
        if key.is_null() || plaintext_len_out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(sealed) = (unsafe { slice_from_raw(sealed, sealed_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        if sealed_len < DSTU_SECRETBOX_OVERHEAD {
            return DstuStatus::DSTU_ERR_TRUNCATED;
        }
        let required = sealed_len - DSTU_SECRETBOX_OVERHEAD;
        if plaintext_out_cap < required {
            return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
        }
        let Some(plaintext_out) = (unsafe { slice_from_raw_mut(plaintext_out, plaintext_out_cap) })
        else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let key = unsafe { &*key };
        match open(&key.0, sealed) {
            Ok(plaintext) => {
                plaintext_out[..plaintext.len()].copy_from_slice(&plaintext);
                unsafe { *plaintext_len_out = plaintext.len() };
                DstuStatus::DSTU_OK
            }
            Err(SecretboxError::TagMismatch) => {
                plaintext_out.fill(0);
                DstuStatus::DSTU_ERR_TAG_MISMATCH
            }
            Err(_) => unreachable!("checked sealed_len above, open() never generates randomness"),
        }
    })
}
