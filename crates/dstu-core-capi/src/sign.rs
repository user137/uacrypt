//! `crypto_sign` C ABI (`dstu_core::crypto_sign`) - DSTU 4145 signatures. `dstu_sign`/
//! `dstu_verify` hash the message internally (Kupyna-256); `dstu_sign_digest`/`dstu_verify_digest`
//! take an already-computed digest directly, for a caller hashing a large/streamed message
//! incrementally (see the wrapped Rust module's own doc comment, T-113).

use crate::error::DstuStatus;
use crate::util::{guard_bool, guard_ptr, guard_status, guard_void, slice_from_raw};
use dstu_core::crypto_sign::{Signature, SigningKey, VerifyingKey};

pub const DSTU_SIGN_PRIVATE_KEY_BYTES: usize = 21;
pub const DSTU_SIGN_PUBLIC_KEY_BYTES: usize = 42;
pub const DSTU_SIGN_SIGNATURE_BYTES: usize = 42;
pub const DSTU_SIGN_DIGEST_BYTES: usize = 32;

/// Opaque signing-key handle. `dstu_sign_key_free`'s `Box::from_raw` fires the wrapped
/// `SigningKey`'s own `Zeroize`-on-`Drop` impl.
pub struct DstuSigningKey(SigningKey);

/// Generates a fresh signing key from the OS CSPRNG. Returns `DSTU_OK` (writing `*out`) or
/// `DSTU_ERR_RANDOM`/`DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `out` must be a valid, non-null pointer to a `*mut DstuSigningKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_sign_key_generate(out: *mut *mut DstuSigningKey) -> DstuStatus {
    guard_status(|| {
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match SigningKey::generate() {
            Ok(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuSigningKey(key))) };
                DstuStatus::DSTU_OK
            }
            Err(_) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Builds a signing key from a big-endian `DSTU_SIGN_PRIVATE_KEY_BYTES`-byte scalar `d`. Returns
/// `DSTU_ERR_INVALID_KEY` if `d` is zero or >= the curve order, `DSTU_ERR_NULL_POINTER` if `d`/
/// `out` is NULL.
///
/// # Safety
///
/// `d` must be valid for reads of `DSTU_SIGN_PRIVATE_KEY_BYTES` bytes when non-null; `out` must
/// be a valid, non-null pointer to a `*mut DstuSigningKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_sign_key_from_bytes(
    d: *const u8,
    out: *mut *mut DstuSigningKey,
) -> DstuStatus {
    guard_status(|| {
        if d.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let mut bytes = [0u8; DSTU_SIGN_PRIVATE_KEY_BYTES];
        bytes
            .copy_from_slice(unsafe { std::slice::from_raw_parts(d, DSTU_SIGN_PRIVATE_KEY_BYTES) });
        match SigningKey::from_bytes(&bytes) {
            Some(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuSigningKey(key))) };
                DstuStatus::DSTU_OK
            }
            None => DstuStatus::DSTU_ERR_INVALID_KEY,
        }
    })
}

/// Copies `d`'s big-endian `DSTU_SIGN_PRIVATE_KEY_BYTES`-byte encoding into `out`. **The caller
/// must `dstu_memzero()` this once done** - this function copies secret material into a
/// caller-owned buffer the wrapped `SigningKey`'s own `Zeroize`-on-`Drop` impl cannot reach. A
/// NULL `key`/`out` is a no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_SIGN_PRIVATE_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_sign_key_bytes(key: *const DstuSigningKey, out: *mut u8) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let bytes = key.0.to_bytes();
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_SIGN_PRIVATE_KEY_BYTES) };
        out.copy_from_slice(&bytes);
    })
}

/// Frees a signing key. NULL is a no-op.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by `dstu_sign_key_generate`/
/// `dstu_sign_key_from_bytes`, not already freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_sign_key_free(key: *mut DstuSigningKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// Opaque verifying-key (public key) handle.
pub struct DstuVerifyingKey(VerifyingKey);

/// Derives the public verifying key for `key` - infallible. Returns NULL if `key` is NULL.
///
/// # Safety
///
/// `key` must be either NULL or a valid pointer from `dstu_sign_key_generate`/
/// `dstu_sign_key_from_bytes`.
#[no_mangle]
pub unsafe extern "C" fn dstu_sign_verifying_key(
    key: *const DstuSigningKey,
) -> *mut DstuVerifyingKey {
    guard_ptr(|| {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        let key = unsafe { &*key };
        Box::into_raw(Box::new(DstuVerifyingKey(key.0.verifying_key())))
    })
}

/// Copies the key's plain `x || y` `DSTU_SIGN_PUBLIC_KEY_BYTES`-byte encoding into `out`
/// (**not** the DSTU 4145 standard's own compressed point encoding - see the wrapped Rust
/// module's own doc comment). A NULL `key`/`out` is a no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_SIGN_PUBLIC_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_verifying_key_to_bytes(key: *const DstuVerifyingKey, out: *mut u8) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let bytes = key.0.to_uncompressed_bytes();
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_SIGN_PUBLIC_KEY_BYTES) };
        out.copy_from_slice(&bytes);
    })
}

/// Builds a verifying key from `DSTU_SIGN_PUBLIC_KEY_BYTES` bytes of plain `x || y` encoding -
/// infallible, no validation that the point is actually on the curve (matches the wrapped Rust
/// function's own `from_uncompressed_bytes` convention). Returns NULL if `bytes` is NULL.
///
/// # Safety
///
/// `bytes` must be valid for reads of `DSTU_SIGN_PUBLIC_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_verifying_key_from_bytes(bytes: *const u8) -> *mut DstuVerifyingKey {
    guard_ptr(|| {
        if bytes.is_null() {
            return std::ptr::null_mut();
        }
        let mut arr = [0u8; DSTU_SIGN_PUBLIC_KEY_BYTES];
        arr.copy_from_slice(unsafe {
            std::slice::from_raw_parts(bytes, DSTU_SIGN_PUBLIC_KEY_BYTES)
        });
        Box::into_raw(Box::new(DstuVerifyingKey(
            VerifyingKey::from_uncompressed_bytes(&arr),
        )))
    })
}

/// Frees a verifying key. NULL is a no-op.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by `dstu_sign_verifying_key`/
/// `dstu_verifying_key_from_bytes`, not already freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_verifying_key_free(key: *mut DstuVerifyingKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// Signs `message`, hashing it with Kupyna-256 internally and deriving the ephemeral nonce
/// deterministically - infallible, no RNG dependency. A NULL `key`/`sig_out`, or a NULL `message`
/// with `message_len > 0`, is a no-op.
///
/// # Safety
///
/// `message` must be valid for reads of `message_len` bytes when non-null and `message_len > 0`;
/// `sig_out` must be valid for writes of `DSTU_SIGN_SIGNATURE_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_sign(
    key: *const DstuSigningKey,
    message: *const u8,
    message_len: usize,
    sig_out: *mut u8,
) {
    guard_void(|| {
        if key.is_null() || sig_out.is_null() {
            return;
        }
        let Some(message) = (unsafe { slice_from_raw(message, message_len) }) else {
            return;
        };
        let key = unsafe { &*key };
        let sig = key.0.sign(message);
        let sig_out = unsafe { std::slice::from_raw_parts_mut(sig_out, DSTU_SIGN_SIGNATURE_BYTES) };
        sig_out.copy_from_slice(&sig.to_bytes());
    })
}

/// Signs an already-computed `DSTU_SIGN_DIGEST_BYTES`-byte Kupyna-256 digest directly - for a
/// message hashed incrementally rather than held whole in memory. Same null-handling convention
/// as [`dstu_sign`].
///
/// # Safety
///
/// `digest` must be valid for reads of `DSTU_SIGN_DIGEST_BYTES` bytes when non-null; `sig_out`
/// must be valid for writes of `DSTU_SIGN_SIGNATURE_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_sign_digest(
    key: *const DstuSigningKey,
    digest: *const u8,
    sig_out: *mut u8,
) {
    guard_void(|| {
        if key.is_null() || digest.is_null() || sig_out.is_null() {
            return;
        }
        let mut d = [0u8; DSTU_SIGN_DIGEST_BYTES];
        d.copy_from_slice(unsafe { std::slice::from_raw_parts(digest, DSTU_SIGN_DIGEST_BYTES) });
        let key = unsafe { &*key };
        let sig = key.0.sign_digest(&d);
        let sig_out = unsafe { std::slice::from_raw_parts_mut(sig_out, DSTU_SIGN_SIGNATURE_BYTES) };
        sig_out.copy_from_slice(&sig.to_bytes());
    })
}

/// Verifies `sig` over `message` under `key`. Returns `false` for a NULL `key`/`sig` (a misuse
/// case with no distinct code to report through a plain `bool`), a NULL `message` with
/// `message_len > 0`, or an actual verification failure - a signature either verifies or it
/// doesn't, this is the answer either way.
///
/// # Safety
///
/// `message` must be valid for reads of `message_len` bytes when non-null and `message_len > 0`;
/// `sig` must be valid for reads of `DSTU_SIGN_SIGNATURE_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_verify(
    key: *const DstuVerifyingKey,
    message: *const u8,
    message_len: usize,
    sig: *const u8,
) -> bool {
    guard_bool(|| {
        if key.is_null() || sig.is_null() {
            return false;
        }
        let Some(message) = (unsafe { slice_from_raw(message, message_len) }) else {
            return false;
        };
        let mut sig_bytes = [0u8; DSTU_SIGN_SIGNATURE_BYTES];
        sig_bytes
            .copy_from_slice(unsafe { std::slice::from_raw_parts(sig, DSTU_SIGN_SIGNATURE_BYTES) });
        let signature = Signature::from_bytes(&sig_bytes);
        let key = unsafe { &*key };
        key.0.verify(message, &signature)
    })
}

/// Verifies `sig` over an already-computed `DSTU_SIGN_DIGEST_BYTES`-byte digest directly. Same
/// null-handling convention as [`dstu_verify`].
///
/// # Safety
///
/// `digest` must be valid for reads of `DSTU_SIGN_DIGEST_BYTES` bytes when non-null; `sig` must
/// be valid for reads of `DSTU_SIGN_SIGNATURE_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_verify_digest(
    key: *const DstuVerifyingKey,
    digest: *const u8,
    sig: *const u8,
) -> bool {
    guard_bool(|| {
        if key.is_null() || digest.is_null() || sig.is_null() {
            return false;
        }
        let mut d = [0u8; DSTU_SIGN_DIGEST_BYTES];
        d.copy_from_slice(unsafe { std::slice::from_raw_parts(digest, DSTU_SIGN_DIGEST_BYTES) });
        let mut sig_bytes = [0u8; DSTU_SIGN_SIGNATURE_BYTES];
        sig_bytes
            .copy_from_slice(unsafe { std::slice::from_raw_parts(sig, DSTU_SIGN_SIGNATURE_BYTES) });
        let signature = Signature::from_bytes(&sig_bytes);
        let key = unsafe { &*key };
        key.0.verify_digest(&d, &signature)
    })
}
