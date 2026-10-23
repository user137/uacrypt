//! `crypto_pwhash` C ABI (`dstu_core::crypto_pwhash`) - Argon2id password hashing into a
//! self-describing, NUL-terminated PHC string. Requires this crate's own `pwhash` feature on
//! `dstu-core` (turned on unconditionally in `Cargo.toml`, matching Python's own precedent).

use crate::error::DstuStatus;
use crate::secretstream::{DstuFileDecryptor, DstuFileEncryptor};
use crate::util::{guard_bool, guard_status, overlaps, slice_from_raw};
use dstu_core::crypto_pwhash::passphrase_file::{
    seal_stream, Header, PassphraseFileError, HEADER_BYTES,
};
use dstu_core::crypto_pwhash::{
    derive_key, hash_password, verify_password, PwHashError, Strength, KEY_BYTES, SALT_BYTES,
};
use std::ffi::CStr;
use std::os::raw::c_char;

/// Salt length for `dstu_pwhash_derive_key` - libsodium's `crypto_pwhash_SALTBYTES`.
pub const DSTU_PWHASH_SALTBYTES: usize = 16;
/// Output length of `dstu_pwhash_derive_key`.
pub const DSTU_PWHASH_KEYBYTES: usize = 32;
/// A passphrase file's first byte (a key-encrypted stream file starts with its version, 2).
pub const DSTU_PASSPHRASE_FILE_CONTAINER_TYPE: u8 = 0x50;
/// The passphrase-file header in front of the stream file (D-240).
pub const DSTU_PASSPHRASE_FILE_HEADER_BYTES: usize = 28;
/// The bytes `dstu_passphrase_file_seal_stream` writes first: the header and the stream file's own
/// prefix.
pub const DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES: usize = 61;
const _: () = assert!(
    DSTU_PWHASH_SALTBYTES == SALT_BYTES
        && DSTU_PWHASH_KEYBYTES == KEY_BYTES
        && DSTU_PASSPHRASE_FILE_HEADER_BYTES == HEADER_BYTES
        && DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES
            == dstu_core::crypto_pwhash::passphrase_file::SEAL_STREAM_PREFIX_BYTES
);

fn pwhash_status(e: &PwHashError) -> DstuStatus {
    match e {
        PwHashError::Random(_) => DstuStatus::DSTU_ERR_RANDOM,
        PwHashError::OutOfMemory => DstuStatus::DSTU_ERR_OUT_OF_MEMORY,
        PwHashError::Hash(_) | PwHashError::Derive(_) => DstuStatus::DSTU_ERR_HASH_ERROR,
    }
}

fn passphrase_file_status(e: &PassphraseFileError) -> DstuStatus {
    match e {
        PassphraseFileError::NotPassphraseFile | PassphraseFileError::UnsupportedFormat { .. } => {
            DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION
        }
        PassphraseFileError::UnsupportedParams { .. } => DstuStatus::DSTU_ERR_UNSUPPORTED_PARAMS,
        PassphraseFileError::EmptyPassphrase => DstuStatus::DSTU_ERR_INVALID_LENGTH,
        PassphraseFileError::PwHash(e) => pwhash_status(e),
    }
}

/// Fixed buffer size for a PHC string produced by `dstu_pwhash_hash_password` - matches
/// libsodium's own `crypto_pwhash_STRBYTES` value exactly (see `docs/DECISIONS.md` D-148 point 3
/// for the hand-counted worst-case-length justification).
pub const DSTU_PWHASH_STRBYTES: usize = 128;

/// Argon2id cost preset - mirrors libsodium's own named `OPSLIMIT`/`MEMLIMIT_*` constants.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstuPwhashStrength {
    DSTU_PWHASH_INTERACTIVE = 0,
    DSTU_PWHASH_MODERATE = 1,
    DSTU_PWHASH_SENSITIVE = 2,
}

/// Maps a raw `DstuPwhashStrength` value from C. The parameter is a `u32`, not the enum itself,
/// because a C/Go/.NET caller can pass any integer and an out-of-range enum value is undefined
/// behavior in Rust (T-240).
fn strength_from_raw(strength: u32) -> Option<Strength> {
    match strength {
        x if x == DstuPwhashStrength::DSTU_PWHASH_INTERACTIVE as u32 => Some(Strength::Interactive),
        x if x == DstuPwhashStrength::DSTU_PWHASH_MODERATE as u32 => Some(Strength::Moderate),
        x if x == DstuPwhashStrength::DSTU_PWHASH_SENSITIVE as u32 => Some(Strength::Sensitive),
        _ => None,
    }
}

/// Hashes `password` into a NUL-terminated PHC string written to `out` (a caller-owned buffer of
/// at least `DSTU_PWHASH_STRBYTES` bytes). Returns `DSTU_ERR_RANDOM` if the OS CSPRNG fails,
/// `DSTU_ERR_OUT_OF_MEMORY` if the preset's memory cannot be allocated, `DSTU_ERR_HASH_ERROR` on
/// an internal Argon2/PHC-encoding failure (not expected in practice for this module's own
/// fixed-length salt), or `DSTU_ERR_NULL_POINTER`. `strength` must be one of the
/// `DSTU_PWHASH_*` values - `DSTU_ERR_INVALID_ARGUMENT` otherwise, checked before any hashing.
///
/// # Safety
///
/// `password` must be valid for reads of `password_len` bytes when non-null and
/// `password_len > 0`; `out` must be valid for writes of `DSTU_PWHASH_STRBYTES` bytes when
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_pwhash_hash_password(
    password: *const u8,
    password_len: usize,
    strength: u32,
    out: *mut c_char,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(
            password.cast::<u8>(),
            password_len,
            out.cast_const().cast::<u8>(),
            DSTU_PWHASH_STRBYTES,
        ) {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        let Some(strength) = strength_from_raw(strength) else {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        };
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(password) = (unsafe { slice_from_raw(password, password_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        match hash_password(password, strength) {
            Ok(hash) => {
                let bytes = hash.as_bytes();
                // `+ 1` for the NUL terminator - never expected to trip for this module's own
                // fixed-length salt/hash/params (D-148 point 3's hand count), checked rather than
                // assumed per this project's own buffer-safety convention.
                if bytes.len() + 1 > DSTU_PWHASH_STRBYTES {
                    return DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL;
                }
                let out = unsafe {
                    std::slice::from_raw_parts_mut(out.cast::<u8>(), DSTU_PWHASH_STRBYTES)
                };
                out[..bytes.len()].copy_from_slice(bytes);
                out[bytes.len()] = 0;
                DstuStatus::DSTU_OK
            }
            Err(e) => pwhash_status(&e),
        }
    })
}

/// Verifies `password` against a NUL-terminated PHC string `hash` (as produced by
/// `dstu_pwhash_hash_password`). Returns `false` for a wrong password, a malformed/unparseable
/// hash string, or a NULL `hash`/malformed-UTF-8 `hash` - matches the wrapped Rust function's own
/// single pass/fail return, nothing for a caller to mishandle by branching differently on the
/// failure cases.
///
/// # Safety
///
/// `password` must be valid for reads of `password_len` bytes when non-null and
/// `password_len > 0`; `hash`, when non-null, must point to a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn dstu_pwhash_verify_password(
    password: *const u8,
    password_len: usize,
    hash: *const c_char,
) -> bool {
    guard_bool(|| {
        if hash.is_null() {
            return false;
        }
        let Some(password) = (unsafe { slice_from_raw(password, password_len) }) else {
            return false;
        };
        let Ok(hash_str) = (unsafe { CStr::from_ptr(hash) }).to_str() else {
            return false;
        };
        verify_password(password, hash_str)
    })
}

/// Derives a `DSTU_PWHASH_KEYBYTES`-byte key from `password` and a `DSTU_PWHASH_SALTBYTES`-byte
/// `salt` into `out` - libsodium's `crypto_pwhash` (Argon2id v1.3, one lane), byte for byte
/// (D-219). Returns `DSTU_ERR_OUT_OF_MEMORY` if the preset's memory cannot be allocated,
/// `DSTU_ERR_INVALID_ARGUMENT` for a `strength` outside `DSTU_PWHASH_*` or an `out` overlapping an
/// input (both checked before Argon2 runs), or `DSTU_ERR_NULL_POINTER`; `out` is not written on
/// failure.
///
/// # Safety
///
/// `password` must be valid for reads of `password_len` bytes when non-null and
/// `password_len > 0`; `salt` must be NULL or valid for reads of `DSTU_PWHASH_SALTBYTES` bytes;
/// `out` must be NULL or valid for writes of `DSTU_PWHASH_KEYBYTES` bytes.
#[no_mangle]
pub unsafe extern "C" fn dstu_pwhash_derive_key(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    strength: u32,
    out: *mut u8,
) -> DstuStatus {
    guard_status(|| {
        if overlaps(password, password_len, out.cast_const(), KEY_BYTES)
            || overlaps(salt, SALT_BYTES, out.cast_const(), KEY_BYTES)
        {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        }
        let Some(strength) = strength_from_raw(strength) else {
            return DstuStatus::DSTU_ERR_INVALID_ARGUMENT;
        };
        if salt.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(password) = (unsafe { slice_from_raw(password, password_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let mut salt_bytes = [0u8; SALT_BYTES];
        salt_bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(salt, SALT_BYTES) });
        match derive_key(password, &salt_bytes, strength) {
            Ok(key) => {
                unsafe { std::slice::from_raw_parts_mut(out, KEY_BYTES) }.copy_from_slice(&*key);
                DstuStatus::DSTU_OK
            }
            Err(e) => pwhash_status(&e),
        }
    })
}

/// Checks a passphrase file's first `DSTU_PASSPHRASE_FILE_HEADER_BYTES` bytes without running
/// Argon2, so a reader can refuse a wrong file before asking for a passphrase. Returns `DSTU_OK`,
/// `DSTU_ERR_UNSUPPORTED_VERSION` (not a passphrase file, or another container version or KDF),
/// `DSTU_ERR_UNSUPPORTED_PARAMS` (costs other than the one preset), or `DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `header` must be NULL or valid for reads of `DSTU_PASSPHRASE_FILE_HEADER_BYTES` bytes.
#[no_mangle]
pub unsafe extern "C" fn dstu_passphrase_file_check_header(header: *const u8) -> DstuStatus {
    guard_status(|| {
        if header.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match Header::parse(&unsafe { read_header(header) }) {
            Ok(_) => DstuStatus::DSTU_OK,
            Err(e) => passphrase_file_status(&e),
        }
    })
}

/// Copies a caller's header bytes into an owned array.
///
/// # Safety
///
/// `header` must be valid for reads of `DSTU_PASSPHRASE_FILE_HEADER_BYTES` bytes.
unsafe fn read_header(header: *const u8) -> [u8; HEADER_BYTES] {
    let mut bytes = [0u8; HEADER_BYTES];
    bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(header, HEADER_BYTES) });
    bytes
}

/// Starts writing a passphrase file (D-240): draws a salt, runs Argon2 (256 MiB, t=3), writes the
/// `DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES`-byte prefix (write it first) to `prefix_out`
/// and a stream-file encryptor to `*out` - drive it with `dstu_secretstream_file_encryptor_*` and
/// free it with `dstu_secretstream_file_encryptor_free`. Returns `DSTU_ERR_INVALID_LENGTH` for an
/// empty passphrase, `DSTU_ERR_RANDOM`, `DSTU_ERR_OUT_OF_MEMORY`, or `DSTU_ERR_NULL_POINTER`;
/// nothing is written on failure.
///
/// # Safety
///
/// `passphrase` must be valid for reads of `passphrase_len` bytes when non-null and
/// `passphrase_len > 0`; `prefix_out` must be NULL or valid for writes of
/// `DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES` bytes; `out` must be NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn dstu_passphrase_file_seal_stream(
    passphrase: *const u8,
    passphrase_len: usize,
    prefix_out: *mut u8,
    out: *mut *mut DstuFileEncryptor,
) -> DstuStatus {
    guard_status(|| {
        if prefix_out.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(passphrase) = (unsafe { slice_from_raw(passphrase, passphrase_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        match seal_stream(passphrase) {
            Ok((enc, prefix)) => {
                unsafe { std::slice::from_raw_parts_mut(prefix_out, prefix.len()) }
                    .copy_from_slice(&prefix);
                unsafe { *out = Box::into_raw(Box::new(DstuFileEncryptor::from_core(enc))) };
                DstuStatus::DSTU_OK
            }
            Err(e) => passphrase_file_status(&e),
        }
    })
}

/// Starts opening a passphrase file: `header` is its first `DSTU_PASSPHRASE_FILE_HEADER_BYTES`
/// bytes, checked as `dstu_passphrase_file_check_header` does before Argon2 runs. On `DSTU_OK`,
/// `*out` is a stream-file decryptor for everything after the header - drive it with
/// `dstu_secretstream_file_decryptor_*` and free it with `dstu_secretstream_file_decryptor_free`.
/// A wrong passphrase is reported by the decryptor (`DSTU_ERR_TAG_MISMATCH` at the first record).
/// Returns the header statuses, `DSTU_ERR_INVALID_LENGTH` for an empty passphrase,
/// `DSTU_ERR_OUT_OF_MEMORY`, or `DSTU_ERR_NULL_POINTER`; `*out` is not written on failure.
///
/// # Safety
///
/// `header` must be NULL or valid for reads of `DSTU_PASSPHRASE_FILE_HEADER_BYTES` bytes;
/// `passphrase` must be valid for reads of `passphrase_len` bytes when non-null and
/// `passphrase_len > 0`; `out` must be NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn dstu_passphrase_file_open_stream(
    header: *const u8,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut DstuFileDecryptor,
) -> DstuStatus {
    guard_status(|| {
        if header.is_null() || out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(passphrase) = (unsafe { slice_from_raw(passphrase, passphrase_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        let result = Header::parse(&unsafe { read_header(header) })
            .and_then(|parsed| parsed.open_stream(passphrase));
        match result {
            Ok(dec) => {
                unsafe { *out = Box::into_raw(Box::new(DstuFileDecryptor::from_core(dec))) };
                DstuStatus::DSTU_OK
            }
            Err(e) => passphrase_file_status(&e),
        }
    })
}
