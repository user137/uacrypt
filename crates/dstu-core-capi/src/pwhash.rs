//! `crypto_pwhash` C ABI (`dstu_core::crypto_pwhash`) - Argon2id password hashing into a
//! self-describing, NUL-terminated PHC string. Requires this crate's own `pwhash` feature on
//! `dstu-core` (turned on unconditionally in `Cargo.toml`, matching Python's own precedent).

use crate::error::DstuStatus;
use crate::util::{guard_bool, guard_status, slice_from_raw};
use dstu_core::crypto_pwhash::{hash_password, verify_password, PwHashError, Strength};
use std::ffi::CStr;
use std::os::raw::c_char;

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

impl From<DstuPwhashStrength> for Strength {
    fn from(strength: DstuPwhashStrength) -> Self {
        match strength {
            DstuPwhashStrength::DSTU_PWHASH_INTERACTIVE => Strength::Interactive,
            DstuPwhashStrength::DSTU_PWHASH_MODERATE => Strength::Moderate,
            DstuPwhashStrength::DSTU_PWHASH_SENSITIVE => Strength::Sensitive,
        }
    }
}

/// Hashes `password` into a NUL-terminated PHC string written to `out` (a caller-owned buffer of
/// at least `DSTU_PWHASH_STRBYTES` bytes). Returns `DSTU_ERR_RANDOM` if the OS CSPRNG fails,
/// `DSTU_ERR_HASH_ERROR` on an internal Argon2/PHC-encoding failure (not expected in practice for
/// this module's own fixed-length salt), or `DSTU_ERR_NULL_POINTER`.
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
    strength: DstuPwhashStrength,
    out: *mut c_char,
) -> DstuStatus {
    guard_status(|| {
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        let Some(password) = (unsafe { slice_from_raw(password, password_len) }) else {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        };
        match hash_password(password, strength.into()) {
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
            Err(PwHashError::Random(_)) => DstuStatus::DSTU_ERR_RANDOM,
            Err(PwHashError::Hash(_)) => DstuStatus::DSTU_ERR_HASH_ERROR,
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
