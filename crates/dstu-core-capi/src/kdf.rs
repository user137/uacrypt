//! `crypto_kdf` C ABI (`dstu_core::crypto_kdf`) - derives subkeys from a 32-byte master key.
//! `dstu_kdf_derive_subkey` is infallible (fixed-length arrays in, fixed-length array out).

use crate::error::DstuStatus;
use crate::util::{guard_ptr, guard_status, guard_void};
use dstu_core::crypto_kdf::MasterKey;

pub const DSTU_KDF_KEY_BYTES: usize = 32;
pub const DSTU_KDF_CONTEXT_BYTES: usize = 8;
pub const DSTU_KDF_SUBKEY_BYTES: usize = 32;

/// Opaque `crypto_kdf` master-key handle. `dstu_kdf_master_key_free`'s `Box::from_raw` fires the
/// wrapped `MasterKey`'s own `Zeroize`-on-`Drop` impl.
pub struct DstuKdfMasterKey(MasterKey);

/// Generates a fresh master key from the OS CSPRNG. Returns `DSTU_OK` (writing `*out`) or
/// `DSTU_ERR_RANDOM`/`DSTU_ERR_NULL_POINTER`.
///
/// # Safety
///
/// `out` must be a valid, non-null pointer to a `*mut DstuKdfMasterKey`.
#[no_mangle]
pub unsafe extern "C" fn dstu_kdf_master_key_generate(
    out: *mut *mut DstuKdfMasterKey,
) -> DstuStatus {
    guard_status(|| {
        if out.is_null() {
            return DstuStatus::DSTU_ERR_NULL_POINTER;
        }
        match MasterKey::generate() {
            Ok(key) => {
                unsafe { *out = Box::into_raw(Box::new(DstuKdfMasterKey(key))) };
                DstuStatus::DSTU_OK
            }
            Err(_) => DstuStatus::DSTU_ERR_RANDOM,
        }
    })
}

/// Builds a master key from exactly `DSTU_KDF_KEY_BYTES` bytes. Infallible for a correct call;
/// returns NULL if `key` is NULL.
///
/// # Safety
///
/// `key` must be valid for reads of `DSTU_KDF_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_kdf_master_key_from_bytes(key: *const u8) -> *mut DstuKdfMasterKey {
    guard_ptr(|| {
        if key.is_null() {
            return std::ptr::null_mut();
        }
        let mut bytes = [0u8; DSTU_KDF_KEY_BYTES];
        bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(key, DSTU_KDF_KEY_BYTES) });
        Box::into_raw(Box::new(DstuKdfMasterKey(MasterKey::from_bytes(bytes))))
    })
}

/// Copies the master key's `DSTU_KDF_KEY_BYTES`-byte encoding into `out`. A NULL `key`/`out` is a
/// no-op.
///
/// # Safety
///
/// `out` must be valid for writes of `DSTU_KDF_KEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_kdf_master_key_bytes(key: *const DstuKdfMasterKey, out: *mut u8) {
    guard_void(|| {
        if key.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_KDF_KEY_BYTES) };
        out.copy_from_slice(key.0.as_bytes());
    })
}

/// Frees a master key. NULL is a no-op.
///
/// # Safety
///
/// `key` must be either NULL or a pointer previously returned by `dstu_kdf_master_key_generate`/
/// `dstu_kdf_master_key_from_bytes`, not already freed.
#[no_mangle]
pub unsafe extern "C" fn dstu_kdf_master_key_free(key: *mut DstuKdfMasterKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(unsafe { Box::from_raw(key) });
        }
    })
}

/// Derives a subkey from `key`/`subkey_id`/`context` - infallible. A NULL `key`/`context`/`out` is
/// a no-op (leaves `out` unwritten).
///
/// # Safety
///
/// `context` must be valid for reads of `DSTU_KDF_CONTEXT_BYTES` bytes when non-null; `out` must
/// be valid for writes of `DSTU_KDF_SUBKEY_BYTES` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn dstu_kdf_derive_subkey(
    key: *const DstuKdfMasterKey,
    subkey_id: u64,
    context: *const u8,
    out: *mut u8,
) {
    guard_void(|| {
        if key.is_null() || context.is_null() || out.is_null() {
            return;
        }
        let key = unsafe { &*key };
        let mut ctx = [0u8; DSTU_KDF_CONTEXT_BYTES];
        ctx.copy_from_slice(unsafe { std::slice::from_raw_parts(context, DSTU_KDF_CONTEXT_BYTES) });
        let subkey = key.0.derive_subkey(subkey_id, &ctx);
        let out = unsafe { std::slice::from_raw_parts_mut(out, DSTU_KDF_SUBKEY_BYTES) };
        out.copy_from_slice(&subkey);
    })
}
