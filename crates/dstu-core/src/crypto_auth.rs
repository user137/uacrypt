//! `crypto_auth`/`crypto_onetimeauth` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the
//! libsodium API", `TASKS.md` T-105, roadmap Step 3 item 2 - `DECISIONS.md` D-66) - a thin
//! libsodium-ergonomics wrapper over [`crate::hazmat::kupyna_kmac::Kupyna256Kmac`].
//!
//! Two departures from the raw `hazmat` API, both following D-47's "delete the knob" criterion
//! (the same rule `crypto_secretbox` applied to Kalyna's five variants, D-51):
//! - **Only the 256-bit MAC size is exposed** - `hazmat::kupyna_kmac` also has `Kupyna384Kmac`/
//!   `Kupyna512Kmac`, matching this crate's existing default-to-256-bit convention
//!   (`crypto_secretbox`'s `Kalyna256_256Gcm`, `crypto_sign`'s internal `Kupyna256` message hash).
//!   The other two sizes remain available at `hazmat::kupyna_kmac` for callers who need them.
//! - **The key is an opaque, `Zeroize`-on-drop [`Key`] type**, not a raw `&[u8]` - this also
//!   forecloses `hazmat::kupyna_kmac::KmacError::WrongKeyLength` at this layer entirely: `Key` can
//!   only ever be exactly 32 bytes (`from_bytes([u8; 32])` or [`Key::generate`]), so [`auth`] is
//!   infallible and [`verify`]'s error type has only one variant. This is a type-signature
//!   foreclosure, not an untested code path - see `DECISIONS.md` D-66.
//!
//! Provenance is otherwise identical to the `hazmat` layer: dual-oracle-cited, not yet confirmed
//! against the primary DSTU 7564:2014 text (D-44).

use crate::hazmat::kupyna_kmac::{KmacError, Kupyna256Kmac};
use core::fmt;
use zeroize::Zeroize;

/// A `crypto_auth` key. Always exactly 32 bytes - [`Kupyna256Kmac`]'s fixed MAC/key length (see
/// the module doc).
pub struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Key {
    /// Generates a fresh key from the OS CSPRNG - libsodium's `crypto_auth_keygen` equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`crate::randombytes::RandomError`] if the OS CSPRNG fails.
    #[cfg(feature = "std")]
    pub fn generate() -> Result<Self, crate::randombytes::RandomError> {
        let mut bytes = [0u8; 32];
        crate::randombytes::randombytes_buf(&mut bytes)?;
        Ok(Key(bytes))
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Key(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `verify` can fail only one way: [`auth`] cannot fail at all (see the module doc's "delete the
/// knob" section - `Key`'s fixed length forecloses `hazmat`'s `WrongKeyLength` case here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagMismatch;

impl fmt::Display for TagMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authentication failed")
    }
}

impl core::error::Error for TagMismatch {}

/// Computes the MAC of `message` under `key`.
#[must_use]
pub fn auth(key: &Key, message: &[u8]) -> [u8; 32] {
    let Ok(tag) = Kupyna256Kmac::mac(key.as_bytes(), message) else {
        unreachable!("Key::as_bytes() is always exactly 32 bytes, Kupyna256Kmac's own mac_len")
    };
    tag
}

/// Verifies `tag` against `message` under `key`, in constant time
/// ([`crate::hazmat::kupyna_kmac`]'s own `subtle::ConstantTimeEq` comparison).
///
/// # Errors
///
/// Returns [`TagMismatch`] if `tag` does not match.
pub fn verify(key: &Key, message: &[u8], tag: &[u8; 32]) -> Result<(), TagMismatch> {
    Kupyna256Kmac::verify(key.as_bytes(), message, tag).map_err(|e| match e {
        KmacError::TagMismatch => TagMismatch,
        KmacError::WrongKeyLength => {
            unreachable!("Key::as_bytes() is always exactly 32 bytes, Kupyna256Kmac's own mac_len")
        }
    })
}
