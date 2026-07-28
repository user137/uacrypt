//! `crypto_kdf` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `docs/TASKS.md` T-105, roadmap Step 3 item 2 - `docs/DECISIONS.md` D-66) - a thin libsodium-ergonomics
//! wrapper over [`Kupyna256Kdf`],
//! matching [`crate::crypto_auth`]'s reasoning exactly: only the 256-bit variant is exposed here
//! (D-47's "delete the knob", same as `crypto_auth`'s choice among `Kupyna{256,384,512}Kmac`; the
//! other two sizes stay available at `hazmat::kupyna_kdf`), and the master key is an opaque,
//! `Zeroize`-on-drop [`MasterKey`] type rather than a raw `[u8; 32]`.
//!
//! Unlike `crypto_auth`, there is no error to foreclose either way: `hazmat::kupyna_kdf::
//! Kupyna256Kdf::derive_subkey` is already infallible (fixed-length arrays in, fixed-length array
//! out, no key-length check to fail). [`MasterKey`] adds `Zeroize`-on-drop and an OS-CSPRNG
//! `generate()`, matching `crypto_secretbox`'s `SecretKey`/`crypto_auth`'s `Key` precedent, not a
//! change in fallibility.
//!
//! Provenance is otherwise identical to the `hazmat` layer: no DSTU standard or reference
//! implementation of "a KDF using Kupyna" exists anywhere, so - unlike every other module in this
//! crate - there is no oracle vector for this construction, ever (D-45); verification is
//! determinism/distinctness property tests only, inherited unchanged from `hazmat::kupyna_kdf`.
//!
//! # Example
//!
//! Derives many independent-looking subkeys from one master key, instead of generating and storing
//! a fresh random key per purpose - useful when you want, say, a separate encryption key and MAC
//! key derived from one secret rather than managing two unrelated secrets.
//!
//! ```rust
//! use dstu_core::crypto_kdf::MasterKey;
//!
//! let master_key = MasterKey::generate().expect("OS CSPRNG should not fail");
//!
//! let encryption_subkey = master_key.derive_subkey(0, b"encrypt_");
//! let mac_subkey = master_key.derive_subkey(1, b"mac_key_");
//!
//! // Different subkey_id (holding context fixed) gives a different, unrelated-looking subkey.
//! assert_ne!(encryption_subkey, mac_subkey);
//! // Deterministic: the same id/context always re-derives the same subkey.
//! assert_eq!(encryption_subkey, master_key.derive_subkey(0, b"encrypt_"));
//! ```

use crate::hazmat::kupyna_kdf::Kupyna256Kdf;
use zeroize::Zeroize;

/// A `crypto_kdf` master key. Always exactly 32 bytes - [`Kupyna256Kdf`]'s fixed key length (see
/// the module doc).
pub struct MasterKey([u8; 32]);

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl MasterKey {
    /// Generates a fresh master key from the OS CSPRNG - libsodium's `crypto_kdf_keygen`
    /// equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`crate::randombytes::RandomError`] if the OS CSPRNG fails.
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn generate() -> Result<Self, crate::randombytes::RandomError> {
        let mut bytes = [0u8; 32];
        crate::randombytes::randombytes_buf(&mut bytes)?;
        Ok(MasterKey(bytes))
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterKey(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives a subkey - see [`Kupyna256Kdf::derive_subkey`] for the construction itself.
    /// Different `subkey_id`/`context` values (holding the others fixed) produce different
    /// subkeys.
    #[must_use]
    pub fn derive_subkey(&self, subkey_id: u64, context: &[u8; 8]) -> [u8; 32] {
        Kupyna256Kdf::derive_subkey(&self.0, subkey_id, context)
    }
}
