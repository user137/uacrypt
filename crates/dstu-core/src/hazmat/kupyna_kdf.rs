//! Kupyna-based KDF - `crypto_kdf` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the
//! libsodium API").
//!
//! **Not a DSTU-specified construction, and not oracle-verified** - a different posture from every
//! other primitive in this project. There is no separate national KDF standard, and no reference
//! implementation of "a KDF using Kupyna" exists anywhere to port or cross-check against. Modeled
//! after libsodium's `crypto_kdf_derive_from_key` *shape* (one master key + an id + a context,
//! a single keyed-hash call per subkey, no separate Extract stage - deliberately not full RFC 5869
//! HKDF, whose proof is stated in terms of HMAC specifically, which `hazmat::kupyna_kmac`'s
//! construction is not) using [`super::kupyna_kmac`] (`TASKS.md` T-38) as the underlying keyed
//! primitive. Full reasoning and citation in `docs/pseudocode/kupyna-kdf.md`.

use super::kupyna_kmac::{Kupyna256Kmac, Kupyna384Kmac, Kupyna512Kmac};

macro_rules! kdf_variant {
    ($name:ident, $kmac:ty, $key_len:literal) => {
        pub struct $name;

        impl $name {
            /// Derives a subkey from `master_key`, `subkey_id`, and `context` -
            /// `context || subkey_id` (little-endian) fed as the message to
            #[doc = concat!("[`", stringify!($kmac), "::mac`].")]
            /// Different `subkey_id`/`context` values (holding the others fixed) produce
            /// different subkeys - see `docs/pseudocode/kupyna-kdf.md` for why this can only be
            /// checked by property test, not against a fixed vector.
            #[must_use]
            pub fn derive_subkey(
                master_key: &[u8; $key_len],
                subkey_id: u64,
                context: &[u8; 8],
            ) -> [u8; $key_len] {
                let mut message = [0u8; 16];
                message[..8].copy_from_slice(context);
                message[8..].copy_from_slice(&subkey_id.to_le_bytes());
                <$kmac>::mac(master_key, &message)
                    .expect("master_key's length always matches this KMAC variant's mac_len")
            }
        }
    };
}

kdf_variant!(Kupyna256Kdf, Kupyna256Kmac, 32);
kdf_variant!(Kupyna384Kdf, Kupyna384Kmac, 48);
kdf_variant!(Kupyna512Kdf, Kupyna512Kmac, 64);
