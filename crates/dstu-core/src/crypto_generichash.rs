//! `crypto_generichash` equivalent (`docs/dstu-crypto-project.md` "Mapping onto the libsodium API",
//! `TASKS.md` T-105, roadmap Step 3 item 2 - `DECISIONS.md` D-66) - a bare re-export of
//! [`crate::hazmat::kupyna`]'s one-shot and streaming API under this crate's top-level `crypto_*`
//! namespace, for naming parity with `crypto_sign`/`crypto_secretbox`/`crypto_pwhash` rather than
//! a new wrapper.
//!
//! Unlike those three modules, there is nothing here for a wrapper to add: `hazmat::kupyna`'s
//! `digest()`/`Hasher` API already has no knob to hide (no algorithm choice beyond the output
//! size, no nonce, no length cap) and libsodium's own `crypto_generichash` value-adds over a bare
//! hash function - a caller-chosen variable output length, and an optional key for keyed hashing -
//! have no DSTU equivalent to re-derive: Kupyna has no variable-length-output mode, and DSTU
//! 7564:2014's own keyed construction is [`crate::hazmat::kupyna_kmac`], a distinct primitive
//! surfaced separately as [`crate::crypto_auth`], not a parameter of this one. See D-66's fuller
//! reasoning for why this module is a re-export rather than a table entry (discoverability under
//! this crate's `crypto_*` namespace) and why it is a re-export rather than a wrapper with new
//! logic (nothing left to wrap).

pub use crate::hazmat::kupyna::{Kupyna256, Kupyna256Hasher, Kupyna512, Kupyna512Hasher};
