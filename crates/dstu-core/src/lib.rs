//! Rust implementations of Ukrainian DSTU cryptographic standards (Kalyna, Kupyna, Strumok).
//!
//! **Pre-release and provisional — not independently audited.** Kalyna and Kupyna are
//! dual-oracle-verified against official test vectors. The Kalyna-alone mode of operation
//! (`hazmat::kalyna_ccm`, `hazmat::kalyna_gcm`, and everything built on them) rests on an adopted
//! assumption, not a confirmation against the primary DSTU 7624:2014 text (`docs/DECISIONS.md` D-05).
//! Strumok is UAPKI-attributed only, not confirmed against the primary DSTU 8845:2019 text
//! (`docs/DECISIONS.md` D-15). This crate makes **no claim of side-channel (SPA/DPA) resistance**. See
//! `docs/SECURITY.md` and `docs/DECISIONS.md` in the project repository for the full threat model, citations,
//! and per-construction status.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod crypto_auth;
#[cfg(feature = "std")]
pub mod crypto_box;
pub mod crypto_generichash;
pub mod crypto_kdf;
#[cfg(feature = "pwhash")]
pub mod crypto_pwhash;
#[cfg(feature = "std")]
pub mod crypto_secretbox;
pub mod crypto_secretstream;
pub mod crypto_sign;
#[cfg(feature = "std")]
pub mod crypto_stream;
pub mod hazmat;
#[cfg(any(feature = "std", feature = "getrandom"))]
pub mod randombytes;
#[cfg(feature = "selftest")]
pub mod selftest;
