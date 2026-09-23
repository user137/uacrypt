//! Rust implementations of Ukrainian DSTU cryptographic standards (Kalyna, Kupyna, Strumok).
//!
//! **Pre-release and provisional — not independently audited.** Kalyna and Kupyna are
//! dual-oracle-verified against official test vectors. Kalyna's modes of operation and Kupyna's KMAC
//! follow the DSTU 7624:2014 and 7564:2014 texts as read from their draft editions, including where
//! UAPKI and Bouncy Castle differ (`docs/DECISIONS.md` D-204–D-206, `docs/COMPATIBILITY.md`); the
//! final published editions have not been checked.
//! Strumok's keystream generator is confirmed against the primary DSTU 8845:2019 text itself
//! (`docs/DECISIONS.md` D-197); its `Tᵢ[a]`/`Mulα`/`Mulα⁻¹` constant tables are spot-checked
//! against the same text too (D-198, zero mismatches on a ~100-entry sample), but not
//! independently transcription-verified in full. This crate makes
//! **no claim of side-channel (SPA/DPA) resistance**. See
//! `docs/SECURITY.md` and `docs/DECISIONS.md` in the project repository for the full threat model, citations,
//! and per-construction status.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod crypto_auth;
#[cfg(feature = "std")]
pub mod crypto_box;
#[cfg(feature = "std")]
pub mod crypto_box512;
pub mod crypto_generichash;
pub mod crypto_kdf;
#[cfg(feature = "pwhash")]
pub mod crypto_pwhash;
#[cfg(feature = "std")]
pub mod crypto_secretbox;
pub mod crypto_secretstream;
pub mod crypto_sign;
pub mod crypto_sign257;
#[cfg(feature = "std")]
pub mod crypto_stream;
pub mod hazmat;
#[cfg(any(feature = "std", feature = "getrandom"))]
pub mod randombytes;
#[cfg(feature = "selftest")]
pub mod selftest;
