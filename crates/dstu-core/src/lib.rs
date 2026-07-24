#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "pwhash")]
pub mod crypto_pwhash;
pub mod crypto_sign;
pub mod hazmat;
#[cfg(feature = "std")]
pub mod randombytes;
