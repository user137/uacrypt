//! Low-level ("hazardous material") primitives: direct DSTU algorithm implementations with no
//! forced RNG dependency and no safety rails — callers manage keys/nonces/IVs explicitly where
//! an algorithm needs them. Available in `no_std` builds.
//!
//! A higher-level, harder-to-misuse API mirroring libsodium's `crypto_*` "easy" functions is
//! planned on top of this module and will be `std`/`alloc`-gated where it needs OS randomness.
//! See `docs/dstu-crypto-project.md` "Concrete API shape" and `DECISIONS.md` D-09.

pub mod kalyna;
pub mod kupyna;
pub mod strumok;
mod tables;
