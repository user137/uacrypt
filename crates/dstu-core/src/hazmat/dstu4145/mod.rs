//! DSTU 4145-2002 digital signature over GF(2^m) binary-field elliptic curves.
//!
//! `m=163` (`gf2m163`/`curve163`) is the complete, wired-into-`sign`/`verify` curve. `m=257`
//! (`gf2m257`) is field-arithmetic-only so far, landing in test-first phases per `docs/TASKS.md`
//! T-199/`docs/DECISIONS.md` D-185/D-186 - point arithmetic (`curve257`) and sign/verify wiring
//! are not implemented yet. Citation for `m=163`'s field-arithmetic algorithms specifically:
//! `docs/DECISIONS.md` D-25 (reduction adapted from OpenSSL's `BN_GF2m_mod_arr`, inversion via a
//! fixed-exponent square-and-multiply chain - the constant-time realization of Itoh-Tsujii's
//! approach). The signature logic itself is transcribed from Bouncy Castle's `DSTU4145Signer` per
//! `docs/DECISIONS.md` D-02/D-14 and `docs/pseudocode/dstu4145.md`.

pub mod curve163;
pub mod curve257;
pub mod gf2m163;
pub mod gf2m257;
pub mod scalar;
pub mod scalar257;
pub mod signature;
pub mod signature257;
