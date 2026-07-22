//! DSTU 4145-2002 digital signature over GF(2^m) binary-field elliptic curves.
//!
//! Only the field-arithmetic layer for the m=163 curve exists so far (`gf2m163`) - point
//! arithmetic and the sign/verify logic itself are not implemented yet (see `TASKS.md` Phase 2).
//! Citation for the field-arithmetic algorithms specifically: `DECISIONS.md` D-25 (reduction
//! adapted from OpenSSL's `BN_GF2m_mod_arr`, inversion via a fixed-exponent square-and-multiply
//! chain - the constant-time realization of Itoh-Tsujii's approach). The signature logic itself,
//! once implemented, is transcribed from Bouncy Castle's `DSTU4145Signer` per `DECISIONS.md`
//! D-02/D-14 and `docs/pseudocode/dstu4145.md`.

pub mod curve163;
pub mod gf2m163;
pub mod scalar;
pub mod signature;
