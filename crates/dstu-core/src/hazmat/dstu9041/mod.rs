//! DSTU 9041:2020 hybrid (ECIES-style) encryption over a twisted Edwards curve over `F_p`.
//!
//! Scope: `l(p)=256` (λ=127, recommended curve E256/1) only - see `docs/pseudocode/dstu9041.md`
//! and `docs/DECISIONS.md` D-163/D-165/D-166 for the primary-source citations and the curve
//! parameter erratum this module's constants were corrected against. `l(p)=384/512/768` need a
//! new `hazmat::kalyna_kw_p` sibling primitive and/or unverified worked examples - out of scope
//! for this pass (T-177), matching this project's own "ship the recommended curve first" (D-47)
//! precedent already applied to `hazmat::dstu4145`.

pub mod curve256;
pub mod fp256;
pub mod message;
