//! DSTU 9041:2020 hybrid (ECIES-style) encryption over a twisted Edwards curve over `F_p`.
//!
//! Scope: `l(p) ∈ {256, 384, 512}` - the recommended curves E256/1 (T-177), E384/1 (T-297) and
//! E512/1 (T-192), one sibling module set per size. See `docs/pseudocode/dstu9041.md` and
//! `docs/DECISIONS.md` D-163/D-165/D-166 (256), D-176-D-180 (512) and D-241/D-244 (384) for the
//! citations and checks. `l(p)=384` follows DSTU 7624's KW-p text, not Додаток Г.2's printed `t`
//! (D-241). `l(p)=768` has no worked example in the standard (D-168) and is not implemented.

pub mod curve256;
pub mod curve384;
pub mod curve512;
pub mod encryption;
pub mod encryption384;
pub mod encryption512;
pub mod fp256;
pub mod fp384;
pub mod fp512;
pub mod message;
pub mod message384;
pub mod message512;
