//! Black-box tests for `dstu_core::hazmat::dstu9041::fp256` (`F_p` arithmetic, `l(p)=256`,
//! E256/1's `p`, clauses 6.5-6.8 - see `docs/pseudocode/dstu9041.md`). Test-first per T-177:
//! written before `fp256` exists.
//!
//! No raw field-operation vectors exist in the DSTU worked example (it only exercises field ops
//! indirectly through curve/KW arithmetic) - `A_HEX`/`B_HEX`/etc. below are independently generated
//! via Python's arbitrary-precision `pow`/`*`/`%` (a genuinely separate implementation from this
//! crate's own), not derived from the standard. Curve-level vectors (Phase 3) provide the
//! DSTU-anchored cross-check on top of this.

use dstu_core::hazmat::dstu9041::fp256::FieldElement;
use proptest::prelude::*;

fn decode_hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex digit");
    }
    out
}

fn fe(s: &str) -> FieldElement {
    FieldElement::from_be_bytes(&decode_hex(s))
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = json.find(pattern.as_str()).expect("key present in vector");
    let after = &json[start + pattern.len()..];
    let end = after.find('"').expect("well-formed test-vector JSON");
    &after[..end]
}

const CURVE_VECTOR: &str = include_str!("vectors/dstu9041/curve-E256-1.json");

/// Sourced from the curve vector JSON itself, not hardcoded - D-166 was exactly "the committed
/// `p_hex` was wrong for two sessions"; a hardcoded copy here would not have caught that.
fn p_hex() -> &'static str {
    extract(CURVE_VECTOR, "p_hex")
}

const P_MINUS_1_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE4C";

const A_HEX: &str = "BEC38FCCEF069DD4D1754859218F5CE3F445EB10E7EE88BBBB93024E836FC195";
const B_HEX: &str = "2C2964ACDA9732E5B66F1F194A08329FC2410DC37368EC7F8B7A79EB2AA39D9F";
const A_MUL_B_HEX: &str = "A985601D2C86103F271682411D766F2EBCBC048167D3957CB631C96AD64FD798";
const A_SQUARE_HEX: &str = "F22FC13CB1AAC5A53B664670E986C32FDA40BE5D6D31A51BF72ACF7AAA0B3BD3";
const A_PLUS_B_HEX: &str = "EAECF479C99DD0BA87E467726B978F83B686F8D45B57753B470D7C39AE135F34";
const A_MINUS_B_HEX: &str = "929A2B20146F6AEF1B06293FD7872A443204DD4D74859C3C3018886358CC23F6";
const A_INV_HEX: &str = "E13E10D9107F389F086F7296DE8374C05F7BDEA2313AB38F0736DC9E3A20B69E";
const SMALL_QR_SQRT_HEX: &str = "BC540AEBBFEC6643E4FCFAAACF32537E75A6B728461266C20D8E34AF0EAAA66E";

fn small_qr_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = 3;
    out
}

fn small_non_qr_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = 2;
    out
}

#[test]
fn p_is_5_mod_8() {
    let p = decode_hex(p_hex());
    assert_eq!(p[31] % 8, 5);
}

#[test]
fn add_matches_independent_python_reference() {
    assert_eq!(fe(A_HEX).add(fe(B_HEX)), fe(A_PLUS_B_HEX));
}

#[test]
fn sub_matches_independent_python_reference() {
    assert_eq!(fe(A_HEX).sub(fe(B_HEX)), fe(A_MINUS_B_HEX));
}

#[test]
fn multiply_matches_independent_python_reference() {
    assert_eq!(fe(A_HEX).multiply(fe(B_HEX)), fe(A_MUL_B_HEX));
}

#[test]
fn square_matches_independent_python_reference() {
    assert_eq!(fe(A_HEX).square(), fe(A_SQUARE_HEX));
}

#[test]
fn invert_matches_independent_python_reference() {
    assert_eq!(fe(A_HEX).invert(), fe(A_INV_HEX));
}

#[test]
fn invert_then_multiply_is_one() {
    let a = fe(A_HEX);
    assert_eq!(a.invert().multiply(a), FieldElement::ONE);
}

#[test]
fn sqrt_of_known_residue_matches_reference() {
    let qr = FieldElement::from_be_bytes(&small_qr_bytes());
    assert!(qr.euler_criterion());
    assert_eq!(qr.sqrt(), fe(SMALL_QR_SQRT_HEX));
}

#[test]
fn euler_criterion_true_for_residue_false_for_non_residue() {
    let qr = FieldElement::from_be_bytes(&small_qr_bytes());
    let non_qr = FieldElement::from_be_bytes(&small_non_qr_bytes());
    assert!(qr.euler_criterion());
    assert!(!non_qr.euler_criterion());
}

#[test]
fn euler_criterion_of_zero_is_false() {
    assert!(!FieldElement::ZERO.euler_criterion());
}

#[test]
fn sqrt_of_non_residue_does_not_square_back() {
    // sqrt is documented as unconditional, caller-precondition-gated on euler_criterion first -
    // pin that contract so a future "simplify" edit can't quietly substitute
    // "sqrt then check the square" for a real euler_criterion call without a test noticing.
    let non_qr = FieldElement::from_be_bytes(&small_non_qr_bytes());
    assert!(!non_qr.euler_criterion());
    assert_ne!(non_qr.sqrt().square(), non_qr);
}

// --- Fixed vectors at p's own boundary (advisor review, 2026-08-05): every proptest above masks
// the top bit off every generated value (`bytes[0] &= 0x7F`), so none of them ever exercise
// add's carry=1 path, reduce_wide's overflow near its real ceiling, or conditional_sub_p actually
// firing. These six close that hole with hand-derivable expected values. ---

#[test]
fn p_minus_1_add_p_minus_1_is_p_minus_2() {
    let p_minus_1 = fe(p_hex()).sub(FieldElement::ONE);
    let p_minus_2 = p_minus_1.sub(FieldElement::ONE);
    assert_eq!(p_minus_1.add(p_minus_1), p_minus_2);
}

#[test]
fn p_minus_1_add_one_is_zero() {
    let p_minus_1 = fe(p_hex()).sub(FieldElement::ONE);
    assert_eq!(p_minus_1.add(FieldElement::ONE), FieldElement::ZERO);
}

#[test]
fn p_minus_1_add_two_is_one() {
    let p_minus_1 = fe(p_hex()).sub(FieldElement::ONE);
    let two = FieldElement::ONE.add(FieldElement::ONE);
    assert_eq!(p_minus_1.add(two), FieldElement::ONE);
}

#[test]
fn zero_sub_p_minus_1_is_one() {
    let p_minus_1 = fe(p_hex()).sub(FieldElement::ONE);
    assert_eq!(FieldElement::ZERO.sub(p_minus_1), FieldElement::ONE);
}

#[test]
fn p_minus_1_multiply_p_minus_1_is_one() {
    // (-1)*(-1) == 1 mod p - drives reduce_wide's overflow chain at its ceiling
    // (hc_top=434, overflow=434, the first conditional_sub_p is load-bearing here).
    let p_minus_1 = fe(p_hex()).sub(FieldElement::ONE);
    assert_eq!(p_minus_1.multiply(p_minus_1), FieldElement::ONE);
}

#[test]
fn p_minus_1_square_is_one() {
    let p_minus_1 = fe(p_hex()).sub(FieldElement::ONE);
    assert_eq!(p_minus_1.square(), FieldElement::ONE);
}

// --- Boundary conditions (this project's own standing rule after D-110/T-152: a formula-based
// correctness precondition is invisible to random sampling - test the edges explicitly). ---

#[test]
fn invert_of_zero_is_zero_and_does_not_panic() {
    // Fermat's `0^(p-2) mod p == 0` - a defined-but-mathematically-meaningless result (zero has no
    // real multiplicative inverse). Must not panic; callers that could reach this (curve256's
    // `to_affine`) must never actually invoke it on a genuine zero Z-coordinate - traced there,
    // not here.
    assert_eq!(FieldElement::ZERO.invert(), FieldElement::ZERO);
}

#[test]
fn sqrt_of_zero_is_zero() {
    assert_eq!(FieldElement::ZERO.sqrt(), FieldElement::ZERO);
}

#[test]
fn pow_mod_by_zero_exponent_is_one() {
    assert_eq!(fe(A_HEX).pow_mod(&[0u8; 32]), FieldElement::ONE);
}

#[test]
fn pow_mod_zero_base_by_zero_exponent_is_one_by_convention() {
    // `0^0 := 1` here (matches this implementation's square-and-multiply loop starting the
    // accumulator at ONE and never touching it when every exponent bit is 0) - documented so a
    // future reader doesn't "fix" it into a special-cased 0.
    assert_eq!(FieldElement::ZERO.pow_mod(&[0u8; 32]), FieldElement::ONE);
}

#[test]
fn from_candidate_bytes_accepts_p_minus_1() {
    use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
    assert!(from_candidate_bytes(&decode_hex(P_MINUS_1_HEX)).is_some());
}

#[test]
fn from_candidate_bytes_rejects_p_itself() {
    use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
    assert!(from_candidate_bytes(&decode_hex(p_hex())).is_none());
}

#[test]
fn from_candidate_bytes_rejects_all_ff() {
    use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
    assert!(from_candidate_bytes(&[0xFFu8; 32]).is_none());
}

#[test]
fn from_candidate_bytes_accepts_zero() {
    use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
    assert!(from_candidate_bytes(&[0u8; 32]).is_some());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn add_sub_are_inverse(a_bytes: [u8; 32], b_bytes: [u8; 32]) {
        use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
        // Reduce arbitrary bytes into the field by retrying-free construction: reject a byte
        // string >= p by masking the top bit off (cheap way to land in-range without a loop).
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.add(b).sub(b), a);
    }

    #[test]
    fn multiply_is_commutative(a_bytes: [u8; 32], b_bytes: [u8; 32]) {
        use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.multiply(b), b.multiply(a));
    }

    #[test]
    fn multiply_is_associative(a_bytes: [u8; 32], b_bytes: [u8; 32], c_bytes: [u8; 32]) {
        use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let mut cb = c_bytes; cb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        let c = from_candidate_bytes(&cb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.multiply(b).multiply(c), a.multiply(b.multiply(c)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "pow_mod's 256-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100/T-177")]
    fn invert_matches_multiplicative_inverse_definition(a_bytes: [u8; 32]) {
        use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        if a == FieldElement::ZERO {
            return Ok(());
        }
        prop_assert_eq!(a.invert().multiply(a), FieldElement::ONE);
    }

    #[test]
    #[cfg_attr(miri, ignore = "sqrt's two 256-iteration pow_mod ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177")]
    fn sqrt_of_a_square_squares_back(a_bytes: [u8; 32]) {
        use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let square = a.square();
        assert!(square.euler_criterion() || square == FieldElement::ZERO);
        prop_assert_eq!(square.sqrt().square(), square);
    }

    #[test]
    #[cfg_attr(miri, ignore = "pow_mod's 256-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100/T-177")]
    fn pow_mod_matches_repeated_squaring_reference(a_bytes: [u8; 32], exp_byte: u8) {
        use dstu_core::hazmat::dstu9041::fp256::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        // Small (<=255) exponent so a naive one-bit-at-a-time reference is cheap to compute here.
        let mut naive = FieldElement::ONE;
        for _ in 0..exp_byte {
            naive = naive.multiply(a);
        }
        let mut exponent = [0u8; 32];
        exponent[31] = exp_byte;
        prop_assert_eq!(a.pow_mod(&exponent), naive);
    }
}
