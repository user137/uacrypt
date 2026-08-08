//! Black-box tests for `dstu_core::hazmat::dstu9041::fp512` (`F_p` arithmetic, `l(p)=512`,
//! E512/1's `p`, T-192 Phase 1 - see `docs/pseudocode/dstu9041.md`, `docs/DECISIONS.md` D-176).
//! Test-first per T-192's own plan (mirrors T-177's `dstu9041_field.rs` for `l(p)=256`): written
//! before `fp512` exists.
//!
//! No raw field-operation vectors exist in the DSTU worked example (it only exercises field ops
//! indirectly through curve/KW arithmetic) - `A_HEX`/`B_HEX`/etc. below are independently generated
//! via Python's arbitrary-precision `pow`/`*`/`%` (a genuinely separate implementation from this
//! crate's own), not derived from the standard. Curve-level vectors (Phase 4) provide the
//! DSTU-anchored cross-check on top of this, same split T-177 used.

use dstu_core::hazmat::dstu9041::fp512::FieldElement;
use proptest::prelude::*;

fn decode_hex(s: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..64 {
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

const CURVE_VECTOR: &str = include_str!("vectors/dstu9041/curve-E512-1.json");

/// Sourced from the curve vector JSON itself, not hardcoded - D-166's "the committed `p_hex` was
/// wrong for two sessions" lesson applies here too: a hardcoded copy would not catch a future fix
/// to the vector file going stale in this test.
fn p_hex() -> &'static str {
    extract(CURVE_VECTOR, "p_hex")
}

const P_MINUS_1_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC94";

const A_HEX: &str = "489920E93A51844367E832F3F4A1424AE17BD0377AE27F948B4E305B9D587A48F51C1D94A193A8EDE8625B0EC1C4765AD7D1AD6CB2AB2C139A51CBC06BF24332";
const B_HEX: &str = "F1C6DBDCEC1A85ACBCFC910555918352BB4D4A9B3FF1F9327D3D24E521E1918B82A895D4ADACA9EA0C4F6F5D5405E350983935EA00D5ED9966CFA26253E55FAF";
const A_PLUS_B_HEX: &str = "3A5FFCC6266C09F024E4C3F94A32C59D9CC91AD2BAD478C7088B5540BF3A0BD477C4B3694F4052D7F4B1CA6C15CA59AB700AE356B38119AD01216E22BFD7A64C";
const A_MINUS_B_HEX: &str = "56D2450C4E36FE96AAEBA1EE9F0FBEF8262E859C3AF086620E110B767B76E8BD727387BFF3E6FF03DC12EBB16DBE930A3F987782B1D53E7A3382295E180CE018";
const A_MUL_B_HEX: &str = "0E98B270C1EAB8AC7F29639A32C45E4EB3F0F49273E3E90567C92D92A762AB917EB4542CFB51422CF8EB6A4248F00DC041ADD0E74E3FED2B2A432CD30085B8AD";
const A_SQUARE_HEX: &str = "E452032BAD8CDE0416BACB66F884C2E1A1B33D6FCF299E0DA35B70F1ADB23CE9270CC1068F91897858B17EE0134198D812CB131289B8CF2EB231F3EA1F427243";
const A_INV_HEX: &str = "0E1C04398E64BD525C408268FF70EFB04CE5E744EA571B995418C6DBF7CED54A88D619ECD0DF329F20B09FE95E6AF2961C9A78F115F6EAB493031FFE8D7932A8";
const SMALL_QR_SQRT_HEX: &str = "A413FC0A23CE79954866BB5E31B1172B84FD7C8E48E8792130FEA8098464345191471CC6F930DE34EE6B648B9B0547B0605EF8CB204606CF1D787122A15CD72D";

/// `5` - the smallest quadratic residue `> 1` mod this `p` (`2`/`3`/`4`... checked independently
/// via Python; `4` is a QR too but its own sqrt is the trivial `2`, so `5` is the more meaningful
/// case, same reasoning fp256's own test file would have applied had it not already had `3`
/// available for `l(p)=256`'s different `p`).
fn small_qr_bytes() -> [u8; 64] {
    let mut out = [0u8; 64];
    out[63] = 5;
    out
}

/// `2` - a documented non-residue mod this `p` too (independently checked via Python, not assumed
/// to carry over from `l(p)=256`'s own `p` just because the same small integer happened to work
/// there).
fn small_non_qr_bytes() -> [u8; 64] {
    let mut out = [0u8; 64];
    out[63] = 2;
    out
}

#[test]
fn p_is_5_mod_8() {
    let p = decode_hex(p_hex());
    assert_eq!(p[63] % 8, 5);
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
    let non_qr = FieldElement::from_be_bytes(&small_non_qr_bytes());
    assert!(!non_qr.euler_criterion());
    assert_ne!(non_qr.sqrt().square(), non_qr);
}

// --- Fixed vectors at p's own boundary (same D-167/T-177 precedent: proptest below masks the top
// bit off every generated value, so none of them ever exercise add's carry=1 path, reduce_wide's
// overflow near its real ceiling, or conditional_sub_p actually firing). ---

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
    // (-1)*(-1) == 1 mod p - drives reduce_wide's overflow chain at its ceiling.
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
    assert_eq!(FieldElement::ZERO.invert(), FieldElement::ZERO);
}

#[test]
fn sqrt_of_zero_is_zero() {
    assert_eq!(FieldElement::ZERO.sqrt(), FieldElement::ZERO);
}

#[test]
fn pow_mod_by_zero_exponent_is_one() {
    assert_eq!(fe(A_HEX).pow_mod(&[0u8; 64]), FieldElement::ONE);
}

#[test]
fn pow_mod_zero_base_by_zero_exponent_is_one_by_convention() {
    assert_eq!(FieldElement::ZERO.pow_mod(&[0u8; 64]), FieldElement::ONE);
}

#[test]
fn from_candidate_bytes_accepts_p_minus_1() {
    use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
    assert!(from_candidate_bytes(&decode_hex(P_MINUS_1_HEX)).is_some());
}

#[test]
fn from_candidate_bytes_rejects_p_itself() {
    use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
    assert!(from_candidate_bytes(&decode_hex(p_hex())).is_none());
}

#[test]
fn from_candidate_bytes_rejects_all_ff() {
    use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
    assert!(from_candidate_bytes(&[0xFFu8; 64]).is_none());
}

#[test]
fn from_candidate_bytes_accepts_zero() {
    use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
    assert!(from_candidate_bytes(&[0u8; 64]).is_some());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn add_sub_are_inverse(a_bytes: [u8; 64], b_bytes: [u8; 64]) {
        use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.add(b).sub(b), a);
    }

    #[test]
    fn multiply_is_commutative(a_bytes: [u8; 64], b_bytes: [u8; 64]) {
        use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.multiply(b), b.multiply(a));
    }

    #[test]
    fn multiply_is_associative(a_bytes: [u8; 64], b_bytes: [u8; 64], c_bytes: [u8; 64]) {
        use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let mut cb = c_bytes; cb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        let c = from_candidate_bytes(&cb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.multiply(b).multiply(c), a.multiply(b.multiply(c)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "pow_mod's 512-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100/T-177/T-192")]
    fn invert_matches_multiplicative_inverse_definition(a_bytes: [u8; 64]) {
        use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        if a == FieldElement::ZERO {
            return Ok(());
        }
        prop_assert_eq!(a.invert().multiply(a), FieldElement::ONE);
    }

    #[test]
    #[cfg_attr(miri, ignore = "sqrt's two 512-iteration pow_mod ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177/T-192")]
    fn sqrt_of_a_square_squares_back(a_bytes: [u8; 64]) {
        use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let square = a.square();
        assert!(square.euler_criterion() || square == FieldElement::ZERO);
        prop_assert_eq!(square.sqrt().square(), square);
    }

    #[test]
    #[cfg_attr(miri, ignore = "pow_mod's 512-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100/T-177/T-192")]
    fn pow_mod_matches_repeated_squaring_reference(a_bytes: [u8; 64], exp_byte: u8) {
        use dstu_core::hazmat::dstu9041::fp512::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let mut naive = FieldElement::ONE;
        for _ in 0..exp_byte {
            naive = naive.multiply(a);
        }
        let mut exponent = [0u8; 64];
        exponent[63] = exp_byte;
        prop_assert_eq!(a.pow_mod(&exponent), naive);
    }
}
