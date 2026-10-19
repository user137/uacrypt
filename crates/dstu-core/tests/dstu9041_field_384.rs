//! Black-box tests for `dstu_core::hazmat::dstu9041::fp384` (`F_p` arithmetic, `l(p)=384`, E384/1's
//! `p`, T-297 - `docs/DECISIONS.md` D-241/D-244), written before `fp384` existed. Generated from
//! `dstu9041_field_512.rs` by script; `A_HEX`/`B_HEX`/etc. come from Python's own big integers in
//! that script (a separate implementation from this crate's), not from the standard, which has no
//! raw field vectors.

use dstu_core::hazmat::dstu9041::fp384::FieldElement;
use proptest::prelude::*;

fn decode_hex(s: &str) -> [u8; 48] {
    let mut out = [0u8; 48];
    for i in 0..48 {
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

const CURVE_VECTOR: &str = include_str!("vectors/dstu9041/curve-E384-1.json");

/// Sourced from the curve vector JSON itself, not hardcoded - D-166's "the committed `p_hex` was
/// wrong for two sessions" lesson applies here too: a hardcoded copy would not catch a future fix
/// to the vector file going stale in this test.
fn p_hex() -> &'static str {
    extract(CURVE_VECTOR, "p_hex")
}

const P_MINUS_1_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF79C";

const A_HEX: &str = "03863FBE1E7C804791C698B6DEDD590157C6BFFA8702A59628E3A68621D989FF6CEAC6AC1693131F76F3867B9A74172A";
const B_HEX: &str = "E4FB581BE017943802F7E6F662458DDD42079A9439C82E9C8657173D82D14F63E2C9801DFEB6F15158981027A558930E";
const A_PLUS_B_HEX: &str = "E88197D9FE94147F94BE7FAD4122E6DE99CE5A8EC0CAD432AF3ABDC3A4AAD9634FB446CA154A0470CF8B96A33FCCAA38";
const A_MINUS_B_HEX: &str = "1E8AE7A23E64EC0F8ECEB1C07C97CB2415BF25664D3A76F9A28C8F489F083A9B8A21468E17DC21CE1E5B7653F51B7BB9";
const A_MUL_B_HEX: &str = "733B0FA9285BA3DD3DF6219749BA29EB7FE38BE4D841C8ABDD24768AEB126A92755F96875A5EAEF9BC540EC1BDF11E55";
const A_SQUARE_HEX: &str = "9E9357ECA0358FF391A83D901CA8EF673776AE54554C2EF25B91DCD5F384E3970721FB96609B98240FAF29FB9F78553B";
const A_INV_HEX: &str = "BE09DF20C8D3D27824E9740B2D74AF99B70F25A62E32C4515DD8684DD3E59F2B3E3267AB5AFED139CA002079B8DE5AB7";
const SMALL_QR_SQRT_HEX: &str = "0FC018B98FDDA0BB3E5D4C624BB629BFF20D3AB6282AF7A146DDA3B30799D5B49BF366AE044290BCDA185AF67472D633";

/// `5` - the smallest quadratic residue `> 1` other than the trivial `4` mod this `p` (found by
/// the generator, not assumed from the other curves).
fn small_qr_bytes() -> [u8; 48] {
    let mut out = [0u8; 48];
    out[47] = 5;
    out
}

/// `2` - a non-residue mod this `p` too (checked by the generator, D-241).
fn small_non_qr_bytes() -> [u8; 48] {
    let mut out = [0u8; 48];
    out[47] = 2;
    out
}

#[test]
fn p_is_5_mod_8() {
    let p = decode_hex(p_hex());
    assert_eq!(p[47] % 8, 5);
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
    assert_eq!(fe(A_HEX).pow_mod(&[0u8; 48]), FieldElement::ONE);
}

#[test]
fn pow_mod_zero_base_by_zero_exponent_is_one_by_convention() {
    assert_eq!(FieldElement::ZERO.pow_mod(&[0u8; 48]), FieldElement::ONE);
}

#[test]
fn from_candidate_bytes_accepts_p_minus_1() {
    use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
    assert!(from_candidate_bytes(&decode_hex(P_MINUS_1_HEX)).is_some());
}

#[test]
fn from_candidate_bytes_rejects_p_itself() {
    use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
    assert!(from_candidate_bytes(&decode_hex(p_hex())).is_none());
}

#[test]
fn from_candidate_bytes_rejects_all_ff() {
    use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
    assert!(from_candidate_bytes(&[0xFFu8; 48]).is_none());
}

#[test]
fn from_candidate_bytes_accepts_zero() {
    use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
    assert!(from_candidate_bytes(&[0u8; 48]).is_some());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn add_sub_are_inverse(a_bytes: [u8; 48], b_bytes: [u8; 48]) {
        use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.add(b).sub(b), a);
    }

    #[test]
    fn multiply_is_commutative(a_bytes: [u8; 48], b_bytes: [u8; 48]) {
        use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.multiply(b), b.multiply(a));
    }

    #[test]
    fn multiply_is_associative(a_bytes: [u8; 48], b_bytes: [u8; 48], c_bytes: [u8; 48]) {
        use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let mut bb = b_bytes; bb[0] &= 0x7F;
        let mut cb = c_bytes; cb[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let b = from_candidate_bytes(&bb).expect("masked top bit keeps value < p");
        let c = from_candidate_bytes(&cb).expect("masked top bit keeps value < p");
        prop_assert_eq!(a.multiply(b).multiply(c), a.multiply(b.multiply(c)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "pow_mod's 384-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100/T-177/T-297")]
    fn invert_matches_multiplicative_inverse_definition(a_bytes: [u8; 48]) {
        use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        if a == FieldElement::ZERO {
            return Ok(());
        }
        prop_assert_eq!(a.invert().multiply(a), FieldElement::ONE);
    }

    #[test]
    #[cfg_attr(miri, ignore = "sqrt's two 384-iteration pow_mod ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177/T-297")]
    fn sqrt_of_a_square_squares_back(a_bytes: [u8; 48]) {
        use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let square = a.square();
        assert!(square.euler_criterion() || square == FieldElement::ZERO);
        prop_assert_eq!(square.sqrt().square(), square);
    }

    #[test]
    #[cfg_attr(miri, ignore = "pow_mod's 384-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100/T-177/T-297")]
    fn pow_mod_matches_repeated_squaring_reference(a_bytes: [u8; 48], exp_byte: u8) {
        use dstu_core::hazmat::dstu9041::fp384::from_candidate_bytes;
        let mut ab = a_bytes; ab[0] &= 0x7F;
        let a = from_candidate_bytes(&ab).expect("masked top bit keeps value < p");
        let mut naive = FieldElement::ONE;
        for _ in 0..exp_byte {
            naive = naive.multiply(a);
        }
        let mut exponent = [0u8; 48];
        exponent[47] = exp_byte;
        prop_assert_eq!(a.pow_mod(&exponent), naive);
    }
}
