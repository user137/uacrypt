//! Black-box tests for `dstu_core::hazmat::dstu9041::curve384` (twisted Edwards point arithmetic,
//! E384/1, T-297 - `docs/DECISIONS.md` D-241/D-244), written before `curve384` existed. Generated
//! from `dstu9041_curve_512.rs` by script, plus Додаток Г.2's own points at the end (`Q`, `R`, `T`
//! from `g2-worked-example.json`, all of which the document prints and D-241 checked exactly).

use dstu_core::hazmat::dstu9041::curve384::{
    base_point, is_valid_scalar, order, point_from_x, Point,
};
use dstu_core::hazmat::dstu9041::fp384::FieldElement;

fn decode_hex_padded(s: &str) -> [u8; 48] {
    let mut padded = String::with_capacity(96);
    for _ in 0..(96 - s.len()) {
        padded.push('0');
    }
    padded.push_str(s);
    let mut out = [0u8; 48];
    for i in 0..48 {
        out[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).expect("valid hex digit");
    }
    out
}

fn scalar(hex: &str) -> [u8; 48] {
    decode_hex_padded(hex)
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = json.find(pattern.as_str()).expect("key present in vector");
    let after = &json[start + pattern.len()..];
    let end = after.find('"').expect("well-formed test-vector JSON");
    &after[..end]
}

const CURVE_VECTOR: &str = include_str!("vectors/dstu9041/curve-E384-1.json");

#[test]
fn base_point_is_on_curve() {
    assert!(base_point().is_on_curve());
}

#[test]
fn order_matches_vector() {
    assert_eq!(order(), scalar(extract(CURVE_VECTOR, "n_hex")));
}

#[test]
fn n_times_base_point_is_neutral() {
    let n = scalar(extract(CURVE_VECTOR, "n_hex"));
    assert_eq!(base_point().scalar_multiply(&n), Point::NEUTRAL);
}

#[test]
fn projective_self_add_matches_scalar_multiply_by_two() {
    let p = base_point();
    let mut two = [0u8; 48];
    two[47] = 2;
    assert_eq!(p.scalar_multiply(&two), p.add(p));
}

// --- Boundary conditions (D-110/T-152 precedent: curve163::scalar_multiply's affine-recovery
// silently broke exactly at k in {0, n-1, n} - invisible to KAT/proptest sampling). ---

#[test]
fn scalar_multiply_by_zero_is_neutral() {
    assert_eq!(base_point().scalar_multiply(&[0u8; 48]), Point::NEUTRAL);
}

#[test]
fn scalar_multiply_by_one_is_unchanged() {
    let mut one = [0u8; 48];
    one[47] = 1;
    assert_eq!(base_point().scalar_multiply(&one), base_point());
}

#[test]
fn scalar_multiply_by_n_minus_one_is_negation() {
    let n = scalar(extract(CURVE_VECTOR, "n_hex"));
    let mut n_minus_1 = n;
    let last = n_minus_1.len() - 1;
    n_minus_1[last] -= 1;
    let negation = base_point().scalar_multiply(&n_minus_1);
    assert_eq!(negation.add(base_point()), Point::NEUTRAL);
}

#[test]
fn scalar_multiply_by_n_plus_one_wraps_to_p_itself() {
    let n = scalar(extract(CURVE_VECTOR, "n_hex"));
    let mut n_plus_1 = n;
    let last = n_plus_1.len() - 1;
    n_plus_1[last] += 1;
    assert_eq!(base_point().scalar_multiply(&n_plus_1), base_point());
}

#[test]
fn is_valid_scalar_boundaries() {
    let n = scalar(extract(CURVE_VECTOR, "n_hex"));
    let zero = [0u8; 48];
    let mut one = [0u8; 48];
    one[47] = 1;
    let mut two = [0u8; 48];
    two[47] = 2;
    let mut n_minus_2 = n;
    n_minus_2[47] -= 2;
    let mut n_minus_1 = n;
    n_minus_1[47] -= 1;

    assert!(!is_valid_scalar(&zero), "k=0 must be invalid");
    assert!(
        !is_valid_scalar(&one),
        "k=1 must be invalid (strict lower bound)"
    );
    assert!(is_valid_scalar(&two), "k=2 (minimum valid) must be valid");
    assert!(
        is_valid_scalar(&n_minus_2),
        "k=n-2 (maximum valid) must be valid"
    );
    assert!(
        !is_valid_scalar(&n_minus_1),
        "k=n-1 must be invalid (strict upper bound)"
    );
    assert!(!is_valid_scalar(&n), "k=n must be invalid");
}

// --- The r=p-1 finding, re-derived for E384/1 specifically (D-241: this is pure algebra
// independent of p/d/n's concrete values - x=p-1 always solves x^2=1 mod p given the curve's own
// y=0 cross-section - but still checked here at the curve-arithmetic level, not assumed). ---

#[test]
fn r_equals_p_minus_1_reconstructs_the_order_2_point() {
    let p_hex = extract(CURVE_VECTOR, "p_hex");
    let p_minus_1 = FieldElement::from_be_bytes(&decode_hex_padded(p_hex)).sub(FieldElement::ONE);
    let r_prime = Point {
        x: p_minus_1,
        y: FieldElement::ZERO,
    };
    assert!(r_prime.is_on_curve());

    let two_r_prime = r_prime.add(r_prime);
    assert_eq!(two_r_prime, Point::NEUTRAL, "R' must have exact order 2");

    let n = scalar(extract(CURVE_VECTOR, "n_hex"));
    let n_r_prime = r_prime.scalar_multiply(&n);
    assert_eq!(
        n_r_prime, r_prime,
        "R' must be OUTSIDE <P> (n*R' == R' since n is odd and R' has order 2, not neutral)"
    );
}

// --- `point_from_x` (shared reconstruction gauntlet, mirroring `curve256.rs`'s own - reused by
// `crypto_box384::PublicKey::from_bytes`, T-297). ---

#[test]
fn point_from_x_reconstructs_a_point_matching_base_point_or_its_negation() {
    let p = base_point();
    let reconstructed = point_from_x(p.x).expect("P's own x is a valid, in-subgroup point");
    let negated_p = Point {
        x: p.x,
        y: FieldElement::ZERO.sub(p.y),
    };
    assert!(reconstructed == p || reconstructed == negated_p);
}

#[test]
fn point_from_x_gives_same_kappa_regardless_of_sqrt_branch() {
    let p = base_point();
    let reconstructed = point_from_x(p.x).expect("P's own x is a valid, in-subgroup point");
    let mut two = [0u8; 48];
    two[47] = 2;
    assert_eq!(
        p.scalar_multiply(&two).x,
        reconstructed.scalar_multiply(&two).x
    );
}

#[test]
fn point_from_x_rejects_zero_one_and_p_minus_1() {
    let p_hex = extract(CURVE_VECTOR, "p_hex");
    let p_minus_1 = FieldElement::from_be_bytes(&decode_hex_padded(p_hex)).sub(FieldElement::ONE);
    assert!(point_from_x(FieldElement::ZERO).is_none());
    assert!(point_from_x(FieldElement::ONE).is_none());
    assert!(point_from_x(p_minus_1).is_none());
}

/// Same reasoning as `dstu9041_curve.rs`'s own `point_from_x_rejects_a_non_residue_x` (T-183
/// "twist attack" item) - re-checked for E384/1's own `p` rather than assumed to carry over.
#[cfg_attr(
    miri,
    ignore = "point_from_x's rejection path still runs a 384-iteration invert() and euler_criterion() pow_mod every call - too slow to interpret under Miri, same T-100/T-156/T-177 class"
)]
#[test]
fn point_from_x_rejects_a_non_residue_x() {
    let mut candidate_x = FieldElement::from_be_bytes(&decode_hex_padded("02"));
    for _ in 0..16u32 {
        if point_from_x(candidate_x).is_none() {
            return;
        }
        candidate_x = candidate_x.add(FieldElement::from_be_bytes(&decode_hex_padded("01")));
    }
    panic!("no non-residue x found in 16 sequential tries starting at x=2 - unexpectedly unlucky");
}

// --- Додаток Г.2 (D-241): every hex value the document prints; `e = 25` is hex, 37 decimal. ---

const G2_VECTOR: &str = include_str!("vectors/dstu9041/g2-worked-example.json");

fn g2_point(block: &str) -> Point {
    let start = G2_VECTOR
        .find(&format!("\"{block}\": {{"))
        .expect("point block present");
    let body = &G2_VECTOR[start..];
    Point {
        x: FieldElement::from_be_bytes(&decode_hex_padded(extract(body, "x_hex"))),
        y: FieldElement::from_be_bytes(&decode_hex_padded(extract(body, "y_hex"))),
    }
}

#[cfg_attr(
    miri,
    ignore = "a 384-iteration scalar-multiply ladder - too slow to interpret under Miri, same T-100/T-177 class"
)]
#[test]
fn g2_public_key_is_37_times_base_point() {
    assert_eq!(
        base_point().scalar_multiply(&scalar("25")),
        g2_point("public_key_Q")
    );
}

#[cfg_attr(
    miri,
    ignore = "a 384-iteration scalar-multiply ladder - too slow to interpret under Miri, same T-100/T-177 class"
)]
#[test]
fn g2_r_is_7_times_base_point() {
    assert_eq!(
        base_point().scalar_multiply(&scalar("07")),
        g2_point("R_point")
    );
}

#[cfg_attr(
    miri,
    ignore = "a 384-iteration scalar-multiply ladder - too slow to interpret under Miri, same T-100/T-177 class"
)]
#[test]
fn g2_t_is_7_times_q() {
    assert_eq!(
        g2_point("public_key_Q").scalar_multiply(&scalar("07")),
        g2_point("T_point")
    );
}

#[test]
fn g2_points_are_on_curve() {
    for block in ["public_key_Q", "R_point", "T_point"] {
        assert!(g2_point(block).is_on_curve(), "{block}");
    }
}
