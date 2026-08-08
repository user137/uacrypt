//! Black-box tests for `dstu_core::hazmat::dstu9041::curve512` (twisted Edwards point arithmetic,
//! E512/1, T-192 Phase 2 - see `docs/pseudocode/dstu9041.md` Додаток Б.4, `docs/DECISIONS.md`
//! D-176/D-177). Test-first per T-192's own plan: written before `curve512` exists.
//!
//! No Додаток Г.3 worked-example `Q`/`R`/`T`/`epsilon`/`e` values are transcribed yet (that's
//! T-192 Phase 4's own job, mirroring how `curve-E256-1.json`'s `g1-worked-example.json` sibling
//! fed `dstu9041_curve.rs`'s `seven_times_p_equals_r`-style tests) - this file uses `base_point()`
//! itself (already verified on-curve, `n*P==NEUTRAL`, D-176) as the one concrete in-subgroup point
//! available this phase, standing in for `q_point()`'s role in `dstu9041_curve.rs` where a real
//! worked-example point would otherwise be used.

use dstu_core::hazmat::dstu9041::curve512::{
    base_point, is_valid_scalar, order, point_from_x, Point,
};
use dstu_core::hazmat::dstu9041::fp512::FieldElement;

fn decode_hex_padded(s: &str) -> [u8; 64] {
    let mut padded = String::with_capacity(128);
    for _ in 0..(128 - s.len()) {
        padded.push('0');
    }
    padded.push_str(s);
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).expect("valid hex digit");
    }
    out
}

fn scalar(hex: &str) -> [u8; 64] {
    decode_hex_padded(hex)
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = json.find(pattern.as_str()).expect("key present in vector");
    let after = &json[start + pattern.len()..];
    let end = after.find('"').expect("well-formed test-vector JSON");
    &after[..end]
}

const CURVE_VECTOR: &str = include_str!("vectors/dstu9041/curve-E512-1.json");

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
    let mut two = [0u8; 64];
    two[63] = 2;
    assert_eq!(p.scalar_multiply(&two), p.add(p));
}

// --- Boundary conditions (D-110/T-152 precedent: curve163::scalar_multiply's affine-recovery
// silently broke exactly at k in {0, n-1, n} - invisible to KAT/proptest sampling). ---

#[test]
fn scalar_multiply_by_zero_is_neutral() {
    assert_eq!(base_point().scalar_multiply(&[0u8; 64]), Point::NEUTRAL);
}

#[test]
fn scalar_multiply_by_one_is_unchanged() {
    let mut one = [0u8; 64];
    one[63] = 1;
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
    let zero = [0u8; 64];
    let mut one = [0u8; 64];
    one[63] = 1;
    let mut two = [0u8; 64];
    two[63] = 2;
    let mut n_minus_2 = n;
    n_minus_2[63] -= 2;
    let mut n_minus_1 = n;
    n_minus_1[63] -= 1;

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

// --- The r=p-1 finding, re-derived for E512/1 specifically (D-176: this is pure algebra
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
// `crypto_box::PublicKey::from_bytes` once T-192 Phase 5 wires `l(p)=512` into `crypto_box`, out
// of scope for this task per its own "explicitly out of scope" note). ---

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
    let mut two = [0u8; 64];
    two[63] = 2;
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
/// "twist attack" item) - re-checked for E512/1's own `p` rather than assumed to carry over.
#[cfg_attr(
    miri,
    ignore = "point_from_x's rejection path still runs a 512-iteration invert() and euler_criterion() pow_mod every call - too slow to interpret under Miri, same T-100/T-156/T-177 class"
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
