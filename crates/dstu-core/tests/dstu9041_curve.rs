//! Black-box tests for `dstu_core::hazmat::dstu9041::curve256` (twisted Edwards point arithmetic,
//! E256/1 - see `docs/pseudocode/dstu9041.md` Додаток Б.4, `docs/DECISIONS.md` D-163/D-165/D-166).
//! Test-first per T-177: written before `curve256` exists.

use dstu_core::hazmat::dstu9041::curve256::{
    base_point, is_valid_scalar, order, point_from_x, Point,
};
use dstu_core::hazmat::dstu9041::fp256::FieldElement;

fn decode_hex_padded(s: &str) -> [u8; 32] {
    let mut padded = String::with_capacity(64);
    for _ in 0..(64 - s.len()) {
        padded.push('0');
    }
    padded.push_str(s);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).expect("valid hex digit");
    }
    out
}

fn point(x_hex: &str, y_hex: &str) -> Point {
    Point {
        x: FieldElement::from_be_bytes(&decode_hex_padded(x_hex)),
        y: FieldElement::from_be_bytes(&decode_hex_padded(y_hex)),
    }
}

fn scalar(hex: &str) -> [u8; 32] {
    decode_hex_padded(hex)
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = json.find(pattern.as_str()).expect("key present in vector");
    let after = &json[start + pattern.len()..];
    let end = after.find('"').expect("well-formed test-vector JSON");
    &after[..end]
}

const CURVE_VECTOR: &str = include_str!("vectors/dstu9041/curve-E256-1.json");
const EXAMPLE_VECTOR: &str = include_str!("vectors/dstu9041/g1-worked-example.json");

fn q_point() -> Point {
    point_from_block(EXAMPLE_VECTOR, "public_key_Q")
}

// The JSON has three x_hex/y_hex pairs (Q, R, T) - `extract` finds the first occurrence, so
// locate each block by its own containing key first.
fn point_from_block(json: &str, block_key: &str) -> Point {
    let pattern = format!("\"{block_key}\": {{");
    let start = json.find(pattern.as_str()).expect("block present");
    let block = &json[start..];
    let end = block.find('}').expect("well-formed block");
    let block = &block[..end];
    point(extract(block, "x_hex"), extract(block, "y_hex"))
}

#[test]
fn base_point_is_on_curve() {
    assert!(base_point().is_on_curve());
}

#[test]
fn order_matches_vector() {
    assert_eq!(order(), scalar(extract(CURVE_VECTOR, "n_hex")));
}

#[test]
fn q_is_on_curve() {
    assert!(point_from_block(EXAMPLE_VECTOR, "public_key_Q").is_on_curve());
}

#[test]
fn r_is_on_curve() {
    assert!(point_from_block(EXAMPLE_VECTOR, "R_point").is_on_curve());
}

#[test]
fn t_is_on_curve() {
    assert!(point_from_block(EXAMPLE_VECTOR, "T_point").is_on_curve());
}

#[test]
fn n_times_base_point_is_neutral() {
    let n = scalar(extract(CURVE_VECTOR, "n_hex"));
    assert_eq!(base_point().scalar_multiply(&n), Point::NEUTRAL);
}

#[test]
fn seven_times_p_equals_r() {
    // The critical tripwire: epsilon=7 has 253 leading zero bits - this is what actually probes
    // "accumulator starts at neutral, all 256 iterations always run, doubling neutral stays
    // neutral through the complete Edwards formula."
    let epsilon = scalar(extract(EXAMPLE_VECTOR, "ephemeral_key_epsilon_hex"));
    let r = point_from_block(EXAMPLE_VECTOR, "R_point");
    assert_eq!(base_point().scalar_multiply(&epsilon), r);
}

#[test]
fn seven_times_q_equals_t() {
    let epsilon = scalar(extract(EXAMPLE_VECTOR, "ephemeral_key_epsilon_hex"));
    let t = point_from_block(EXAMPLE_VECTOR, "T_point");
    assert_eq!(q_point().scalar_multiply(&epsilon), t);
}

#[test]
fn thirty_seven_times_p_equals_q() {
    let e = scalar(extract(EXAMPLE_VECTOR, "private_key_e_hex"));
    assert_eq!(base_point().scalar_multiply(&e), q_point());
}

#[test]
fn projective_self_add_matches_scalar_multiply_by_two() {
    let p = base_point();
    let two = {
        let mut s = [0u8; 32];
        s[31] = 2;
        s
    };
    assert_eq!(p.scalar_multiply(&two), p.add(p));
}

// --- Boundary conditions (D-110/T-152 precedent: curve163::scalar_multiply's affine-recovery
// silently broke exactly at k in {0, n-1, n} - invisible to KAT/proptest sampling). ---

#[test]
fn scalar_multiply_by_zero_is_neutral() {
    assert_eq!(base_point().scalar_multiply(&[0u8; 32]), Point::NEUTRAL);
}

#[test]
fn scalar_multiply_by_one_is_unchanged() {
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(base_point().scalar_multiply(&one), base_point());
}

#[test]
fn scalar_multiply_by_n_minus_one_is_negation() {
    let n = scalar(extract(CURVE_VECTOR, "n_hex"));
    let mut n_minus_1 = n;
    // n is odd (prime), so subtracting 1 never borrows into a carry across bytes here except the
    // last byte - safe as a direct decrement since n's low byte (from n_hex) is not 0x00.
    let last = n_minus_1.len() - 1;
    n_minus_1[last] -= 1;
    let negation = base_point().scalar_multiply(&n_minus_1);
    // -P has the same y (Edwards negation flips x, per the curve's own x/y-swapped form here -
    // verified directly: (-P) + P must equal NEUTRAL).
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
    let zero = [0u8; 32];
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut two = [0u8; 32];
    two[31] = 2;
    let mut n_minus_2 = n;
    n_minus_2[31] -= 2;
    let mut n_minus_1 = n;
    n_minus_1[31] -= 1;

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

// --- The r=p-1 security finding (advisor-flagged, verified numerically before this plan): clause
// 12 step 2 rejects r=0, r=1, r^2=a*d^-1 mod p - but not r=p-1, which reconstructs to R'=(p-1,0),
// a genuine order-2 point OUTSIDE the base point's subgroup <P>. This test documents the
// underlying arithmetic fact at the curve level, independent of Phase 4's rejection logic - it
// would catch a regression if the curve math itself ever silently changed. ---

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

// --- `point_from_x` (T-178's extraction of the shared reconstruction gauntlet out of
// `encryption::decrypt`, reused by `crypto_box::PublicKey::from_bytes`) ---

#[test]
fn point_from_x_reconstructs_a_point_matching_q_or_its_negation() {
    let q = q_point();
    let reconstructed = point_from_x(q.x).expect("Q's own x is a valid, in-subgroup point");
    // -Q = (x, -y): this curve's own negation is (x, -y) (the x/y-swapped Edwards form).
    let negated_q = Point {
        x: q.x,
        y: FieldElement::ZERO.sub(q.y),
    };
    assert!(reconstructed == q || reconstructed == negated_q);
}

#[test]
fn point_from_x_gives_same_kappa_regardless_of_sqrt_branch() {
    // The load-bearing property `crypto_box`'s x-only `PublicKey` compression relies on: whichever
    // of {Q, -Q} `point_from_x` returns, `epsilon * that_point` has the same x-coordinate as
    // `epsilon * Q` - because x_T = x_{-T} on this curve and k*(-Q) = -(k*Q) for any scalar k.
    let q = q_point();
    let reconstructed = point_from_x(q.x).expect("Q's own x is a valid, in-subgroup point");
    let epsilon = scalar(extract(EXAMPLE_VECTOR, "ephemeral_key_epsilon_hex"));
    assert_eq!(
        q.scalar_multiply(&epsilon).x,
        reconstructed.scalar_multiply(&epsilon).x
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
