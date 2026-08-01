//! Black-box test for `dstu_core::hazmat::dstu4145::curve163` against
//! `tests/vectors/dstu4145/gf2m163_arith.json`'s `point_cases` - unit-level point-arithmetic
//! cases generated via Bouncy Castle's `ECPoint.F2m` (single-oracle at this granularity, see
//! `docs/DECISIONS.md` D-25). Same hand-rolled JSON extractor as `tests/dstu4145_gf2m.rs`.

use dstu_core::hazmat::dstu4145::curve163;
use dstu_core::hazmat::dstu4145::curve163::Point;
use dstu_core::hazmat::dstu4145::gf2m163::FieldElement;
use proptest::prelude::*;

fn decode_hex(s: &str) -> Vec<u8> {
    let padded;
    let s = if s.len().is_multiple_of(2) {
        s
    } else {
        padded = format!("0{s}");
        &padded
    };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit in test vector"))
        .collect()
}

fn field(s: &str) -> FieldElement {
    FieldElement::from_be_bytes(&decode_hex(s))
}

/// Left-pads to exactly 21 bytes (163 bits) - `scalar_multiply` requires a fixed-width scalar.
fn scalar(s: &str) -> [u8; 21] {
    let bytes = decode_hex(s);
    let mut out = [0u8; 21];
    out[21 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn extract_all<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let pattern = format!("\"{key}\": \"");
    let mut results = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(pattern.as_str()) {
        let after = &rest[start + pattern.len()..];
        let end = after.find('"').expect("well-formed test-vector JSON");
        results.push(&after[..end]);
        rest = &after[end + 1..];
    }
    results
}

fn extract_objects<'a>(json: &'a str, array_key: &str) -> Vec<&'a str> {
    let key_pos = json
        .find(&format!("\"{array_key}\""))
        .unwrap_or_else(|| panic!("missing \"{array_key}\" array in test vector JSON"));
    let array_start = json[key_pos..].find('[').unwrap() + key_pos;
    let mut objects = Vec::new();
    let mut depth = 0i32;
    let mut object_start = 0usize;
    for (i, c) in json[array_start..].char_indices() {
        let pos = array_start + i;
        match c {
            '{' => {
                if depth == 0 {
                    object_start = pos;
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    objects.push(&json[object_start..=pos]);
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }
    objects
}

fn field_of(obj: &str, key: &str) -> Option<FieldElement> {
    extract_all(obj, key).first().map(|s| field(s))
}

fn point_of(obj: &str, x_key: &str, y_key: &str) -> Point {
    Point::Affine(
        field_of(obj, x_key).unwrap_or_else(|| panic!("missing \"{x_key}\" in {obj}")),
        field_of(obj, y_key).unwrap_or_else(|| panic!("missing \"{y_key}\" in {obj}")),
    )
}

#[test]
fn gf2m163_generator_matches_vector() {
    let json = include_str!("vectors/dstu4145/gf2m163_arith.json");
    let gx = field_of(json, "x").expect("base_point.x");
    let gy = field_of(json, "y").expect("base_point.y");
    assert_eq!(Point::generator(), Point::Affine(gx, gy));
}

// `Point::double`/`add` each call `FieldElement::invert` once. Under the old 162-multiply direct
// form (D-25) this was as expensive per call as `scalar_multiply`'s own ladder, making these two
// tests too slow to interpret under Miri (>40 min unfinished, T-100). D-109/T-153's 9-multiply
// addition-chain `invert` re-measured (not assumed) at ~91-95s for these two tests, well within CI's
// budget - exclusion removed, real Miri coverage restored.
#[test]
fn gf2m163_point_double_matches_bouncy_castle() {
    let json = include_str!("vectors/dstu4145/gf2m163_arith.json");
    let cases: Vec<_> = extract_objects(json, "point_cases")
        .into_iter()
        .filter(|c| extract_all(c, "op") == ["double"])
        .collect();
    assert!(!cases.is_empty(), "no double cases found");
    for case in &cases {
        let p = point_of(case, "px", "py");
        let expected = point_of(case, "rx", "ry");
        assert_eq!(p.double(), expected, "point double mismatch for {case}");
    }
}

// See `gf2m163_point_double_matches_bouncy_castle`'s comment above - same fix, re-measured
// separately at ~95s.
#[test]
fn gf2m163_point_add_matches_bouncy_castle() {
    let json = include_str!("vectors/dstu4145/gf2m163_arith.json");
    let cases: Vec<_> = extract_objects(json, "point_cases")
        .into_iter()
        .filter(|c| extract_all(c, "op") == ["add"])
        .collect();
    assert!(!cases.is_empty(), "no add cases found");
    for case in &cases {
        let p = point_of(case, "px", "py");
        let q = point_of(case, "qx", "qy");
        let expected = point_of(case, "rx", "ry");
        assert_eq!(p + q, expected, "point add mismatch for {case}");
    }
}

// `scalar_multiply`'s 163-iteration constant-time ladder takes minutes per call to interpret
// under Miri (docs/TASKS.md T-100/T-85/D-46), not seconds - excluded from CI's required Miri gate for
// cost reasons; `cargo test` (required, fast) still covers this every push.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn gf2m163_scalar_multiply_matches_bouncy_castle() {
    let json = include_str!("vectors/dstu4145/gf2m163_arith.json");
    let cases: Vec<_> = extract_objects(json, "point_cases")
        .into_iter()
        .filter(|c| extract_all(c, "op") == ["scalar_multiply"])
        .collect();
    assert!(!cases.is_empty(), "no scalar_multiply cases found");
    for case in &cases {
        let k = scalar(extract_all(case, "k")[0]);
        let expected = point_of(case, "rx", "ry");
        assert_eq!(
            Point::generator().scalar_multiply(&k),
            expected,
            "scalar_multiply mismatch for {case}"
        );
    }
}

/// The generator's random 163-bit-ish scalars are very unlikely to exercise leading zero bits.
/// `scalar_multiply` is meant to run the same fixed 163 iterations regardless (see its doc
/// comment on the infinity-starting ladder) - cross-check small scalars against repeated
/// `Point::add`, which has no such fixed-width concern, to exercise that path directly.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn gf2m163_scalar_multiply_matches_repeated_addition_for_small_scalars() {
    let g = Point::generator();
    let mut expected = Point::Infinity;
    for k in 1u32..=32 {
        expected = expected + g;
        let mut bytes = [0u8; 21];
        bytes[17..].copy_from_slice(&k.to_be_bytes());
        assert_eq!(g.scalar_multiply(&bytes), expected, "mismatch at k={k}");
    }
}

// `curve163::verify_combine` (docs/DECISIONS.md D-108) computes `s*g + r*q` - the same quantity
// `signature::verify` needs - via a different implementation per build profile (default: a
// projective/Shamir's-trick fast path; `small-tables`: the classic `scalar_multiply`-based
// computation below, unchanged). Every test below checks the wrapper (whichever body the active
// feature set compiles in) against this same classic computation done inline, never a second copy
// of the new code - trivially true under `small-tables`, genuinely discriminating by default.
fn classic_combine(g: Point, s: &[u8; 21], q: Point, r: &[u8; 21]) -> Point {
    g.scalar_multiply(s) + q.scalar_multiply(r)
}

fn u32_scalar(k: u32) -> [u8; 21] {
    let mut bytes = [0u8; 21];
    bytes[17..].copy_from_slice(&k.to_be_bytes());
    bytes
}

#[test]
fn verify_combine_matches_classic_for_small_scalars() {
    let g = Point::generator();
    let q = g.double(); // a second, distinct public point - not g itself

    for s_val in 1u32..=8 {
        for r_val in 1u32..=8 {
            let s = u32_scalar(s_val);
            let r = u32_scalar(r_val);
            assert_eq!(
                curve163::verify_combine(g, &s, q, &r),
                classic_combine(g, &s, q, &r),
                "mismatch at s={s_val} r={r_val}"
            );
        }
    }
}

#[test]
fn verify_combine_matches_classic_for_asymmetric_magnitudes() {
    let g = Point::generator();
    let q = g.double();

    let one = u32_scalar(1);
    // A large (~160-bit) scalar, well clear of `order()`'s own boundary: `scalar_multiply`'s own
    // doc comment only promises correctness for `k < n`, and `order()`/`order()-1` sit exactly on
    // that boundary in a way this test deliberately avoids (see the `docs/TASKS.md` follow-up this
    // session filed after finding `q.scalar_multiply(order())` isn't `Infinity` there - a
    // pre-existing `scalar_multiply` question, unrelated to `verify_combine`, not chased further
    // here). Zeroing `order()`'s top byte drops it to roughly half of `n`'s magnitude - still large
    // enough to exercise the skip-leading-zeros logic asymmetrically against `one`.
    let mut large = curve163::order();
    large[0] = 0;

    assert_eq!(
        curve163::verify_combine(g, &one, q, &large),
        classic_combine(g, &one, q, &large),
        "s=1, r=large mismatch"
    );
    assert_eq!(
        curve163::verify_combine(g, &large, q, &one),
        classic_combine(g, &large, q, &one),
        "s=large, r=1 mismatch"
    );
}

#[test]
fn verify_combine_matches_classic_when_r_eq_s_eq_one() {
    let g = Point::generator();
    let q = g.double();
    let one = u32_scalar(1);

    assert_eq!(
        curve163::verify_combine(g, &one, q, &one),
        classic_combine(g, &one, q, &one)
    );
}

/// Hand-constructed case where the Shamir accumulator hits `Point::Infinity` mid-loop (not just
/// at the final result) while the final result is nonzero - the totality guards `verify_combine`'s
/// fast path needs (docs/DECISIONS.md D-108) exist precisely for this shape, and a random proptest
/// is very unlikely to stumble onto it (probability ~2^-163 for uniform random scalars).
///
/// Construction: with `q = -2*g` (`d=2`), processing `s`/`r` from the top bit down, the partial
/// sum after `k` bits is `s_partial*g + r_partial*q = (s_partial - 2*r_partial)*g`. Choosing
/// `s = 0b1000` (8), `r = 0b0111` (7): after the top 2 bits, `s_partial = 0b10 = 2`,
/// `r_partial = 0b01 = 1`, so the partial sum is `(2 - 2*1)*g = Infinity`. Continuing the
/// remaining 2 bits gives the full, nonzero result `(8 - 2*7)*g = -6*g`.
#[test]
fn verify_combine_handles_mid_loop_infinity() {
    let g = Point::generator();
    let d = u32_scalar(2);
    let q = match g.scalar_multiply(&d) {
        Point::Affine(x, y) => Point::Affine(x, y).negate(),
        Point::Infinity => panic!("d=2 must not be degenerate"),
    };

    let s = u32_scalar(8);
    let r = u32_scalar(7);

    assert_eq!(
        curve163::verify_combine(g, &s, q, &r),
        classic_combine(g, &s, q, &r),
        "mid-loop-infinity case mismatch"
    );
}

proptest! {
    #[test]
    fn verify_combine_matches_classic_for_random_scalars(
        d_bytes in prop::collection::vec(any::<u8>(), 20),
        s_bytes in prop::collection::vec(any::<u8>(), 20),
        r_bytes in prop::collection::vec(any::<u8>(), 20),
    ) {
        let g = Point::generator();
        let mut d_arr = [0u8; 21];
        d_arr[1..].copy_from_slice(&d_bytes);
        let mut s_arr = [0u8; 21];
        s_arr[1..].copy_from_slice(&s_bytes);
        let mut r_arr = [0u8; 21];
        r_arr[1..].copy_from_slice(&r_bytes);
        prop_assume!(d_arr != [0u8; 21]);
        prop_assume!(s_arr != [0u8; 21]);
        prop_assume!(r_arr != [0u8; 21]);

        // 160-bit values are comfortably below the curve order n (~163 bits) - same pattern
        // `dstu4145_signature.rs`'s existing round-trip proptest uses for d/e, avoiding an
        // explicit mod-n reduction step in the test itself.
        let q = match g.scalar_multiply(&d_arr) {
            Point::Affine(x, y) => Point::Affine(x, y).negate(),
            Point::Infinity => return Ok(()), // d = 0 mod n - not reachable with a nonzero 160-bit d
        };

        prop_assert_eq!(
            curve163::verify_combine(g, &s_arr, q, &r_arr),
            classic_combine(g, &s_arr, q, &r_arr)
        );
    }
}
