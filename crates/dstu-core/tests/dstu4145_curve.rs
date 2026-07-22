//! Black-box test for `dstu_core::hazmat::dstu4145::curve163` against
//! `tests/vectors/dstu4145/gf2m163_arith.json`'s `point_cases` - unit-level point-arithmetic
//! cases generated via Bouncy Castle's `ECPoint.F2m` (single-oracle at this granularity, see
//! `DECISIONS.md` D-25). Same hand-rolled JSON extractor as `tests/dstu4145_gf2m.rs`.

use dstu_core::hazmat::dstu4145::curve163::Point;
use dstu_core::hazmat::dstu4145::gf2m163::FieldElement;

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
