//! Black-box test for `dstu_core::hazmat::dstu4145::curve257` against
//! `tests/vectors/dstu4145/gf2m257_arith.json`'s `point_cases` - unit-level EC point-arithmetic
//! cases generated via Bouncy Castle's `ECPoint.F2m` (single-oracle at this granularity, same
//! posture as `gf2m163.json`/`dstu4145_curve.rs` - see `docs/DECISIONS.md` D-185/D-186). Same
//! hand-rolled JSON extractor as `dstu4145_gf2m257.rs`.

use dstu_core::hazmat::dstu4145::curve257::{self, Point};
use dstu_core::hazmat::dstu4145::gf2m257::FieldElement;

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "odd-length hex string in test vector: {s}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit in test vector"))
        .collect()
}

fn field(s: &str) -> FieldElement {
    FieldElement::from_be_bytes(&decode_hex(s))
}

fn scalar33(s: &str) -> [u8; 33] {
    let bytes = decode_hex(s);
    let mut out = [0u8; 33];
    let start = 33 - bytes.len();
    out[start..].copy_from_slice(&bytes);
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

#[test]
fn curve257_generator_is_on_curve() {
    assert!(Point::generator().is_on_curve());
}

#[test]
fn curve257_generator_times_order_is_infinity() {
    let g = Point::generator();
    assert_eq!(g.scalar_multiply(&curve257::order()), Point::Infinity);
}

#[test]
fn curve257_point_arithmetic_matches_bouncy_castle() {
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    let cases = extract_objects(json, "point_cases");
    assert!(
        !cases.is_empty(),
        "no point_cases found - extractor or fixture is broken"
    );

    let mut checked = 0;
    for case in cases {
        let op = extract_all(case, "op")[0];

        match op {
            "double" => {
                let px = field_of(case, "px").unwrap();
                let py = field_of(case, "py").unwrap();
                let rx = field_of(case, "rx").unwrap();
                let ry = field_of(case, "ry").unwrap();
                let p = Point::Affine(px, py);
                assert_eq!(p.double(), Point::Affine(rx, ry), "double mismatch: {case}");
            }
            "add" => {
                let px = field_of(case, "px").unwrap();
                let py = field_of(case, "py").unwrap();
                let qx = field_of(case, "qx").unwrap();
                let qy = field_of(case, "qy").unwrap();
                let rx = field_of(case, "rx").unwrap();
                let ry = field_of(case, "ry").unwrap();
                let p = Point::Affine(px, py);
                let q = Point::Affine(qx, qy);
                assert_eq!(p + q, Point::Affine(rx, ry), "add mismatch: {case}");
            }
            "scalar_multiply" => {
                let k = extract_all(case, "k")[0];
                let rx = field_of(case, "rx").unwrap();
                let ry = field_of(case, "ry").unwrap();
                let g = Point::generator();
                assert_eq!(
                    g.scalar_multiply(&scalar33(k)),
                    Point::Affine(rx, ry),
                    "scalar_multiply mismatch: {case}"
                );
            }
            other => panic!("unknown point op in test vector: {other}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 60, "expected 20 cases x 3 ops from the generator");
}
