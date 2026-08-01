//! Black-box test for `dstu_core::hazmat::dstu4145::gf2m163` against
//! `tests/vectors/dstu4145/gf2m163_arith.json` - unit-level field-arithmetic cases generated via
//! Bouncy Castle's `ECFieldElement.F2m` (single-oracle at this granularity, see `docs/DECISIONS.md`
//! D-25; `gf2m163.json`'s signature-level vector is the dual-sourced end-to-end check, once the
//! point/signature layers exist). Same hand-rolled JSON extractor as `tests/kalyna.rs`/
//! `tests/kupyna.rs` - no JSON dependency for a fixed, project-controlled vector shape.

use dstu_core::hazmat::dstu4145::gf2m163::FieldElement;
use proptest::prelude::*;

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

/// Pulls every value of `"key": "..."` out of the vector JSON, in file order.
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

/// Splits the `"field_cases"` array into one JSON-object substring per case (same brace-counting
/// approach as `tests/oracle-harness/java/src/main/java/OracleHarness.java`'s `extractCases`).
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

// `FieldElement::invert` was a 162-step square-and-multiply exponentiation (as expensive per call
// as `Point::scalar_multiply`'s ladder) when this test's Miri exclusion was first written (D-25,
// T-100). `docs/DECISIONS.md` D-109/`docs/TASKS.md` T-153 replaced it with a 9-multiply addition-chain
// form - re-measured (not assumed) to now complete under Miri in ~76s
// (`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=1`, CI's actual invocation), so the exclusion
// was removed; this test's 20 "invert" cases (of its 80 total field_cases) are real Miri coverage
// again.
#[test]
fn gf2m163_field_arithmetic_matches_bouncy_castle() {
    let json = include_str!("vectors/dstu4145/gf2m163_arith.json");
    let cases = extract_objects(json, "field_cases");
    assert!(
        !cases.is_empty(),
        "no field_cases found - extractor or fixture is broken"
    );

    let mut checked = 0;
    for case in cases {
        let op = extract_all(case, "op")[0];
        let a = field_of(case, "a").expect("every field case has an \"a\" operand");
        let expected = field_of(case, "result").expect("every field case has a \"result\"");

        let actual = match op {
            "add" => a + field_of(case, "b").expect("\"add\" case needs a \"b\" operand"),
            "multiply" => {
                a.multiply(field_of(case, "b").expect("\"multiply\" case needs a \"b\" operand"))
            }
            "square" => a.square(),
            "invert" => a.invert(),
            other => panic!("unknown field op in test vector: {other}"),
        };

        assert_eq!(actual, expected, "GF(2^163) {op} mismatch for a = {case}");
        checked += 1;
    }
    assert_eq!(checked, 80, "expected 20 cases x 4 ops from the generator");
}

#[test]
fn gf2m163_round_trip_be_bytes() {
    let json = include_str!("vectors/dstu4145/gf2m163_arith.json");
    let cases = extract_objects(json, "field_cases");
    for case in cases {
        let a = field_of(case, "a").expect("every field case has an \"a\" operand");
        assert_eq!(FieldElement::from_be_bytes(&a.to_be_bytes()), a);
    }
}

/// `square()`'s bit-interleave implementation (`docs/DECISIONS.md` D-109) against the old
/// `self.multiply(self)` form, kept only as an inline test oracle here - not a second production
/// path.
#[test]
fn gf2m163_square_matches_multiply_at_byte_boundaries() {
    let bits: &[u32] = &[0, 7, 8, 63, 64, 127, 128, 162];
    for &bit in bits {
        let byte_index = 20 - (bit / 8) as usize;
        let mut bytes = [0u8; 21];
        bytes[byte_index] = 1u8 << (bit % 8);
        let a = FieldElement::from_be_bytes(&bytes);
        assert_eq!(a.square(), a.multiply(a), "bit {bit}");
    }
}

proptest! {
    #[test]
    fn gf2m163_square_matches_multiply_for_random_elements(bytes in prop::collection::vec(any::<u8>(), 21)) {
        let mut arr = [0u8; 21];
        arr.copy_from_slice(&bytes);
        // Clear the top 5 bits so the value stays below 2^163 (21 bytes = 168 bits of storage,
        // 163 meaningful) - same invariant every `FieldElement` constructor upholds.
        arr[0] &= 0x07;
        let a = FieldElement::from_be_bytes(&arr);
        prop_assert_eq!(a.square(), a.multiply(a));
    }
}

#[test]
fn gf2m163_one_is_multiplicative_identity() {
    let json = include_str!("vectors/dstu4145/gf2m163_arith.json");
    let cases = extract_objects(json, "field_cases");
    for case in cases {
        let a = field_of(case, "a").expect("every field case has an \"a\" operand");
        assert_eq!(a.multiply(FieldElement::ONE), a);
    }
}

// Re-measured under D-109/T-153's 9-multiply `invert()`: completes in ~230s under Miri
// (`MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=1`, CI's actual invocation) - the exclusion
// this carried under the old 162-multiply form (D-25, T-100) no longer applies, removed.
#[test]
fn gf2m163_invert_is_involution_via_reciprocal() {
    // a * a^-1 == 1 for every nonzero `a` exercised by the generator (all cases use nonzero field
    // elements - see Dstu4145VectorGen.java's randomFieldElement).
    let json = include_str!("vectors/dstu4145/gf2m163_arith.json");
    let cases = extract_objects(json, "field_cases");
    for case in cases {
        let a = field_of(case, "a").expect("every field case has an \"a\" operand");
        assert_eq!(
            a.multiply(a.invert()),
            FieldElement::ONE,
            "a * a^-1 != 1 for {case}"
        );
    }
}
