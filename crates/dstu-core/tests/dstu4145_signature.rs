//! Black-box test for `dstu_core::hazmat::dstu4145::signature::verify` against
//! `tests/vectors/dstu4145/gf2m163.json` - the standard's own Annex B.1 worked example, dual-
//! sourced against Bouncy Castle's `test163()` (`DECISIONS.md` D-14). This is the first
//! genuinely dual-sourced (not single-BC-oracle) check for anything built on the field/point
//! arithmetic landed so far - see `DECISIONS.md` D-25's follow-up entry.

use dstu_core::hazmat::dstu4145::curve163::Point;
use dstu_core::hazmat::dstu4145::gf2m163::FieldElement;
use dstu_core::hazmat::dstu4145::scalar::Scalar;
use dstu_core::hazmat::dstu4145::signature::{sign, verify};
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

fn scalar(s: &str) -> [u8; 21] {
    let bytes = decode_hex(s);
    let mut out = [0u8; 21];
    out[21 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Pulls every value of `"key": "..."` out of the vector JSON, in file order. `gf2m163.json` has
/// both `base_point.x/y` and `public_key_q.x/y` under the bare keys `"x"`/`"y"` - callers must
/// pick the right index (`base_point` comes first in the file).
fn extract_all<'a>(json: &'a str, key: &str) -> Vec<&'a str> {
    let pattern = format!("\"{key}\": \"");
    let mut results = Vec::new();
    let mut rest = json;
    while let Some(start) = rest.find(pattern.as_str()) {
        let after = &rest[start + pattern.len()..];
        let end = after.find('"').expect("well-formed test-vector JSON");
        results.push(&after[..end]);
        rest = &after[end + 1..];
    }
    results
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    extract_all(json, key)[0]
}

/// `gf2m163.json`'s `hash_h_of_t` is used directly, no byte reversal - `hash_to_field` implements
/// the official text's §5.9 algorithm on the hash as given (see that function's doc comment for
/// why an earlier version of this test/function pair needed a reversal that turned out to be
/// compensating for a bug, not a real API requirement).
fn hash(json: &str) -> Vec<u8> {
    decode_hex(extract(json, "hash_h_of_t"))
}

#[test]
fn gf2m163_worked_example_verifies() {
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let qx = field(extract_all(json, "x")[1]); // index 0 is base_point.x
    let qy = field(extract_all(json, "y")[1]); // index 0 is base_point.y
    let q = Point::Affine(qx, qy);
    let g = Point::generator();
    let hash = hash(json);
    let r = scalar(extract(json, "r"));
    let s = scalar(extract(json, "s"));

    assert!(
        verify(&hash, &r, &s, q, g),
        "official DSTU 4145 Annex B.1 worked example failed to verify"
    );
}

#[test]
fn gf2m163_tampered_signature_is_rejected() {
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let qx = field(extract_all(json, "x")[1]); // index 0 is base_point.x
    let qy = field(extract_all(json, "y")[1]); // index 0 is base_point.y
    let q = Point::Affine(qx, qy);
    let g = Point::generator();
    let hash = hash(json);
    let r = scalar(extract(json, "r"));
    let mut s = scalar(extract(json, "s"));

    assert!(verify(&hash, &r, &s, q, g));
    s[20] ^= 1; // flip the low bit of s
    assert!(
        !verify(&hash, &r, &s, q, g),
        "tampered signature must not verify"
    );
}

#[test]
fn gf2m163_worked_example_signs_with_pinned_ephemeral() {
    // Reproduces the official Annex B.1 worked example's (r, s) exactly, using the vector's
    // pinned ephemeral `e` - the seam `gf2m163.json`'s own note calls for (KAT reproduction only,
    // never real signing - see `signature::sign`'s doc comment).
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let g = Point::generator();
    let hash = hash(json);
    let d = Scalar::from_be_bytes(&decode_hex(extract(json, "private_key_d")));
    let e = Scalar::from_be_bytes(&decode_hex(extract(json, "ephemeral_e")));
    let expected_r = scalar(extract(json, "r"));
    let expected_s = scalar(extract(json, "s"));

    let (r, s) = sign(&hash, d, e, g).expect("official worked example must not be degenerate");
    assert_eq!(r, expected_r, "r mismatch");
    assert_eq!(s, expected_s, "s mismatch");
}

#[test]
fn gf2m163_wrong_hash_is_rejected() {
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let qx = field(extract_all(json, "x")[1]); // index 0 is base_point.x
    let qy = field(extract_all(json, "y")[1]); // index 0 is base_point.y
    let q = Point::Affine(qx, qy);
    let g = Point::generator();
    let mut hash = hash(json);
    let r = scalar(extract(json, "r"));
    let s = scalar(extract(json, "s"));

    // Flip the *last* byte - `hash_to_field` only looks at the hash's last 21 bytes (see its doc
    // comment), so a change outside that window (e.g. byte 0 of this 32-byte hash) would be
    // invisible to it and wrongly still verify.
    let last = hash.len() - 1;
    hash[last] ^= 1;
    assert!(
        !verify(&hash, &r, &s, q, g),
        "signature must not verify against a different hash"
    );
}

// The single official worked example only exercises one d/e/hash combination. Property-test the
// full round trip (sign(hash, d, e) verifies against Q = -d*G - see signature.rs's module doc)
// over random 160-bit d/e (comfortably below the curve order n, so Scalar's
// single-conditional-subtract reduction is exercised without needing an explicit mod-n rejection
// step in the test itself) and random 32-byte hashes - see TASKS.md "Testing & hardening" for why
// this project property-tests round trips broadly rather than trusting a single fixed vector
// alone. (This exact property test is what caught the Q = -d*G vs d*G discrepancy above - the
// fixed vector uses a pre-computed Q and never exercised key derivation itself.)
proptest! {
    #[test]
    fn dstu4145_sign_verify_roundtrip(
        d_bytes in prop::collection::vec(any::<u8>(), 20),
        e_bytes in prop::collection::vec(any::<u8>(), 20),
        hash_bytes in prop::collection::vec(any::<u8>(), 32),
    ) {
        let g = Point::generator();
        let mut d_arr = [0u8; 21];
        d_arr[1..].copy_from_slice(&d_bytes);
        let mut e_arr = [0u8; 21];
        e_arr[1..].copy_from_slice(&e_bytes);
        prop_assume!(d_arr != [0u8; 21]);
        prop_assume!(e_arr != [0u8; 21]);

        let d = Scalar::from_be_bytes(&d_arr);
        let e = Scalar::from_be_bytes(&e_arr);

        // Q = -d*G, not d*G - see signature.rs's module doc / DECISIONS.md D-25's follow-up entry.
        let q = match g.scalar_multiply(&d_arr) {
            Point::Affine(x, y) => Point::Affine(x, y).negate(),
            Point::Infinity => return Ok(()), // d = 0 mod n - not reachable with a nonzero 160-bit d
        };

        if let Some((r, s)) = sign(&hash_bytes, d, e, g) {
            prop_assert!(verify(&hash_bytes, &r, &s, q, g));
        }
        // A `None` here is one of the pseudocode's ~2^-163-probability degenerate cases - nothing
        // to assert, just don't fail the property (see `signature::sign`'s doc comment).
    }
}
