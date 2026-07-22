//! Black-box integration test for `dstu_core::hazmat::kupyna` against the official test vectors
//! in `tests/vectors/kupyna/` (extracted from `docs/papers/Kupyna.pdf` Appendix B — see
//! `ORACLES.md`). No JSON/hex crate dependency: the vector files have a fixed, simple shape
//! controlled by this project, so a tiny inline extractor is safer than adding a dependency for
//! two fields.

use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna512};

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

#[test]
fn kupyna_256_official_vectors() {
    let json = include_str!("vectors/kupyna/kupyna-256.json");
    let messages = extract_all(json, "message_hex");
    let hashes = extract_all(json, "hash_hex");
    assert_eq!(
        messages.len(),
        hashes.len(),
        "message/hash count mismatch in vector file"
    );
    assert!(
        !messages.is_empty(),
        "no cases found - extractor or fixture is broken"
    );

    for (message_hex, expected_hex) in messages.iter().zip(hashes.iter()) {
        let message = decode_hex(message_hex);
        let expected = decode_hex(expected_hex);
        let actual = Kupyna256::digest(&message);
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "Kupyna-256 mismatch for message_hex={message_hex}"
        );
    }
}

#[test]
fn kupyna_512_official_vectors() {
    let json = include_str!("vectors/kupyna/kupyna-512.json");
    let messages = extract_all(json, "message_hex");
    let hashes = extract_all(json, "hash_hex");
    assert_eq!(
        messages.len(),
        hashes.len(),
        "message/hash count mismatch in vector file"
    );
    assert!(
        !messages.is_empty(),
        "no cases found - extractor or fixture is broken"
    );

    for (message_hex, expected_hex) in messages.iter().zip(hashes.iter()) {
        let message = decode_hex(message_hex);
        let expected = decode_hex(expected_hex);
        let actual = Kupyna512::digest(&message);
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "Kupyna-512 mismatch for message_hex={message_hex}"
        );
    }
}
