//! Black-box integration test for `dstu_core::hazmat::strumok` against the UAPKI-attributed
//! keystream vectors in `tests/vectors/strumok/` — **not** the official DSTU 8845:2019 text
//! itself (no copy of that has been located; see `ORACLES.md` and `DECISIONS.md` D-15). Same
//! hand-rolled extractor as `tests/kalyna.rs`/`tests/kupyna.rs` — no JSON dependency for a fixed,
//! project-controlled vector shape.

use dstu_core::hazmat::strumok::{Strumok256, Strumok512};

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

macro_rules! keystream_test {
    ($test_name:ident, $file:literal, $variant:ty, $key_len:literal) => {
        #[test]
        fn $test_name() {
            let json = include_str!($file);
            let keys = extract_all(json, "key_hex");
            let ivs = extract_all(json, "iv_hex");
            let keystreams = extract_all(json, "keystream_hex");
            assert_eq!(
                keys.len(),
                ivs.len(),
                "key/iv count mismatch in vector file"
            );
            assert_eq!(
                keys.len(),
                keystreams.len(),
                "key/keystream count mismatch in vector file"
            );
            assert!(
                !keys.is_empty(),
                "no cases found - extractor or fixture is broken"
            );

            for ((key_hex, iv_hex), keystream_hex) in
                keys.iter().zip(ivs.iter()).zip(keystreams.iter())
            {
                let key_bytes = decode_hex(key_hex);
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&key_bytes);

                let iv_bytes = decode_hex(iv_hex);
                let mut iv = [0u8; 32];
                iv.copy_from_slice(&iv_bytes);

                let expected = decode_hex(keystream_hex);
                let mut actual = vec![0u8; expected.len()];
                let mut cipher = <$variant>::new(&key, &iv);
                cipher.apply_keystream(&mut actual);

                assert_eq!(
                    actual,
                    expected,
                    "{}: keystream mismatch for key_hex={key_hex}",
                    stringify!($variant)
                );
            }
        }
    };
}

keystream_test!(
    strumok_256_uapki_attributed_vectors,
    "vectors/strumok/keystream-256.json",
    Strumok256,
    32
);
keystream_test!(
    strumok_512_uapki_attributed_vectors,
    "vectors/strumok/keystream-512.json",
    Strumok512,
    64
);
