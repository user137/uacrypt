//! Black-box integration test for `dstu_core::hazmat::kalyna` against the official test vectors
//! in `tests/vectors/kalyna/` (extracted from `docs/papers/Kalyna.pdf` Appendix B - see
//! `ORACLES.md`). Same hand-rolled extractor as `tests/kupyna.rs` - no JSON dependency for a
//! fixed, project-controlled vector shape.

use dstu_core::hazmat::kalyna::{
    Kalyna128_128, Kalyna128_128ExpandedKey, Kalyna128_256, Kalyna128_256ExpandedKey,
    Kalyna256_256, Kalyna256_256ExpandedKey, Kalyna256_512, Kalyna256_512ExpandedKey,
    Kalyna512_512, Kalyna512_512ExpandedKey,
};
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

struct Case {
    name: &'static str,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn cases(json: &'static str) -> Vec<Case> {
    let names = extract_all(json, "name");
    let keys = extract_all(json, "key_hex");
    let plaintexts = extract_all(json, "plaintext_hex");
    let ciphertexts = extract_all(json, "ciphertext_hex");
    assert_eq!(
        names.len(),
        keys.len(),
        "name/key count mismatch in vector file"
    );
    assert_eq!(
        names.len(),
        plaintexts.len(),
        "name/plaintext count mismatch"
    );
    assert_eq!(
        names.len(),
        ciphertexts.len(),
        "name/ciphertext count mismatch"
    );
    assert!(
        !names.is_empty(),
        "no cases found - extractor or fixture is broken"
    );

    names
        .into_iter()
        .zip(keys)
        .zip(plaintexts)
        .zip(ciphertexts)
        .map(|(((name, key), plaintext), ciphertext)| Case {
            name: match name {
                "encryption" => "encryption",
                "decryption" => "decryption",
                other => panic!("unknown case name in vector file: {other}"),
            },
            key: decode_hex(key),
            plaintext: decode_hex(plaintext),
            ciphertext: decode_hex(ciphertext),
        })
        .collect()
}

macro_rules! variant_test {
    ($test_name:ident, $file:literal, $variant:ty, $key_len:literal, $block_len:literal) => {
        #[test]
        fn $test_name() {
            let json = include_str!($file);
            for case in cases(json) {
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&case.key);
                match case.name {
                    "encryption" => {
                        let mut plaintext = [0u8; $block_len];
                        plaintext.copy_from_slice(&case.plaintext);
                        let actual = <$variant>::encrypt(&key, &plaintext);
                        assert_eq!(
                            actual.as_slice(),
                            case.ciphertext.as_slice(),
                            "{}: encryption mismatch",
                            stringify!($variant)
                        );
                    }
                    "decryption" => {
                        let mut ciphertext = [0u8; $block_len];
                        ciphertext.copy_from_slice(&case.ciphertext);
                        let actual = <$variant>::decrypt(&key, &ciphertext);
                        assert_eq!(
                            actual.as_slice(),
                            case.plaintext.as_slice(),
                            "{}: decryption mismatch",
                            stringify!($variant)
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }
    };
}

variant_test!(
    kalyna_128_128_official_vectors,
    "vectors/kalyna/128-128.json",
    Kalyna128_128,
    16,
    16
);
variant_test!(
    kalyna_128_256_official_vectors,
    "vectors/kalyna/128-256.json",
    Kalyna128_256,
    32,
    16
);
variant_test!(
    kalyna_256_256_official_vectors,
    "vectors/kalyna/256-256.json",
    Kalyna256_256,
    32,
    32
);
variant_test!(
    kalyna_256_512_official_vectors,
    "vectors/kalyna/256-512.json",
    Kalyna256_512,
    64,
    32
);
variant_test!(
    kalyna_512_512_official_vectors,
    "vectors/kalyna/512-512.json",
    Kalyna512_512,
    64,
    64
);

/// Two fixed key/block pairs per variant (the official vectors above) is thin coverage for
/// `decrypt(encrypt(key, block), key) == block`. Property-testing this over random keys/blocks
/// costs almost nothing extra and exercises far more of the state space than the fixed vectors
/// alone - see `TASKS.md` "Testing & hardening".
macro_rules! roundtrip_proptest {
    ($test_name:ident, $variant:ty, $key_len:literal, $block_len:literal) => {
        proptest! {
            #[test]
            fn $test_name(
                key_bytes in prop::collection::vec(any::<u8>(), $key_len),
                block_bytes in prop::collection::vec(any::<u8>(), $block_len),
            ) {
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&key_bytes);
                let mut block = [0u8; $block_len];
                block.copy_from_slice(&block_bytes);

                let ciphertext = <$variant>::encrypt(&key, &block);
                let plaintext = <$variant>::decrypt(&key, &ciphertext);
                prop_assert_eq!(plaintext, block);
            }
        }
    };
}

roundtrip_proptest!(kalyna_128_128_roundtrip, Kalyna128_128, 16, 16);
roundtrip_proptest!(kalyna_128_256_roundtrip, Kalyna128_256, 32, 16);
roundtrip_proptest!(kalyna_256_256_roundtrip, Kalyna256_256, 32, 32);
roundtrip_proptest!(kalyna_256_512_roundtrip, Kalyna256_512, 64, 32);
roundtrip_proptest!(kalyna_512_512_roundtrip, Kalyna512_512, 64, 64);

/// `ExpandedKey` (D-28 stage 3) must be interchangeable with the raw `encrypt`/`decrypt`
/// functions for every input, not just "usually agree" - property-tested over random keys/blocks,
/// same rationale as `roundtrip_proptest!` above.
macro_rules! expanded_key_matches_raw_proptest {
    ($test_name:ident, $variant:ty, $expanded:ty, $key_len:literal, $block_len:literal) => {
        proptest! {
            #[test]
            fn $test_name(
                key_bytes in prop::collection::vec(any::<u8>(), $key_len),
                block_bytes in prop::collection::vec(any::<u8>(), $block_len),
            ) {
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&key_bytes);
                let mut block = [0u8; $block_len];
                block.copy_from_slice(&block_bytes);

                let expanded = <$expanded>::new(&key);

                let raw_ciphertext = <$variant>::encrypt(&key, &block);
                let expanded_ciphertext = expanded.encrypt_block(&block);
                prop_assert_eq!(raw_ciphertext, expanded_ciphertext);

                let raw_plaintext = <$variant>::decrypt(&key, &raw_ciphertext);
                let expanded_plaintext = expanded.decrypt_block(&raw_ciphertext);
                prop_assert_eq!(raw_plaintext, block);
                prop_assert_eq!(expanded_plaintext, block);
            }
        }
    };
}

expanded_key_matches_raw_proptest!(
    kalyna_128_128_expanded_key_matches_raw,
    Kalyna128_128,
    Kalyna128_128ExpandedKey,
    16,
    16
);
expanded_key_matches_raw_proptest!(
    kalyna_128_256_expanded_key_matches_raw,
    Kalyna128_256,
    Kalyna128_256ExpandedKey,
    32,
    16
);
expanded_key_matches_raw_proptest!(
    kalyna_256_256_expanded_key_matches_raw,
    Kalyna256_256,
    Kalyna256_256ExpandedKey,
    32,
    32
);
expanded_key_matches_raw_proptest!(
    kalyna_256_512_expanded_key_matches_raw,
    Kalyna256_512,
    Kalyna256_512ExpandedKey,
    64,
    32
);
expanded_key_matches_raw_proptest!(
    kalyna_512_512_expanded_key_matches_raw,
    Kalyna512_512,
    Kalyna512_512ExpandedKey,
    64,
    64
);

/// Encrypting/decrypting many blocks from one `ExpandedKey` must give the same answer every time
/// (the schedule is reused, not recomputed) - not covered by the single-call proptest above.
macro_rules! expanded_key_reused_across_blocks_proptest {
    ($test_name:ident, $expanded:ty, $key_len:literal, $block_len:literal) => {
        proptest! {
            #[test]
            fn $test_name(
                key_bytes in prop::collection::vec(any::<u8>(), $key_len),
                block_a in prop::collection::vec(any::<u8>(), $block_len),
                block_b in prop::collection::vec(any::<u8>(), $block_len),
            ) {
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&key_bytes);
                let mut a = [0u8; $block_len];
                a.copy_from_slice(&block_a);
                let mut b = [0u8; $block_len];
                b.copy_from_slice(&block_b);

                let expanded = <$expanded>::new(&key);
                let ciphertext_a = expanded.encrypt_block(&a);
                let ciphertext_b = expanded.encrypt_block(&b);
                prop_assert_eq!(expanded.decrypt_block(&ciphertext_a), a);
                prop_assert_eq!(expanded.decrypt_block(&ciphertext_b), b);
            }
        }
    };
}

expanded_key_reused_across_blocks_proptest!(
    kalyna_128_128_expanded_key_reused,
    Kalyna128_128ExpandedKey,
    16,
    16
);
expanded_key_reused_across_blocks_proptest!(
    kalyna_512_512_expanded_key_reused,
    Kalyna512_512ExpandedKey,
    64,
    64
);
