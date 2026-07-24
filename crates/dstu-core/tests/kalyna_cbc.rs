//! Black-box integration test for `dstu_core::hazmat::kalyna_cbc` against the cross-oracle
//! vectors in `tests/vectors/kalyna-cbc/` (`TASKS.md` T-90, `DECISIONS.md` D-53) - programmatically
//! extracted from `oracles/uapki/library/uapkic/src/dstu7624.c`'s `dstu7624_cbc_self_test`, not
//! hand-transcribed. Same hand-rolled extractor convention as `tests/kalyna_ofb.rs`.
//!
//! Excludes the self-test's 10th declared vector - its own harness loop only checks `i<9`, so that
//! case is dead code, never actually verified upstream (see `DECISIONS.md` D-53's carried-forward
//! verification risk).

use dstu_core::hazmat::kalyna_cbc::{
    InvalidLength, Kalyna128_128Cbc, Kalyna128_256Cbc, Kalyna256_256Cbc, Kalyna256_512Cbc,
    Kalyna512_512Cbc,
};
use proptest::prelude::*;

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
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

struct Case {
    key: Vec<u8>,
    iv: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn cases(json: &'static str) -> Vec<Case> {
    let keys = extract_all(json, "key_hex");
    let ivs = extract_all(json, "iv_hex");
    let plaintexts = extract_all(json, "plaintext_hex");
    let ciphertexts = extract_all(json, "ciphertext_hex");
    assert!(!keys.is_empty(), "no cases found - fixture is broken");
    keys.into_iter()
        .zip(ivs)
        .zip(plaintexts)
        .zip(ciphertexts)
        .map(|(((key, iv), plaintext), ciphertext)| Case {
            key: decode_hex(key),
            iv: decode_hex(iv),
            plaintext: decode_hex(plaintext),
            ciphertext: decode_hex(ciphertext),
        })
        .collect()
}

macro_rules! variant_test {
    ($mod_name:ident, $file:literal, $variant:ty, $key_len:literal, $block_len:literal) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn official_vectors_encrypt_and_decrypt() {
                let json = include_str!($file);
                for case in cases(json) {
                    let mut key = [0u8; $key_len];
                    key.copy_from_slice(&case.key);
                    let mut iv = [0u8; $block_len];
                    iv.copy_from_slice(&case.iv);

                    let mut buf = case.plaintext.clone();
                    <$variant>::new(&key, &iv)
                        .encrypt_in_place(&mut buf)
                        .expect("block-aligned vector");
                    assert_eq!(buf, case.ciphertext, "encrypt mismatch");

                    <$variant>::new(&key, &iv)
                        .decrypt_in_place(&mut buf)
                        .expect("block-aligned vector");
                    assert_eq!(buf, case.plaintext, "decrypt mismatch");
                }
            }

            #[test]
            fn rejects_length_not_a_multiple_of_block_size() {
                let key = [0u8; $key_len];
                let iv = [0u8; $block_len];
                let mut buf = vec![0u8; $block_len + 1];
                assert_eq!(
                    <$variant>::new(&key, &iv).encrypt_in_place(&mut buf),
                    Err(InvalidLength)
                );
                assert_eq!(
                    <$variant>::new(&key, &iv).decrypt_in_place(&mut buf),
                    Err(InvalidLength)
                );
            }

            proptest! {
                /// The chaining register carries over between calls (see the module doc) -
                /// encrypting N block-aligned chunks across N separate calls under one instance
                /// must match one call over the whole concatenated buffer.
                #[test]
                fn multi_call_chaining_matches_one_call(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    iv in proptest::collection::vec(any::<u8>(), $block_len),
                    block_counts in proptest::collection::vec(1usize..4, 1..5),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut iv_arr = [0u8; $block_len];
                    iv_arr.copy_from_slice(&iv);

                    let total_blocks: usize = block_counts.iter().sum();
                    let plaintext: Vec<u8> = (0..total_blocks * $block_len)
                        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
                        .collect();

                    let mut whole = plaintext.clone();
                    <$variant>::new(&key_arr, &iv_arr)
                        .encrypt_in_place(&mut whole)
                        .expect("block-aligned");

                    let mut chunked = plaintext.clone();
                    let mut cipher = <$variant>::new(&key_arr, &iv_arr);
                    let mut offset = 0usize;
                    for count in &block_counts {
                        let len = count * $block_len;
                        cipher
                            .encrypt_in_place(&mut chunked[offset..offset + len])
                            .expect("block-aligned");
                        offset += len;
                    }

                    prop_assert_eq!(whole, chunked);
                }
            }
        }
    };
}

variant_test!(
    k128_128,
    "vectors/kalyna-cbc/128-128.json",
    Kalyna128_128Cbc,
    16,
    16
);
variant_test!(
    k128_256,
    "vectors/kalyna-cbc/128-256.json",
    Kalyna128_256Cbc,
    32,
    16
);
variant_test!(
    k256_256,
    "vectors/kalyna-cbc/256-256.json",
    Kalyna256_256Cbc,
    32,
    32
);
variant_test!(
    k256_512,
    "vectors/kalyna-cbc/256-512.json",
    Kalyna256_512Cbc,
    64,
    32
);
variant_test!(
    k512_512,
    "vectors/kalyna-cbc/512-512.json",
    Kalyna512_512Cbc,
    64,
    64
);
