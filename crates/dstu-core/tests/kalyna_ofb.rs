//! Black-box integration test for `dstu_core::hazmat::kalyna_ofb` against the cross-oracle
//! vectors in `tests/vectors/kalyna-ofb/` (`TASKS.md` T-89, `DECISIONS.md` D-53) - programmatically
//! extracted from `oracles/uapki/library/uapkic/src/dstu7624.c`'s `dstu7624_ofb_self_test`, not
//! hand-transcribed. Same hand-rolled extractor convention as `tests/kalyna_ccm.rs`.

use dstu_core::hazmat::kalyna_ofb::{
    Kalyna128_128Ofb, Kalyna128_256Ofb, Kalyna256_256Ofb, Kalyna256_512Ofb, Kalyna512_512Ofb,
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
            fn official_vectors_apply_and_are_self_inverse() {
                let json = include_str!($file);
                for case in cases(json) {
                    let mut key = [0u8; $key_len];
                    key.copy_from_slice(&case.key);
                    let mut iv = [0u8; $block_len];
                    iv.copy_from_slice(&case.iv);

                    let mut buf = case.plaintext.clone();
                    <$variant>::new(&key, &iv).apply_in_place(&mut buf);
                    assert_eq!(buf, case.ciphertext, "encrypt mismatch");

                    // OFB is self-inverse (see the module doc) - applying it again with a fresh
                    // instance over the ciphertext must recover the plaintext.
                    <$variant>::new(&key, &iv).apply_in_place(&mut buf);
                    assert_eq!(buf, case.plaintext, "decrypt mismatch");
                }
            }

            proptest! {
                /// Splitting one logical message across several `apply_in_place` calls at
                /// arbitrary, non-block-aligned boundaries must match one call over the whole
                /// concatenated buffer - the property that makes this a genuine streaming API,
                /// same discipline as `hazmat::strumok`'s chunk-invariance test (T-24).
                #[test]
                fn chunk_invariance(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    iv in proptest::collection::vec(any::<u8>(), $block_len),
                    data in proptest::collection::vec(any::<u8>(), 0..200),
                    chunk_lens in proptest::collection::vec(0usize..17, 0..20),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut iv_arr = [0u8; $block_len];
                    iv_arr.copy_from_slice(&iv);

                    let mut whole = data.clone();
                    <$variant>::new(&key_arr, &iv_arr).apply_in_place(&mut whole);

                    let mut chunked = data.clone();
                    let mut cipher = <$variant>::new(&key_arr, &iv_arr);
                    let mut offset = 0usize;
                    for len in &chunk_lens {
                        let end = (offset + len).min(chunked.len());
                        cipher.apply_in_place(&mut chunked[offset..end]);
                        offset = end;
                        if offset >= chunked.len() {
                            break;
                        }
                    }
                    if offset < chunked.len() {
                        cipher.apply_in_place(&mut chunked[offset..]);
                    }

                    prop_assert_eq!(whole, chunked);
                }
            }
        }
    };
}

variant_test!(
    k128_128,
    "vectors/kalyna-ofb/128-128.json",
    Kalyna128_128Ofb,
    16,
    16
);
variant_test!(
    k128_256,
    "vectors/kalyna-ofb/128-256.json",
    Kalyna128_256Ofb,
    32,
    16
);
variant_test!(
    k256_256,
    "vectors/kalyna-ofb/256-256.json",
    Kalyna256_256Ofb,
    32,
    32
);
variant_test!(
    k256_512,
    "vectors/kalyna-ofb/256-512.json",
    Kalyna256_512Ofb,
    64,
    32
);
variant_test!(
    k512_512,
    "vectors/kalyna-ofb/512-512.json",
    Kalyna512_512Ofb,
    64,
    64
);
