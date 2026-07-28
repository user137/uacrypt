//! Black-box integration test for `dstu_core::hazmat::kalyna_ctr` against the cross-oracle
//! vectors in `tests/vectors/kalyna-ctr/` (`docs/TASKS.md` T-92, `docs/DECISIONS.md` D-53) - uapki plus a
//! genuinely independent second Bouncy Castle vector (`KCTRBlockCipher`), for the one variant
//! either oracle covers (Kalyna128_128). Other variants rely on this mode sharing its keystream
//! logic with the already dual-oracle-verified `hazmat::kalyna_ccm` (both call the same
//! `dstu7624.c` `encrypt_ctr` internally, per the module doc) plus the chunk-invariance `proptest`
//! below across all five.

use dstu_core::hazmat::kalyna_ctr::{
    Kalyna128_128Ctr, Kalyna128_256Ctr, Kalyna256_256Ctr, Kalyna256_512Ctr, Kalyna512_512Ctr,
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
    ($mod_name:ident, $variant:ty, $key_len:literal, $block_len:literal) => {
        mod $mod_name {
            use super::*;

            proptest! {
                /// Splitting one logical message across several `apply_in_place` calls at
                /// arbitrary boundaries must match one call over the whole buffer - same
                /// discipline as `kalyna_ofb`'s chunk-invariance test. Unlike `kalyna_cfb`, CTR's
                /// counter-increment bookkeeping has no `q`-alignment restriction, so boundaries
                /// here really are arbitrary.
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

                    prop_assert_eq!(&whole, &chunked);

                    // Self-inverse: applying again with a fresh instance recovers the original.
                    let mut recovered = whole.clone();
                    <$variant>::new(&key_arr, &iv_arr).apply_in_place(&mut recovered);
                    prop_assert_eq!(&recovered, &data);
                }
            }
        }
    };
}

variant_test!(k128_128, Kalyna128_128Ctr, 16, 16);
variant_test!(k128_256, Kalyna128_256Ctr, 32, 16);
variant_test!(k256_256, Kalyna256_256Ctr, 32, 32);
variant_test!(k256_512, Kalyna256_512Ctr, 64, 32);
variant_test!(k512_512, Kalyna512_512Ctr, 64, 64);

#[test]
fn official_vectors_apply_and_are_self_inverse() {
    let json = include_str!("vectors/kalyna-ctr/128-128.json");
    for case in cases(json) {
        let mut key = [0u8; 16];
        key.copy_from_slice(&case.key);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&case.iv);

        let mut buf = case.plaintext.clone();
        Kalyna128_128Ctr::new(&key, &iv).apply_in_place(&mut buf);
        assert_eq!(buf, case.ciphertext, "encrypt mismatch");

        Kalyna128_128Ctr::new(&key, &iv).apply_in_place(&mut buf);
        assert_eq!(buf, case.plaintext, "decrypt mismatch");
    }
}
