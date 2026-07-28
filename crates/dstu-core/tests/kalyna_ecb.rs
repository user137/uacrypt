//! Black-box integration test for `dstu_core::hazmat::kalyna_ecb` (`docs/TASKS.md` T-88,
//! `docs/DECISIONS.md` D-53).
//!
//! **No new vector file** - `dstu7624.c`'s own `dstu7624_ecb_self_test` sets each case's block
//! size to the exact length of that case's single data blob (`dstu7624_init_ecb(ctx, key,
//! ba_get_len(data_ba))`), so every one of its 10 cases is single-block. Confirmed byte-for-byte:
//! that self-test's 10 vectors are the *same* official designer vectors (`docs/papers/Kalyna.pdf`
//! Appendix B) already in `tests/vectors/kalyna/*.json` and used by `tests/kalyna.rs` - ECB over
//! exactly one block reduces to the already-oracle-verified raw block cipher (D-13). Reusing those
//! files here (not duplicating them into a new `kalyna-ecb/` directory) verifies ECB's single-block
//! case is wired correctly. The genuinely new property ECB adds - that multi-block input is
//! encrypted **independently per block**, not chained - has no vector to check (uapki's own
//! self-test never exercises it either) and is instead verified directly against the raw
//! (already-verified) block primitive via `proptest` below.

use dstu_core::hazmat::kalyna::{
    Kalyna128_128ExpandedKey, Kalyna128_256ExpandedKey, Kalyna256_256ExpandedKey,
    Kalyna256_512ExpandedKey, Kalyna512_512ExpandedKey,
};
use dstu_core::hazmat::kalyna_ecb::{
    InvalidLength, Kalyna128_128Ecb, Kalyna128_256Ecb, Kalyna256_256Ecb, Kalyna256_512Ecb,
    Kalyna512_512Ecb,
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
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn cases(json: &'static str) -> Vec<Case> {
    let keys = extract_all(json, "key_hex");
    let plaintexts = extract_all(json, "plaintext_hex");
    let ciphertexts = extract_all(json, "ciphertext_hex");
    assert!(!keys.is_empty(), "no cases found - fixture is broken");
    keys.into_iter()
        .zip(plaintexts)
        .zip(ciphertexts)
        .map(|((key, plaintext), ciphertext)| Case {
            key: decode_hex(key),
            plaintext: decode_hex(plaintext),
            ciphertext: decode_hex(ciphertext),
        })
        .collect()
}

macro_rules! variant_test {
    ($mod_name:ident, $file:literal, $ecb:ty, $expanded:ty, $key_len:literal, $block_len:literal) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn single_block_matches_raw_block_cipher_vectors() {
                let json = include_str!($file);
                for case in cases(json) {
                    let mut key = [0u8; $key_len];
                    key.copy_from_slice(&case.key);
                    let cipher = <$ecb>::new(&key);

                    let mut buf = case.plaintext.clone();
                    cipher.encrypt_in_place(&mut buf).expect("one block");
                    assert_eq!(buf, case.ciphertext, "encrypt mismatch");

                    cipher.decrypt_in_place(&mut buf).expect("one block");
                    assert_eq!(buf, case.plaintext, "decrypt mismatch");
                }
            }

            #[test]
            fn rejects_length_not_a_multiple_of_block_size() {
                let key = [0u8; $key_len];
                let cipher = <$ecb>::new(&key);
                let mut buf = vec![0u8; $block_len + 1];
                assert_eq!(cipher.encrypt_in_place(&mut buf), Err(InvalidLength));
                assert_eq!(cipher.decrypt_in_place(&mut buf), Err(InvalidLength));
            }

            proptest! {
                /// The property ECB actually adds over the raw block cipher: every block is
                /// encrypted independently, not chained - so ECB over N blocks must equal N
                /// separate calls to the already-verified block primitive.
                #[test]
                fn multi_block_matches_independent_raw_block_calls(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    blocks in proptest::collection::vec(
                        proptest::collection::vec(any::<u8>(), $block_len), 1..=4
                    ),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let cipher = <$ecb>::new(&key_arr);
                    let expanded = <$expanded>::new(&key_arr);

                    let mut buf: Vec<u8> = blocks.iter().flatten().copied().collect();
                    cipher.encrypt_in_place(&mut buf).expect("block-multiple length");

                    let mut expected = Vec::new();
                    for block in &blocks {
                        let mut block_arr = [0u8; $block_len];
                        block_arr.copy_from_slice(block);
                        expected.extend_from_slice(&expanded.encrypt_block(&block_arr));
                    }
                    prop_assert_eq!(buf, expected);
                }
            }
        }
    };
}

variant_test!(
    k128_128,
    "vectors/kalyna/128-128.json",
    Kalyna128_128Ecb,
    Kalyna128_128ExpandedKey,
    16,
    16
);
variant_test!(
    k128_256,
    "vectors/kalyna/128-256.json",
    Kalyna128_256Ecb,
    Kalyna128_256ExpandedKey,
    32,
    16
);
variant_test!(
    k256_256,
    "vectors/kalyna/256-256.json",
    Kalyna256_256Ecb,
    Kalyna256_256ExpandedKey,
    32,
    32
);
variant_test!(
    k256_512,
    "vectors/kalyna/256-512.json",
    Kalyna256_512Ecb,
    Kalyna256_512ExpandedKey,
    64,
    32
);
variant_test!(
    k512_512,
    "vectors/kalyna/512-512.json",
    Kalyna512_512Ecb,
    Kalyna512_512ExpandedKey,
    64,
    64
);
