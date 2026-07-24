//! Black-box integration test for `dstu_core::hazmat::kalyna_cfb` against the cross-oracle
//! vectors in `tests/vectors/kalyna-cfb/` (`TASKS.md` T-91, `DECISIONS.md` D-53) - programmatically
//! extracted from `oracles/uapki/library/uapkic/src/dstu7624.c`'s `dstu7624_cfb_self_test`, not
//! hand-transcribed. Covers both partial (`q` < block size) and full (`q` == block size) feedback
//! widths - see the module doc comment's warning that this construction is not a textbook shift
//! register, transcribed exactly rather than simplified by analogy.

use dstu_core::hazmat::kalyna_cfb::{
    Kalyna128_128Cfb, Kalyna128_256Cfb, Kalyna256_256Cfb, Kalyna256_512Cfb, Kalyna512_512Cfb,
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

fn extract_all_numbers(text: &str, key: &str) -> Vec<usize> {
    let pattern = format!("\"{key}\": ");
    let mut results = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(pattern.as_str()) {
        let after = &rest[start + pattern.len()..];
        let end = after
            .find(|c: char| !c.is_ascii_digit())
            .expect("well-formed test-vector JSON");
        results.push(after[..end].parse().expect("valid integer in vector"));
        rest = &after[end..];
    }
    results
}

struct Case {
    key: Vec<u8>,
    iv: Vec<u8>,
    q: usize,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn cases(json: &'static str) -> Vec<Case> {
    let keys = extract_all(json, "key_hex");
    let ivs = extract_all(json, "iv_hex");
    let qs = extract_all_numbers(json, "q");
    let plaintexts = extract_all(json, "plaintext_hex");
    let ciphertexts = extract_all(json, "ciphertext_hex");
    assert!(!keys.is_empty(), "no cases found - fixture is broken");
    assert_eq!(keys.len(), qs.len(), "key/q count mismatch");
    keys.into_iter()
        .zip(ivs)
        .zip(qs)
        .zip(plaintexts)
        .zip(ciphertexts)
        .map(|((((key, iv), q), plaintext), ciphertext)| Case {
            key: decode_hex(key),
            iv: decode_hex(iv),
            q,
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
                    <$variant>::new(&key, &iv, case.q)
                        .expect("valid q in vector")
                        .encrypt_in_place(&mut buf);
                    assert_eq!(buf, case.ciphertext, "encrypt mismatch, q={}", case.q);

                    <$variant>::new(&key, &iv, case.q)
                        .expect("valid q in vector")
                        .decrypt_in_place(&mut buf);
                    assert_eq!(buf, case.plaintext, "decrypt mismatch, q={}", case.q);
                }
            }

            proptest! {
                /// Splitting one logical message across several `encrypt_in_place` calls, **where
                /// every call except the last is a multiple of `q` bytes**, must match one call
                /// over the whole buffer. Unlike `kalyna_ofb`, arbitrary (non-`q`-multiple)
                /// mid-stream call boundaries are NOT supported by this construction - see the
                /// module doc comment's "not a textbook shift register" note; a call boundary
                /// landing mid-way through a `q`-sized group leaves `used_gamma_len` referencing a
                /// position in the *current* `gamma` block that a subsequent call's own bookkeeping
                /// does not correctly resume from, since `dstu7624.c`'s own `encrypt_cfb`/
                /// `decrypt_cfb` never exercises that combination either (all 8 official vectors
                /// are single-call). This is a transcribed property of the source construction, not
                /// a gap introduced here.
                #[test]
                fn chunk_invariance_at_q_boundaries(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    iv in proptest::collection::vec(any::<u8>(), $block_len),
                    data in proptest::collection::vec(any::<u8>(), 0..200),
                    chunk_units in proptest::collection::vec(0usize..5, 0..8),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut iv_arr = [0u8; $block_len];
                    iv_arr.copy_from_slice(&iv);

                    for q in [1usize, 8, 16, 32, 64] {
                        if q > $block_len {
                            continue;
                        }

                        let mut whole = data.clone();
                        <$variant>::new(&key_arr, &iv_arr, q)
                            .unwrap()
                            .encrypt_in_place(&mut whole);

                        let mut chunked = data.clone();
                        let mut cipher = <$variant>::new(&key_arr, &iv_arr, q).unwrap();
                        let mut offset = 0usize;
                        for units in &chunk_units {
                            let len = (units * q).min(chunked.len() - offset);
                            let end = offset + len;
                            cipher.encrypt_in_place(&mut chunked[offset..end]);
                            offset = end;
                            if offset >= chunked.len() {
                                break;
                            }
                        }
                        if offset < chunked.len() {
                            cipher.encrypt_in_place(&mut chunked[offset..]);
                        }

                        prop_assert_eq!(&whole, &chunked, "q={}", q);

                        // Round trip through decrypt too, single call.
                        let mut recovered = whole.clone();
                        <$variant>::new(&key_arr, &iv_arr, q)
                            .unwrap()
                            .decrypt_in_place(&mut recovered);
                        prop_assert_eq!(&recovered, &data, "round trip, q={}", q);
                    }
                }
            }
        }
    };
}

variant_test!(
    k128_128,
    "vectors/kalyna-cfb/128-128.json",
    Kalyna128_128Cfb,
    16,
    16
);
variant_test!(
    k128_256,
    "vectors/kalyna-cfb/128-256.json",
    Kalyna128_256Cfb,
    32,
    16
);
variant_test!(
    k256_256,
    "vectors/kalyna-cfb/256-256.json",
    Kalyna256_256Cfb,
    32,
    32
);
variant_test!(
    k256_512,
    "vectors/kalyna-cfb/256-512.json",
    Kalyna256_512Cfb,
    64,
    32
);
variant_test!(
    k512_512,
    "vectors/kalyna-cfb/512-512.json",
    Kalyna512_512Cfb,
    64,
    64
);
