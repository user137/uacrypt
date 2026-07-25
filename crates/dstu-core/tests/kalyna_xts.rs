//! Black-box integration test for `dstu_core::hazmat::kalyna_xts` against the cross-oracle vectors
//! in `tests/vectors/kalyna-xts/` (`TASKS.md` T-96, `DECISIONS.md` D-58) - one "aligned" (simple
//! loop) and one "stealing" (ciphertext-stealing, non-block-aligned) KAT per Kalyna variant, full
//! 10-vector coverage of DSTU 7624's last remaining mode. The aligned case is dual-oracle
//! (uapki + Bouncy Castle `XTSModeTests`, vector-only cross-check - construction source not
//! vendored); the stealing case is uapki-only for every variant, see D-58.

use dstu_core::hazmat::kalyna_xts::{
    Kalyna128_128Xts, Kalyna128_256Xts, Kalyna256_256Xts, Kalyna256_512Xts, Kalyna512_512Xts,
    XtsError,
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
    let n = keys.len();
    assert_eq!(ivs.len(), n);
    assert_eq!(plaintexts.len(), n);
    assert_eq!(ciphertexts.len(), n);

    (0..n)
        .map(|i| Case {
            key: decode_hex(keys[i]),
            iv: decode_hex(ivs[i]),
            plaintext: decode_hex(plaintexts[i]),
            ciphertext: decode_hex(ciphertexts[i]),
        })
        .collect()
}

macro_rules! official_vector_test {
    ($test_name:ident, $variant:ty, $key_len:literal, $block_len:literal, $fixture:literal) => {
        #[test]
        fn $test_name() {
            for case in cases(include_str!($fixture)) {
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&case.key);
                let mut iv = [0u8; $block_len];
                iv.copy_from_slice(&case.iv);
                let cipher = <$variant>::new(&key);

                let mut buf = case.plaintext.clone();
                cipher.encrypt_in_place(&iv, &mut buf).expect("valid input");
                assert_eq!(buf, case.ciphertext, "ciphertext mismatch");

                let mut buf = case.ciphertext.clone();
                cipher.decrypt_in_place(&iv, &mut buf).expect("valid input");
                assert_eq!(buf, case.plaintext, "plaintext mismatch");
            }
        }
    };
}

official_vector_test!(
    kalyna128_128_official_vectors,
    Kalyna128_128Xts,
    16,
    16,
    "vectors/kalyna-xts/128-128.json"
);
official_vector_test!(
    kalyna128_256_official_vectors,
    Kalyna128_256Xts,
    32,
    16,
    "vectors/kalyna-xts/128-256.json"
);
official_vector_test!(
    kalyna256_256_official_vectors,
    Kalyna256_256Xts,
    32,
    32,
    "vectors/kalyna-xts/256-256.json"
);
official_vector_test!(
    kalyna256_512_official_vectors,
    Kalyna256_512Xts,
    64,
    32,
    "vectors/kalyna-xts/256-512.json"
);
official_vector_test!(
    kalyna512_512_official_vectors,
    Kalyna512_512Xts,
    64,
    64,
    "vectors/kalyna-xts/512-512.json"
);

#[test]
fn buffer_shorter_than_one_block_is_rejected_not_undefined() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let cipher = Kalyna128_128Xts::new(&key);

    for len in 0..16 {
        let mut buf = vec![0u8; len];
        assert_eq!(
            cipher.encrypt_in_place(&iv, &mut buf),
            Err(XtsError::InvalidLength),
            "len={len}"
        );
        assert_eq!(
            cipher.decrypt_in_place(&iv, &mut buf),
            Err(XtsError::InvalidLength),
            "len={len}"
        );
    }
}

/// XTS is confidentiality-only by design (`docs/release-readiness.md`'s "Full-disk encryption"
/// row) - there is no tag, so tampering ciphertext must never error, only silently decrypt to
/// garbage. Pins that this is the actual behavior, not an accident: integrity for disk sectors is
/// deliberately left to a layer above (the filesystem), unlike every AEAD mode in this crate.
#[test]
fn tampered_ciphertext_does_not_error_but_produces_garbage() {
    let case = &cases(include_str!("vectors/kalyna-xts/128-128.json"))[0];
    let mut key = [0u8; 16];
    key.copy_from_slice(&case.key);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&case.iv);
    let cipher = Kalyna128_128Xts::new(&key);

    let mut tampered = case.ciphertext.clone();
    tampered[0] ^= 0x01;

    cipher
        .decrypt_in_place(&iv, &mut tampered)
        .expect("XTS has no tag to fail - tampering must not error");
    assert_ne!(
        tampered, case.plaintext,
        "tampered ciphertext must decrypt to something other than the original plaintext"
    );
}

macro_rules! roundtrip_proptest {
    ($mod_name:ident, $variant:ty, $key_len:literal, $block_len:literal) => {
        mod $mod_name {
            use super::*;

            proptest! {
                /// encrypt-then-decrypt must recover the original buffer for any length
                /// >= one block - covers both the aligned (simple-loop) and non-aligned
                /// (ciphertext-stealing) paths generically, not just the two fixed lengths
                /// the official vectors happen to use.
                #[test]
                fn encrypt_then_decrypt_roundtrips(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    iv in proptest::collection::vec(any::<u8>(), $block_len),
                    data in proptest::collection::vec(any::<u8>(), $block_len..(3 * $block_len + 7)),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut iv_arr = [0u8; $block_len];
                    iv_arr.copy_from_slice(&iv);
                    let cipher = <$variant>::new(&key_arr);

                    let original = data.clone();
                    let mut buf = data;
                    cipher.encrypt_in_place(&iv_arr, &mut buf).unwrap();
                    cipher.decrypt_in_place(&iv_arr, &mut buf).unwrap();

                    prop_assert_eq!(buf, original);
                }
            }
        }
    };
}

roundtrip_proptest!(k128_128, Kalyna128_128Xts, 16, 16);
roundtrip_proptest!(k128_256, Kalyna128_256Xts, 32, 16);
roundtrip_proptest!(k256_256, Kalyna256_256Xts, 32, 32);
roundtrip_proptest!(k256_512, Kalyna256_512Xts, 64, 32);
roundtrip_proptest!(k512_512, Kalyna512_512Xts, 64, 64);
