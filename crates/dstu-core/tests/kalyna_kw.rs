//! Black-box integration test for `dstu_core::hazmat::kalyna_kw` against the cross-oracle vectors
//! in `tests/vectors/kalyna-kw/` (`TASKS.md` T-94, `DECISIONS.md` D-55) - one block-aligned uapki
//! KAT per Kalyna variant (full 5-variant coverage), shared-BC-lineage corroborated for
//! Kalyna128_128 only. The non-aligned/padding branch is out of scope for this module (see D-55) -
//! `wrap`/`unwrap` only accept block-aligned input, matching both Bouncy Castle ports' own
//! restriction.

use dstu_core::hazmat::kalyna_kw::{
    Kalyna128_128Kw, Kalyna128_256Kw, Kalyna256_256Kw, Kalyna256_512Kw, Kalyna512_512Kw, KwError,
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
    assert_eq!(keys.len(), plaintexts.len());
    assert_eq!(keys.len(), ciphertexts.len());
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

macro_rules! official_vector_test {
    ($test_name:ident, $variant:ty, $key_len:literal, $fixture:literal) => {
        #[test]
        fn $test_name() {
            for case in cases(include_str!($fixture)) {
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&case.key);

                let mut wrapped = vec![0u8; case.ciphertext.len()];
                <$variant>::wrap(&key, &case.plaintext, &mut wrapped).expect("valid wrap input");
                assert_eq!(wrapped, case.ciphertext, "wrap mismatch");

                let mut unwrapped = vec![0u8; case.plaintext.len()];
                <$variant>::unwrap(&key, &case.ciphertext, &mut unwrapped)
                    .expect("valid, untampered ciphertext");
                assert_eq!(unwrapped, case.plaintext, "unwrap mismatch");
            }
        }
    };
}

official_vector_test!(
    kalyna128_128_official_vector,
    Kalyna128_128Kw,
    16,
    "vectors/kalyna-kw/128-128.json"
);
official_vector_test!(
    kalyna128_256_official_vector,
    Kalyna128_256Kw,
    32,
    "vectors/kalyna-kw/128-256.json"
);
official_vector_test!(
    kalyna256_256_official_vector,
    Kalyna256_256Kw,
    32,
    "vectors/kalyna-kw/256-256.json"
);
official_vector_test!(
    kalyna256_512_official_vector,
    Kalyna256_512Kw,
    64,
    "vectors/kalyna-kw/256-512.json"
);
official_vector_test!(
    kalyna512_512_official_vector,
    Kalyna512_512Kw,
    64,
    "vectors/kalyna-kw/512-512.json"
);

#[test]
fn tampered_ciphertext_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-kw/128-128.json"))[0];
    let mut key = [0u8; 16];
    key.copy_from_slice(&case.key);

    let mut tampered = case.ciphertext.clone();
    tampered[0] ^= 0x01;

    let mut out = vec![0u8; case.plaintext.len()];
    assert_eq!(
        Kalyna128_128Kw::unwrap(&key, &tampered, &mut out),
        Err(KwError::ChecksumMismatch)
    );
}

#[test]
fn wrong_key_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-kw/128-128.json"))[0];
    let mut wrong_key = [0u8; 16];
    wrong_key.copy_from_slice(&case.key);
    wrong_key[0] ^= 0x01;

    let mut out = vec![0u8; case.plaintext.len()];
    assert_eq!(
        Kalyna128_128Kw::unwrap(&wrong_key, &case.ciphertext, &mut out),
        Err(KwError::ChecksumMismatch)
    );
}

#[test]
fn non_block_aligned_plaintext_is_rejected() {
    let key = [0u8; 16];
    let plaintext = [0u8; 17];
    let mut out = [0u8; 33];
    assert_eq!(
        Kalyna128_128Kw::wrap(&key, &plaintext, &mut out),
        Err(KwError::InvalidLength)
    );
}

#[test]
fn empty_plaintext_is_rejected() {
    let key = [0u8; 16];
    let mut out = [0u8; 16];
    assert_eq!(
        Kalyna128_128Kw::wrap(&key, &[], &mut out),
        Err(KwError::InvalidLength)
    );
}

#[test]
fn oversized_plaintext_is_rejected() {
    // r <= 20 is the enforced bound (DECISIONS.md D-55); r = 21 must be rejected.
    let key = [0u8; 16];
    let plaintext = [0u8; 16 * 21];
    let mut out = vec![0u8; 16 * 22];
    assert_eq!(
        Kalyna128_128Kw::wrap(&key, &plaintext, &mut out),
        Err(KwError::InvalidLength)
    );
}

#[test]
fn wrong_output_buffer_length_is_rejected() {
    let key = [0u8; 16];
    let plaintext = [0u8; 16];
    let mut out = [0u8; 16]; // should be 32
    assert_eq!(
        Kalyna128_128Kw::wrap(&key, &plaintext, &mut out),
        Err(KwError::InvalidLength)
    );
}

#[test]
fn ciphertext_too_short_is_rejected() {
    let key = [0u8; 16];
    let ciphertext = [0u8; 16]; // must be >= 32 (at least 1 plaintext block + 1 checksum block)
    let mut out = [0u8; 0];
    assert_eq!(
        Kalyna128_128Kw::unwrap(&key, &ciphertext, &mut out),
        Err(KwError::InvalidLength)
    );
}

macro_rules! roundtrip_proptest {
    ($mod_name:ident, $variant:ty, $key_len:literal, $block_len:literal) => {
        mod $mod_name {
            use super::*;

            proptest! {
                /// wrap-then-unwrap must recover the original plaintext for every block-aligned
                /// length up to the enforced r <= 20 bound (DECISIONS.md D-55).
                #[test]
                fn wrap_then_unwrap_roundtrips(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    r in 1usize..=20,
                    seed in any::<u8>(),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);

                    let plaintext: Vec<u8> = (0..r * $block_len)
                        .map(|i| seed.wrapping_add(i as u8))
                        .collect();

                    let mut wrapped = vec![0u8; plaintext.len() + $block_len];
                    <$variant>::wrap(&key_arr, &plaintext, &mut wrapped).unwrap();

                    let mut recovered = vec![0u8; plaintext.len()];
                    <$variant>::unwrap(&key_arr, &wrapped, &mut recovered).unwrap();

                    prop_assert_eq!(recovered, plaintext);
                }
            }
        }
    };
}

roundtrip_proptest!(k128_128, Kalyna128_128Kw, 16, 16);
roundtrip_proptest!(k128_256, Kalyna128_256Kw, 32, 16);
roundtrip_proptest!(k256_256, Kalyna256_256Kw, 32, 32);
roundtrip_proptest!(k256_512, Kalyna256_512Kw, 64, 32);
roundtrip_proptest!(k512_512, Kalyna512_512Kw, 64, 64);
