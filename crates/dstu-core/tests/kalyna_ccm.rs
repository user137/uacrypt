//! Black-box integration test for `dstu_core::hazmat::kalyna_ccm` against the cross-oracle
//! vectors in `tests/vectors/kalyna-ccm/` (BC + UAPKI, see each vector file's `source` field and
//! `DECISIONS.md` D-41). Same hand-rolled extractor convention as `tests/kalyna.rs`.

use dstu_core::hazmat::kalyna_ccm::{
    CcmError, Kalyna128_128Ccm, Kalyna128_256Ccm, Kalyna256_256Ccm, Kalyna256_512Ccm,
    Kalyna512_512Ccm,
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
    nonce: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

fn cases(json: &'static str) -> Vec<Case> {
    let keys = extract_all(json, "key_hex");
    let nonces = extract_all(json, "nonce_hex");
    let aads = extract_all(json, "aad_hex");
    let plaintexts = extract_all(json, "plaintext_hex");
    let ciphertexts = extract_all(json, "ciphertext_hex");
    let tags = extract_all(json, "tag_hex");
    assert!(
        !keys.is_empty(),
        "no cases found - extractor or fixture is broken"
    );
    assert_eq!(keys.len(), nonces.len());
    assert_eq!(keys.len(), aads.len());
    assert_eq!(keys.len(), plaintexts.len());
    assert_eq!(keys.len(), ciphertexts.len());
    assert_eq!(keys.len(), tags.len());

    keys.into_iter()
        .zip(nonces)
        .zip(aads)
        .zip(plaintexts)
        .zip(ciphertexts)
        .zip(tags)
        .map(
            |(((((key, nonce), aad), plaintext), ciphertext), tag)| Case {
                key: decode_hex(key),
                nonce: decode_hex(nonce),
                aad: decode_hex(aad),
                plaintext: decode_hex(plaintext),
                ciphertext: decode_hex(ciphertext),
                tag: decode_hex(tag),
            },
        )
        .collect()
}

macro_rules! variant_test {
    ($mod_name:ident, $file:literal, $variant:ty, $key_len:literal, $block_len:literal, $tag_len:literal) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn official_vector_seals_and_opens() {
                let json = include_str!($file);
                for case in cases(json) {
                    let mut key = [0u8; $key_len];
                    key.copy_from_slice(&case.key);
                    let mut nonce = [0u8; $block_len];
                    nonce.copy_from_slice(&case.nonce);

                    let cipher = <$variant>::new(&key);

                    let mut buf = case.plaintext.clone();
                    let tag = cipher
                        .seal_in_place(&nonce, &case.aad, &mut buf)
                        .expect("seal within length limits");
                    assert_eq!(buf, case.ciphertext, "ciphertext mismatch");
                    assert_eq!(tag.as_slice(), case.tag.as_slice(), "tag mismatch");

                    let mut tag_arr = [0u8; $tag_len];
                    tag_arr.copy_from_slice(&case.tag);
                    let mut open_buf = case.ciphertext.clone();
                    cipher
                        .open_in_place(&nonce, &case.aad, &mut open_buf, &tag_arr)
                        .expect("open should verify against the known-good tag");
                    assert_eq!(open_buf, case.plaintext, "recovered plaintext mismatch");
                }
            }

            proptest! {
                #[test]
                fn round_trip(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    nonce in proptest::collection::vec(any::<u8>(), $block_len),
                    aad in proptest::collection::vec(any::<u8>(), 0..64),
                    plaintext in proptest::collection::vec(any::<u8>(), 0..64),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut nonce_arr = [0u8; $block_len];
                    nonce_arr.copy_from_slice(&nonce);
                    let cipher = <$variant>::new(&key_arr);

                    let mut buf = plaintext.clone();
                    let tag = cipher.seal_in_place(&nonce_arr, &aad, &mut buf).unwrap();

                    let mut open_buf = buf.clone();
                    cipher.open_in_place(&nonce_arr, &aad, &mut open_buf, &tag).unwrap();
                    prop_assert_eq!(open_buf, plaintext);
                }

                #[test]
                fn tampered_ciphertext_is_rejected(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    nonce in proptest::collection::vec(any::<u8>(), $block_len),
                    aad in proptest::collection::vec(any::<u8>(), 0..32),
                    plaintext in proptest::collection::vec(any::<u8>(), 1..64),
                    flip_index in 0usize..64,
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut nonce_arr = [0u8; $block_len];
                    nonce_arr.copy_from_slice(&nonce);
                    let cipher = <$variant>::new(&key_arr);

                    let mut buf = plaintext.clone();
                    let tag = cipher.seal_in_place(&nonce_arr, &aad, &mut buf).unwrap();

                    let idx = flip_index % buf.len();
                    buf[idx] ^= 0x01;

                    let mut open_buf = buf.clone();
                    let result = cipher.open_in_place(&nonce_arr, &aad, &mut open_buf, &tag);
                    prop_assert_eq!(result, Err(CcmError::TagMismatch));
                    prop_assert!(open_buf.iter().all(|&b| b == 0), "plaintext must not survive a failed verify");
                }

                #[test]
                fn tampered_tag_is_rejected(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    nonce in proptest::collection::vec(any::<u8>(), $block_len),
                    aad in proptest::collection::vec(any::<u8>(), 0..32),
                    plaintext in proptest::collection::vec(any::<u8>(), 0..64),
                    flip_index in 0usize..$tag_len,
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut nonce_arr = [0u8; $block_len];
                    nonce_arr.copy_from_slice(&nonce);
                    let cipher = <$variant>::new(&key_arr);

                    let mut buf = plaintext.clone();
                    let mut tag = cipher.seal_in_place(&nonce_arr, &aad, &mut buf).unwrap();
                    tag[flip_index] ^= 0x01;

                    let mut open_buf = buf.clone();
                    let result = cipher.open_in_place(&nonce_arr, &aad, &mut open_buf, &tag);
                    prop_assert_eq!(result, Err(CcmError::TagMismatch));
                }

                #[test]
                fn tampered_aad_is_rejected(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    nonce in proptest::collection::vec(any::<u8>(), $block_len),
                    aad in proptest::collection::vec(any::<u8>(), 1..32),
                    plaintext in proptest::collection::vec(any::<u8>(), 0..64),
                    flip_index in 0usize..32,
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut nonce_arr = [0u8; $block_len];
                    nonce_arr.copy_from_slice(&nonce);
                    let cipher = <$variant>::new(&key_arr);

                    let mut buf = plaintext.clone();
                    let tag = cipher.seal_in_place(&nonce_arr, &aad, &mut buf).unwrap();

                    let mut tampered_aad = aad.clone();
                    let idx = flip_index % tampered_aad.len();
                    tampered_aad[idx] ^= 0x01;

                    let mut open_buf = buf.clone();
                    let result = cipher.open_in_place(&nonce_arr, &tampered_aad, &mut open_buf, &tag);
                    prop_assert_eq!(result, Err(CcmError::TagMismatch));
                }

                #[test]
                fn tampered_nonce_is_rejected(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    nonce in proptest::collection::vec(any::<u8>(), $block_len),
                    aad in proptest::collection::vec(any::<u8>(), 0..32),
                    plaintext in proptest::collection::vec(any::<u8>(), 0..64),
                    flip_index in 0usize..$block_len,
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut nonce_arr = [0u8; $block_len];
                    nonce_arr.copy_from_slice(&nonce);
                    let cipher = <$variant>::new(&key_arr);

                    let mut buf = plaintext.clone();
                    let tag = cipher.seal_in_place(&nonce_arr, &aad, &mut buf).unwrap();

                    let mut tampered_nonce = nonce_arr;
                    tampered_nonce[flip_index] ^= 0x01;

                    let mut open_buf = buf.clone();
                    let result = cipher.open_in_place(&tampered_nonce, &aad, &mut open_buf, &tag);
                    prop_assert_eq!(result, Err(CcmError::TagMismatch));
                    prop_assert!(open_buf.iter().all(|&b| b == 0), "plaintext must not survive a failed verify");
                }

                #[test]
                fn wrong_key_is_rejected(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    wrong_key in proptest::collection::vec(any::<u8>(), $key_len),
                    nonce in proptest::collection::vec(any::<u8>(), $block_len),
                    aad in proptest::collection::vec(any::<u8>(), 0..32),
                    plaintext in proptest::collection::vec(any::<u8>(), 0..64),
                ) {
                    prop_assume!(key != wrong_key);

                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut wrong_key_arr = [0u8; $key_len];
                    wrong_key_arr.copy_from_slice(&wrong_key);
                    let mut nonce_arr = [0u8; $block_len];
                    nonce_arr.copy_from_slice(&nonce);

                    let cipher = <$variant>::new(&key_arr);
                    let mut buf = plaintext.clone();
                    let tag = cipher.seal_in_place(&nonce_arr, &aad, &mut buf).unwrap();

                    let wrong_cipher = <$variant>::new(&wrong_key_arr);
                    let mut open_buf = buf.clone();
                    let result = wrong_cipher.open_in_place(&nonce_arr, &aad, &mut open_buf, &tag);
                    prop_assert_eq!(result, Err(CcmError::TagMismatch));
                }
            }
        }
    };
}

variant_test!(
    kalyna_128_128,
    "vectors/kalyna-ccm/128-128.json",
    Kalyna128_128Ccm,
    16,
    16,
    16
);
variant_test!(
    kalyna_128_256,
    "vectors/kalyna-ccm/128-256.json",
    Kalyna128_256Ccm,
    32,
    16,
    16
);
variant_test!(
    kalyna_256_256,
    "vectors/kalyna-ccm/256-256.json",
    Kalyna256_256Ccm,
    32,
    32,
    16
);
variant_test!(
    kalyna_256_512,
    "vectors/kalyna-ccm/256-512.json",
    Kalyna256_512Ccm,
    64,
    32,
    32
);
variant_test!(
    kalyna_512_512,
    "vectors/kalyna-ccm/512-512.json",
    Kalyna512_512Ccm,
    64,
    64,
    64
);

#[test]
fn plaintext_over_limit_is_rejected() {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let cipher = Kalyna128_128Ccm::new(&key);
    let mut buf = vec![0u8; dstu_core::hazmat::kalyna_ccm::MAX_PLAINTEXT_LEN + 1];
    let result = cipher.seal_in_place(&nonce, &[], &mut buf);
    assert_eq!(result.unwrap_err(), CcmError::PlaintextTooLong);
}

#[test]
fn aad_over_limit_is_rejected() {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let cipher = Kalyna128_128Ccm::new(&key);
    let aad = vec![0u8; dstu_core::hazmat::kalyna_ccm::MAX_AAD_LEN + 1];
    let mut buf = [0u8; 16];
    let result = cipher.seal_in_place(&nonce, &aad, &mut buf);
    assert_eq!(result.unwrap_err(), CcmError::AadTooLong);
}
