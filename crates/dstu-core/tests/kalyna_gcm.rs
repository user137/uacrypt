//! Black-box integration test for `dstu_core::hazmat::kalyna_gcm` against the cross-oracle vectors
//! in `tests/vectors/kalyna-gcm/` (`TASKS.md` T-95, `DECISIONS.md` D-56) - one KAT per Kalyna
//! variant (full 5-variant coverage), plus a bonus q=16-vs-q=32 truncation-consistency pair for
//! Kalyna256_256. All 6 official vectors have block-aligned plaintext - the ISO/IEC 7816-4
//! padding-marker branch in the ciphertext-accumulation step is untested by any oracle vector, see
//! D-56.

use dstu_core::hazmat::kalyna_gcm::{
    GcmError, Kalyna128_128Gcm, Kalyna128_256Gcm, Kalyna256_256Gcm, Kalyna256_512Gcm,
    Kalyna512_512Gcm,
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
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

fn cases(json: &'static str) -> Vec<Case> {
    let keys = extract_all(json, "key_hex");
    let ivs = extract_all(json, "iv_hex");
    let aads = extract_all(json, "aad_hex");
    let plaintexts = extract_all(json, "plaintext_hex");
    let ciphertexts = extract_all(json, "ciphertext_hex");
    let tags = extract_all(json, "tag_hex");
    assert!(!keys.is_empty(), "no cases found - fixture is broken");
    let n = keys.len();
    assert_eq!(ivs.len(), n);
    assert_eq!(aads.len(), n);
    assert_eq!(plaintexts.len(), n);
    assert_eq!(ciphertexts.len(), n);
    assert_eq!(tags.len(), n);

    (0..n)
        .map(|i| Case {
            key: decode_hex(keys[i]),
            iv: decode_hex(ivs[i]),
            aad: decode_hex(aads[i]),
            plaintext: decode_hex(plaintexts[i]),
            ciphertext: decode_hex(ciphertexts[i]),
            tag: decode_hex(tags[i]),
        })
        .collect()
}

macro_rules! official_vector_test {
    ($test_name:ident, $variant:ty, $key_len:literal, $iv_len:literal, $fixture:literal) => {
        #[test]
        fn $test_name() {
            for case in cases(include_str!($fixture)) {
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&case.key);
                let mut iv = [0u8; $iv_len];
                iv.copy_from_slice(&case.iv);
                let cipher = <$variant>::new(&key);

                let mut ciphertext_out = vec![0u8; case.plaintext.len()];
                let tag = cipher
                    .encrypt(&iv, &case.aad, &case.plaintext, &mut ciphertext_out)
                    .expect("valid encrypt input");
                assert_eq!(ciphertext_out, case.ciphertext, "ciphertext mismatch");
                assert_eq!(&tag[..case.tag.len()], case.tag.as_slice(), "tag mismatch");

                let mut plaintext_out = vec![0u8; case.ciphertext.len()];
                cipher
                    .decrypt(
                        &iv,
                        &case.aad,
                        &case.ciphertext,
                        &case.tag,
                        &mut plaintext_out,
                    )
                    .expect("valid, untampered ciphertext");
                assert_eq!(plaintext_out, case.plaintext, "decrypt mismatch");
            }
        }
    };
}

official_vector_test!(
    kalyna128_128_official_vector,
    Kalyna128_128Gcm,
    16,
    16,
    "vectors/kalyna-gcm/128-128.json"
);
official_vector_test!(
    kalyna128_256_official_vector,
    Kalyna128_256Gcm,
    32,
    16,
    "vectors/kalyna-gcm/128-256.json"
);
official_vector_test!(
    kalyna256_256_official_vector,
    Kalyna256_256Gcm,
    32,
    32,
    "vectors/kalyna-gcm/256-256.json"
);
official_vector_test!(
    kalyna256_512_official_vector,
    Kalyna256_512Gcm,
    64,
    32,
    "vectors/kalyna-gcm/256-512.json"
);
official_vector_test!(
    kalyna512_512_official_vector,
    Kalyna512_512Gcm,
    64,
    64,
    "vectors/kalyna-gcm/512-512.json"
);

#[test]
fn shorter_tag_is_a_prefix_of_longer_tag() {
    let case = &cases(include_str!("vectors/kalyna-gcm/256-256.json"));
    let short = &case[0];
    let long = &case[1];
    assert_eq!(short.tag, long.tag[..short.tag.len()]);
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-gcm/128-128.json"))[0];
    let mut key = [0u8; 16];
    key.copy_from_slice(&case.key);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&case.iv);
    let cipher = Kalyna128_128Gcm::new(&key);

    let mut tampered = case.ciphertext.clone();
    tampered[0] ^= 0x01;

    let mut out = vec![0u8; case.plaintext.len()];
    assert_eq!(
        cipher.decrypt(&iv, &case.aad, &tampered, &case.tag, &mut out),
        Err(GcmError::TagMismatch)
    );
    assert!(out.iter().all(|&b| b == 0), "plaintext leaked on failure");
}

#[test]
fn tampered_aad_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-gcm/128-128.json"))[0];
    let mut key = [0u8; 16];
    key.copy_from_slice(&case.key);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&case.iv);
    let cipher = Kalyna128_128Gcm::new(&key);

    let mut tampered_aad = case.aad.clone();
    tampered_aad[0] ^= 0x01;

    let mut out = vec![0u8; case.plaintext.len()];
    assert_eq!(
        cipher.decrypt(&iv, &tampered_aad, &case.ciphertext, &case.tag, &mut out),
        Err(GcmError::TagMismatch)
    );
}

#[test]
fn mismatched_output_buffer_length_is_rejected() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let cipher = Kalyna128_128Gcm::new(&key);
    let plaintext = [0u8; 16];
    let mut wrong_out = [0u8; 15];
    assert_eq!(
        cipher.encrypt(&iv, &[], &plaintext, &mut wrong_out),
        Err(GcmError::InvalidLength)
    );
}

macro_rules! roundtrip_proptest {
    ($mod_name:ident, $variant:ty, $key_len:literal, $iv_len:literal, $block_len:literal) => {
        mod $mod_name {
            use super::*;

            proptest! {
                /// encrypt-then-decrypt must recover the original plaintext and produce a
                /// verifying tag, for both block-aligned and non-block-aligned lengths (the
                /// padding-marker branch no official vector exercises - see D-56).
                #[test]
                fn encrypt_then_decrypt_roundtrips(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    iv in proptest::collection::vec(any::<u8>(), $iv_len),
                    aad in proptest::collection::vec(any::<u8>(), 0..50),
                    plaintext in proptest::collection::vec(any::<u8>(), 0..(3 * $block_len + 7)),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);
                    let mut iv_arr = [0u8; $iv_len];
                    iv_arr.copy_from_slice(&iv);
                    let cipher = <$variant>::new(&key_arr);

                    let mut ciphertext = vec![0u8; plaintext.len()];
                    let tag = cipher.encrypt(&iv_arr, &aad, &plaintext, &mut ciphertext).unwrap();

                    let mut recovered = vec![0u8; ciphertext.len()];
                    cipher.decrypt(&iv_arr, &aad, &ciphertext, &tag, &mut recovered).unwrap();

                    prop_assert_eq!(recovered, plaintext);
                }
            }
        }
    };
}

roundtrip_proptest!(k128_128, Kalyna128_128Gcm, 16, 16, 16);
roundtrip_proptest!(k128_256, Kalyna128_256Gcm, 32, 16, 16);
roundtrip_proptest!(k256_256, Kalyna256_256Gcm, 32, 32, 32);
roundtrip_proptest!(k256_512, Kalyna256_512Gcm, 64, 32, 32);
roundtrip_proptest!(k512_512, Kalyna512_512Gcm, 64, 64, 64);
