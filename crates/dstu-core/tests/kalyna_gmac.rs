//! Black-box integration test for `dstu_core::hazmat::kalyna_gmac` against the uapki-only vectors
//! in `tests/vectors/kalyna-gmac/` (`TASKS.md` T-95, `DECISIONS.md` D-57). Every official vector is
//! exactly one block long - multi-block chaining, the `0x80` padding-marker branch, and the
//! `Kalyna128_128Gmac` variant (no official vector exists for it at all) are proptest-only, not
//! oracle-vector-covered. See D-57 for the full honesty note on why this is weaker than D-56's GCM
//! coverage.

use dstu_core::hazmat::kalyna_gmac::{
    GmacError, Kalyna128_128Gmac, Kalyna128_256Gmac, Kalyna256_256Gmac, Kalyna256_512Gmac,
    Kalyna512_512Gmac,
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
    message: Vec<u8>,
    tag: Vec<u8>,
}

fn cases(json: &'static str) -> Vec<Case> {
    let keys = extract_all(json, "key_hex");
    let messages = extract_all(json, "message_hex");
    let tags = extract_all(json, "tag_hex");
    assert!(!keys.is_empty(), "no cases found - fixture is broken");
    let n = keys.len();
    assert_eq!(messages.len(), n);
    assert_eq!(tags.len(), n);

    (0..n)
        .map(|i| Case {
            key: decode_hex(keys[i]),
            message: decode_hex(messages[i]),
            tag: decode_hex(tags[i]),
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

                let tag = <$variant>::mac(&key, &case.message);
                assert_eq!(&tag[..case.tag.len()], case.tag.as_slice(), "tag mismatch");

                <$variant>::verify(&key, &case.message, &case.tag)
                    .expect("official vector must verify");
            }
        }
    };
}

official_vector_test!(
    kalyna128_256_official_vector,
    Kalyna128_256Gmac,
    32,
    "vectors/kalyna-gmac/128-256.json"
);
official_vector_test!(
    kalyna256_256_official_vector,
    Kalyna256_256Gmac,
    32,
    "vectors/kalyna-gmac/256-256.json"
);
official_vector_test!(
    kalyna256_512_official_vector,
    Kalyna256_512Gmac,
    64,
    "vectors/kalyna-gmac/256-512.json"
);
official_vector_test!(
    kalyna512_512_official_vector,
    Kalyna512_512Gmac,
    64,
    "vectors/kalyna-gmac/512-512.json"
);

#[test]
fn shorter_tag_is_a_prefix_of_longer_tag() {
    let case = &cases(include_str!("vectors/kalyna-gmac/256-256.json"));
    let short = &case[0];
    let long = &case[1];
    assert_eq!(short.tag, long.tag[..short.tag.len()]);
}

#[test]
fn tampered_message_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-gmac/128-256.json"))[0];
    let mut key = [0u8; 32];
    key.copy_from_slice(&case.key);

    let mut tampered = case.message.clone();
    tampered[0] ^= 0x01;

    assert_eq!(
        Kalyna128_256Gmac::verify(&key, &tampered, &case.tag),
        Err(GmacError::TagMismatch)
    );
}

#[test]
fn tag_length_out_of_range_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-gmac/128-256.json"))[0];
    let mut key = [0u8; 32];
    key.copy_from_slice(&case.key);

    let too_short = &case.tag[..7];
    assert_eq!(
        Kalyna128_256Gmac::verify(&key, &case.message, too_short),
        Err(GmacError::InvalidLength)
    );

    let mut too_long = case.tag.clone();
    too_long.push(0);
    assert_eq!(
        Kalyna128_256Gmac::verify(&key, &case.message, &too_long),
        Err(GmacError::InvalidLength)
    );
}

macro_rules! roundtrip_proptest {
    ($mod_name:ident, $variant:ty, $key_len:literal, $block_len:literal) => {
        mod $mod_name {
            use super::*;

            proptest! {
                /// `verify` must accept a freshly computed `mac`, for both block-aligned and
                /// non-block-aligned lengths (the padding-marker branch, and any multi-block
                /// input, no official vector exercises - see D-57) and for message-content
                /// changes to be tag-detectable (the Horner chain must actually read every
                /// block, not just the first - exactly the property the found reference bug
                /// (D-57) would violate if ported faithfully).
                #[test]
                fn mac_then_verify_roundtrips(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    message in proptest::collection::vec(any::<u8>(), 0..(3 * $block_len + 7)),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);

                    let tag = <$variant>::mac(&key_arr, &message);
                    prop_assert!(<$variant>::verify(&key_arr, &message, &tag).is_ok());
                }

                #[test]
                fn changing_any_block_changes_the_tag(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    message in proptest::collection::vec(any::<u8>(), 2 * $block_len..(3 * $block_len)),
                    flip_index in 0usize..(2 * $block_len),
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);

                    let tag = <$variant>::mac(&key_arr, &message);
                    let mut altered = message.clone();
                    altered[flip_index] ^= 0x01;
                    let altered_tag = <$variant>::mac(&key_arr, &altered);
                    prop_assert_ne!(tag, altered_tag);
                }
            }
        }
    };
}

roundtrip_proptest!(k128_128, Kalyna128_128Gmac, 16, 16);
roundtrip_proptest!(k128_256, Kalyna128_256Gmac, 32, 16);
roundtrip_proptest!(k256_256, Kalyna256_256Gmac, 32, 32);
roundtrip_proptest!(k256_512, Kalyna256_512Gmac, 64, 32);
roundtrip_proptest!(k512_512, Kalyna512_512Gmac, 64, 64);
