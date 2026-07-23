//! Black-box integration test for `dstu_core::hazmat::kupyna` against the official test vectors
//! in `tests/vectors/kupyna/` (extracted from `docs/papers/Kupyna.pdf` Appendix B — see
//! `ORACLES.md`). No JSON/hex crate dependency: the vector files have a fixed, simple shape
//! controlled by this project, so a tiny inline extractor is safer than adding a dependency for
//! two fields.

use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna256Hasher, Kupyna512, Kupyna512Hasher};

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

/// Pulls every value of `"key": "..."` out of the vector JSON, in file order.
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

#[test]
fn kupyna_256_official_vectors() {
    let json = include_str!("vectors/kupyna/kupyna-256.json");
    let messages = extract_all(json, "message_hex");
    let hashes = extract_all(json, "hash_hex");
    assert_eq!(
        messages.len(),
        hashes.len(),
        "message/hash count mismatch in vector file"
    );
    assert!(
        !messages.is_empty(),
        "no cases found - extractor or fixture is broken"
    );

    for (message_hex, expected_hex) in messages.iter().zip(hashes.iter()) {
        let message = decode_hex(message_hex);
        let expected = decode_hex(expected_hex);
        let actual = Kupyna256::digest(&message);
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "Kupyna-256 mismatch for message_hex={message_hex}"
        );
    }
}

#[test]
fn kupyna_512_official_vectors() {
    let json = include_str!("vectors/kupyna/kupyna-512.json");
    let messages = extract_all(json, "message_hex");
    let hashes = extract_all(json, "hash_hex");
    assert_eq!(
        messages.len(),
        hashes.len(),
        "message/hash count mismatch in vector file"
    );
    assert!(
        !messages.is_empty(),
        "no cases found - extractor or fixture is broken"
    );

    for (message_hex, expected_hex) in messages.iter().zip(hashes.iter()) {
        let message = decode_hex(message_hex);
        let expected = decode_hex(expected_hex);
        let actual = Kupyna512::digest(&message);
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "Kupyna-512 mismatch for message_hex={message_hex}"
        );
    }
}

/// Streaming (`Hasher::update`/`finalize`) must match one-shot `digest()` for every official
/// vector, fed as a single `update` call - the simplest possible streaming use, but still a real
/// exercise of the new incremental padding/length-tracking logic (T-11 follow-up).
#[test]
fn kupyna_256_streaming_single_update_matches_official_vectors() {
    let json = include_str!("vectors/kupyna/kupyna-256.json");
    let messages = extract_all(json, "message_hex");
    let hashes = extract_all(json, "hash_hex");

    for (message_hex, expected_hex) in messages.iter().zip(hashes.iter()) {
        let message = decode_hex(message_hex);
        let expected = decode_hex(expected_hex);
        let mut hasher = Kupyna256Hasher::new();
        hasher.update(&message);
        let actual = hasher.finalize();
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "Kupyna-256 streaming mismatch for message_hex={message_hex}"
        );
    }
}

#[test]
fn kupyna_512_streaming_single_update_matches_official_vectors() {
    let json = include_str!("vectors/kupyna/kupyna-512.json");
    let messages = extract_all(json, "message_hex");
    let hashes = extract_all(json, "hash_hex");

    for (message_hex, expected_hex) in messages.iter().zip(hashes.iter()) {
        let message = decode_hex(message_hex);
        let expected = decode_hex(expected_hex);
        let mut hasher = Kupyna512Hasher::new();
        hasher.update(&message);
        let actual = hasher.finalize();
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "Kupyna-512 streaming mismatch for message_hex={message_hex}"
        );
    }
}

/// `Default` must agree with `new()` - a plain sanity check, not a security property, but cheap
/// insurance against the two ever drifting apart.
#[test]
fn kupyna_hasher_default_matches_new() {
    assert_eq!(
        Kupyna256Hasher::default().finalize(),
        Kupyna256Hasher::new().finalize()
    );
    assert_eq!(
        Kupyna512Hasher::default().finalize(),
        Kupyna512Hasher::new().finalize()
    );
}

/// `update` buffers a partial block internally whenever a call doesn't end on a block boundary
/// (64 bytes for Kupyna-256, 128 for Kupyna-512). Every vector/single-update test above calls
/// `update` exactly once, which never exercises that buffer across a call boundary. This asserts
/// that splitting the same message into arbitrary, non-block-aligned chunks produces byte-for-byte
/// the same digest as one `update` call on the whole message - the same boundary case T-24 already
/// checks for `Strumok::apply_keystream`, applied here to the new incremental state.
macro_rules! chunk_invariance_test {
    ($test_name:ident, $hasher:ty) => {
        #[test]
        fn $test_name() {
            // Deliberately spans more than one block for both variants (128+ bytes total),
            // includes chunk lengths both smaller and larger than a block, and a zero-length
            // chunk (must be a no-op).
            let chunk_lens = [1usize, 64, 3, 0, 5, 130, 2, 7, 128, 4];
            let total: usize = chunk_lens.iter().sum();
            let message: Vec<u8> = (0..total).map(|i| (i as u8).wrapping_mul(31)).collect();

            let mut whole = <$hasher>::new();
            whole.update(&message);
            let expected = whole.finalize();

            let mut chunked = <$hasher>::new();
            let mut offset = 0;
            for len in chunk_lens {
                chunked.update(&message[offset..offset + len]);
                offset += len;
            }
            let actual = chunked.finalize();

            assert_eq!(
                actual,
                expected,
                "{}: chunked update diverged from one-shot update",
                stringify!($hasher)
            );
        }
    };
}

chunk_invariance_test!(kupyna_256_streaming_chunk_invariance, Kupyna256Hasher);
chunk_invariance_test!(kupyna_512_streaming_chunk_invariance, Kupyna512Hasher);

mod streaming_proptests {
    use super::{Kupyna256, Kupyna256Hasher, Kupyna512, Kupyna512Hasher};
    use proptest::prelude::*;

    macro_rules! streaming_matches_one_shot {
        ($test_name:ident, $hasher:ty, $one_shot:ty) => {
            proptest! {
                #[test]
                fn $test_name(message in proptest::collection::vec(any::<u8>(), 0..600), split in 0usize..600) {
                    let split = split.min(message.len());
                    let mut hasher = <$hasher>::new();
                    hasher.update(&message[..split]);
                    hasher.update(&message[split..]);
                    let streamed = hasher.finalize();
                    let one_shot = <$one_shot>::digest(&message);
                    prop_assert_eq!(streamed.as_slice(), one_shot.as_slice());
                }
            }
        };
    }

    streaming_matches_one_shot!(
        kupyna_256_streaming_matches_one_shot,
        Kupyna256Hasher,
        Kupyna256
    );
    streaming_matches_one_shot!(
        kupyna_512_streaming_matches_one_shot,
        Kupyna512Hasher,
        Kupyna512
    );
}
