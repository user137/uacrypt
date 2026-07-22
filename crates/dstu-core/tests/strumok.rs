//! Black-box integration test for `dstu_core::hazmat::strumok` against the UAPKI-attributed
//! keystream vectors in `tests/vectors/strumok/` — **not** the official DSTU 8845:2019 text
//! itself (no copy of that has been located; see `ORACLES.md` and `DECISIONS.md` D-15). Same
//! hand-rolled extractor as `tests/kalyna.rs`/`tests/kupyna.rs` — no JSON dependency for a fixed,
//! project-controlled vector shape.

use dstu_core::hazmat::strumok::{Strumok256, Strumok512};
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

macro_rules! keystream_test {
    ($test_name:ident, $file:literal, $variant:ty, $key_len:literal) => {
        #[test]
        fn $test_name() {
            let json = include_str!($file);
            let keys = extract_all(json, "key_hex");
            let ivs = extract_all(json, "iv_hex");
            let keystreams = extract_all(json, "keystream_hex");
            assert_eq!(
                keys.len(),
                ivs.len(),
                "key/iv count mismatch in vector file"
            );
            assert_eq!(
                keys.len(),
                keystreams.len(),
                "key/keystream count mismatch in vector file"
            );
            assert!(
                !keys.is_empty(),
                "no cases found - extractor or fixture is broken"
            );

            for ((key_hex, iv_hex), keystream_hex) in
                keys.iter().zip(ivs.iter()).zip(keystreams.iter())
            {
                let key_bytes = decode_hex(key_hex);
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&key_bytes);

                let iv_bytes = decode_hex(iv_hex);
                let mut iv = [0u8; 32];
                iv.copy_from_slice(&iv_bytes);

                let expected = decode_hex(keystream_hex);
                let mut actual = vec![0u8; expected.len()];
                let mut cipher = <$variant>::new(&key, &iv);
                cipher.apply_keystream(&mut actual);

                assert_eq!(
                    actual,
                    expected,
                    "{}: keystream mismatch for key_hex={key_hex}",
                    stringify!($variant)
                );
            }
        }
    };
}

keystream_test!(
    strumok_256_uapki_attributed_vectors,
    "vectors/strumok/keystream-256.json",
    Strumok256,
    32
);
keystream_test!(
    strumok_512_uapki_attributed_vectors,
    "vectors/strumok/keystream-512.json",
    Strumok512,
    64
);

/// `apply_keystream` buffers a partial 64-bit word internally (`Core::block`/`block_pos` in
/// `strumok.rs`) whenever a call doesn't end on an 8-byte boundary. Every vector test above calls
/// it exactly once, on a length that happens to be a multiple of 8 - that never exercises the
/// buffer across a call boundary. This test asserts that splitting the same total length into
/// arbitrary, non-8-aligned chunks produces byte-for-byte the same output as one call on the
/// concatenated buffer - the boundary case a buffering off-by-one would hide in.
macro_rules! chunk_invariance_test {
    ($test_name:ident, $variant:ty, $key_len:literal) => {
        #[test]
        fn $test_name() {
            let mut key = [0u8; $key_len];
            for (i, b) in key.iter_mut().enumerate() {
                *b = i as u8;
            }
            let mut iv = [0u8; 32];
            for (i, b) in iv.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(1);
            }

            // Deliberately not a round multiple of 8, and includes chunk lengths both smaller
            // and larger than one word, plus a zero-length chunk (must be a no-op).
            let chunk_lens = [1usize, 8, 3, 0, 5, 13, 2, 7, 21, 4];
            let total: usize = chunk_lens.iter().sum();

            let mut whole = vec![0u8; total];
            <$variant>::new(&key, &iv).apply_keystream(&mut whole);

            let mut chunked = vec![0u8; total];
            let mut cipher = <$variant>::new(&key, &iv);
            let mut offset = 0;
            for len in chunk_lens {
                cipher.apply_keystream(&mut chunked[offset..offset + len]);
                offset += len;
            }

            assert_eq!(
                chunked,
                whole,
                "{}: chunked apply_keystream diverged from one-shot output",
                stringify!($variant)
            );
        }
    };
}

chunk_invariance_test!(strumok_256_chunk_invariance, Strumok256, 32);
chunk_invariance_test!(strumok_512_chunk_invariance, Strumok512, 64);

/// A stream cipher's keystream XOR is its own inverse: applying it twice with the same key/IV
/// must return the original bytes. Property-tested over random keys/IVs/data instead of relying
/// only on the fixed vectors above - see `TASKS.md` "Testing & hardening".
macro_rules! xor_involution_proptest {
    ($test_name:ident, $variant:ty, $key_len:literal) => {
        proptest! {
            #[test]
            fn $test_name(
                key_bytes in prop::collection::vec(any::<u8>(), $key_len),
                iv_bytes in prop::collection::vec(any::<u8>(), 32),
                data in prop::collection::vec(any::<u8>(), 0..300),
            ) {
                let mut key = [0u8; $key_len];
                key.copy_from_slice(&key_bytes);
                let mut iv = [0u8; 32];
                iv.copy_from_slice(&iv_bytes);

                let mut buf = data.clone();
                <$variant>::new(&key, &iv).apply_keystream(&mut buf);
                // Fresh cipher instance, same key/IV - re-derives the identical keystream from
                // the start, so applying it again must undo the first pass.
                <$variant>::new(&key, &iv).apply_keystream(&mut buf);

                prop_assert_eq!(buf, data);
            }
        }
    };
}

xor_involution_proptest!(strumok_256_apply_keystream_is_involution, Strumok256, 32);
xor_involution_proptest!(strumok_512_apply_keystream_is_involution, Strumok512, 64);
