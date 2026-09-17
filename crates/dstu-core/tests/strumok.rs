//! Black-box integration test for `dstu_core::hazmat::strumok` against the UAPKI-attributed
//! keystream vectors in `tests/vectors/strumok/`. The `official_annex_d_vectors` module below
//! verifies the same primitive directly against the official DSTU 8845:2019 text itself (Додаток
//! Д, obtained as a genuine library scan — `docs/DECISIONS.md` D-197, closing D-15/D-16's
//! "UAPKI-attributed, not independently confirmed" gap). Same hand-rolled extractor as
//! `tests/kalyna.rs`/`tests/kupyna.rs` for the JSON-backed vectors — no JSON dependency for a
//! fixed, project-controlled vector shape.

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
/// only on the fixed vectors above - see `docs/TASKS.md` "Testing & hardening".
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

#[test]
fn different_key_produces_different_keystream() {
    let iv = [0x24u8; 32];
    let mut buf_a = [0u8; 64];
    let mut buf_b = [0u8; 64];
    Strumok256::new(&[0x11u8; 32], &iv).apply_keystream(&mut buf_a);
    Strumok256::new(&[0x22u8; 32], &iv).apply_keystream(&mut buf_b);
    assert_ne!(buf_a, buf_b);
}

/// Pins `hazmat::strumok`'s module doc "Warning: never reuse the same key+IV pair" directly - not
/// a bug, the defining weakness of every stream cipher used this way. Reusing key+IV across two
/// messages must let `ciphertext_a XOR ciphertext_b` recover `plaintext_a XOR plaintext_b` with no
/// key material at all. If this test ever starts failing, the module doc's warning is stale, not
/// fixed - update the doc, don't just delete this test.
#[test]
fn reusing_key_and_iv_leaks_plaintext_xor() {
    let key = [0x77u8; 32];
    let iv = [0x24u8; 32];
    let plaintext_a = b"attack at dawn!!".to_vec();
    let plaintext_b = b"defend at dusk!!".to_vec();
    assert_eq!(plaintext_a.len(), plaintext_b.len());

    let mut ciphertext_a = plaintext_a.clone();
    Strumok256::new(&key, &iv).apply_keystream(&mut ciphertext_a);
    let mut ciphertext_b = plaintext_b.clone();
    Strumok256::new(&key, &iv).apply_keystream(&mut ciphertext_b);

    let ciphertext_xor: Vec<u8> = ciphertext_a
        .iter()
        .zip(&ciphertext_b)
        .map(|(a, b)| a ^ b)
        .collect();
    let plaintext_xor: Vec<u8> = plaintext_a
        .iter()
        .zip(&plaintext_b)
        .map(|(a, b)| a ^ b)
        .collect();
    assert_eq!(ciphertext_xor, plaintext_xor);
}

/// Official supplementary Strumok-256/512 test examples from Держспецзв'язку (State Service for
/// Special Communications), received via a public-information request - see `docs/DECISIONS.md`
/// D-104, `docs/ORACLES.md` (the request/response's own reference number, date, and signatory are
/// deliberately not recorded, here or anywhere else in this public repository - D-104 explains
/// why). Sourced from ДНДІ ТКЗІ (the State Research Institute of Cybersecurity Technologies and
/// Information Protection), described as *supplementary* to Annex Д (Annex D) of DSTU 8845:2019
/// itself, used during conformance expert examination - **not** a substitute for reading Annex D's
/// own known-answer tests (still not done, D-15/D-16 stay open on that specific point).
///
/// Hex below is transcribed **exactly as printed** in the letter's appendix (byte-for-byte
/// eyeball-diffable against it) - no pre-applied reordering. Two distinct byte-order transforms
/// are then applied explicitly, each independently derived and verified rather than assumed (see
/// D-104):
/// - Key/IV: the document labels bytes `KeyN, KeyN-1, ..., Key0` / `IVN, ..., IV0`, printed in
///   that descending-index order - the reverse of this crate's ascending-byte-array convention
///   (`hazmat::strumok::init_state`'s `kw(0)`/`ivw(0)` reads array index 0 first). Reversing the
///   printed byte sequence recovers the crate's own convention - confirmed correct because doing
///   only this (with `RandBlock` still untransformed) already produced a per-8-byte-word
///   permutation of the expected value, not unrelated bytes.
/// - `RandBlock` (the raw keystream over an all-zero input, no index annotation): matches this
///   crate's output only after each 8-byte word is *also* internally byte-reversed - a distinct
///   convention from Key/IV's, confirmed empirically the same way (every one of the 32 words
///   across both variants was an exact per-word swap of the expected value, not assumed from the
///   Key/IV pattern alone).
mod official_letter_vectors {
    use super::*;

    #[test]
    fn strumok_256() {
        let key_as_printed: [u8; 32] = [
            0x8a, 0x80, 0xbf, 0xe4, 0x04, 0x5b, 0x8c, 0x30, 0x34, 0x76, 0xfb, 0x3f, 0xe5, 0x6c,
            0x16, 0x00, 0x5c, 0x11, 0xb9, 0x35, 0xf4, 0xeb, 0xd7, 0xf3, 0x77, 0xb4, 0xb0, 0xfe,
            0x90, 0x38, 0xe2, 0xe0,
        ];
        let iv_as_printed: [u8; 32] = [
            0x5f, 0xe5, 0xd3, 0x03, 0xf4, 0x8b, 0x8d, 0xc5, 0xe7, 0xdd, 0x6d, 0x41, 0x92, 0x17,
            0x4a, 0xf5, 0xfe, 0x6d, 0x52, 0xc6, 0xab, 0xb6, 0xd1, 0x2a, 0x32, 0x5f, 0x02, 0xa2,
            0x8a, 0x2f, 0xd4, 0x91,
        ];
        let randblock: [u8; 128] = [
            0x2c, 0xc7, 0x00, 0x44, 0xd1, 0x3c, 0x3f, 0xa3, 0x76, 0xef, 0xff, 0xbd, 0xc4, 0x79,
            0x4a, 0xe7, 0x87, 0x6a, 0x42, 0x96, 0x57, 0xb5, 0x44, 0x59, 0xff, 0xe8, 0xb8, 0x86,
            0x5c, 0x0c, 0x2d, 0x3a, 0xb7, 0x96, 0xd2, 0x65, 0xf3, 0xb7, 0xd1, 0x41, 0xfe, 0x33,
            0x7c, 0x43, 0xa1, 0x06, 0x76, 0x82, 0x9c, 0x95, 0x78, 0xe0, 0xc9, 0xde, 0x56, 0x9d,
            0xce, 0x6b, 0xe8, 0x75, 0x5c, 0xfe, 0x96, 0x60, 0x24, 0x97, 0xaf, 0xf3, 0x77, 0x73,
            0x45, 0xd8, 0xd2, 0xbe, 0x3c, 0xfc, 0xf4, 0x45, 0xe9, 0x52, 0x75, 0xb6, 0xbe, 0xc9,
            0x62, 0x19, 0xad, 0x86, 0x10, 0x8d, 0xd3, 0x19, 0x19, 0xbb, 0x3f, 0x93, 0xc5, 0xd9,
            0xdf, 0x9d, 0x42, 0x5e, 0xb8, 0x28, 0x53, 0x95, 0xbf, 0x0d, 0x41, 0xf3, 0x7a, 0x2d,
            0x13, 0x62, 0x87, 0x92, 0x8f, 0xd0, 0x73, 0x4f, 0x06, 0xef, 0x2b, 0xe0, 0x1a, 0x4a,
            0x4b, 0xf4,
        ];

        let mut key = key_as_printed;
        key.reverse();
        let mut iv = iv_as_printed;
        iv.reverse();

        let mut expected = randblock;
        for chunk in expected.chunks_exact_mut(8) {
            chunk.reverse();
        }

        let mut actual = [0u8; 128];
        Strumok256::new(&key, &iv).apply_keystream(&mut actual);
        assert_eq!(
            actual, expected,
            "Strumok-256 official letter vector mismatch"
        );
    }

    #[test]
    fn strumok_512() {
        let key_as_printed: [u8; 64] = [
            0x22, 0x23, 0xbe, 0x1b, 0x98, 0xe5, 0x44, 0x50, 0x6a, 0xdb, 0x36, 0x84, 0x4e, 0xe3,
            0xb3, 0xbe, 0xfe, 0x33, 0x30, 0xfe, 0x0c, 0xf7, 0x16, 0x5c, 0x83, 0xa5, 0x05, 0x26,
            0xd8, 0x69, 0x84, 0xe8, 0x24, 0x2d, 0x25, 0x94, 0x8a, 0xf1, 0x0e, 0xf7, 0x24, 0xd7,
            0x6d, 0x63, 0x5d, 0x57, 0x5d, 0x49, 0x3f, 0x61, 0xf5, 0x32, 0x30, 0x1a, 0x5a, 0xd9,
            0xf3, 0xf0, 0x84, 0x5a, 0xc4, 0xc3, 0x95, 0x59,
        ];
        // Same IV as the 256-bit case (letter reuses it for both variants) - a free consistency
        // check that the transcription above is faithful.
        let iv_as_printed: [u8; 32] = [
            0x5f, 0xe5, 0xd3, 0x03, 0xf4, 0x8b, 0x8d, 0xc5, 0xe7, 0xdd, 0x6d, 0x41, 0x92, 0x17,
            0x4a, 0xf5, 0xfe, 0x6d, 0x52, 0xc6, 0xab, 0xb6, 0xd1, 0x2a, 0x32, 0x5f, 0x02, 0xa2,
            0x8a, 0x2f, 0xd4, 0x91,
        ];
        let randblock: [u8; 128] = [
            0x09, 0x5f, 0x5e, 0x46, 0xff, 0xbe, 0xd7, 0x47, 0xc0, 0x09, 0x00, 0xaf, 0x9d, 0x6e,
            0x9b, 0xa4, 0x40, 0x22, 0xdb, 0xab, 0x76, 0xba, 0x68, 0xc8, 0x9c, 0xc2, 0xf4, 0x59,
            0x03, 0x79, 0x32, 0xe7, 0xfa, 0x66, 0x7f, 0x6d, 0x79, 0xe3, 0x8d, 0x24, 0x85, 0x3c,
            0x22, 0x28, 0xda, 0xe7, 0x84, 0xff, 0x77, 0xbb, 0x4f, 0x0b, 0x6a, 0x56, 0x31, 0x8f,
            0x8f, 0xee, 0xc9, 0x6a, 0x80, 0x60, 0x0c, 0x1a, 0x14, 0x97, 0x4d, 0x7b, 0x50, 0xc8,
            0x73, 0x25, 0x67, 0xcb, 0xc6, 0x32, 0x3d, 0x8c, 0x96, 0xde, 0x88, 0x18, 0x7c, 0x0b,
            0xda, 0xaf, 0x60, 0xc7, 0x8a, 0xe9, 0xbf, 0x18, 0xe2, 0xe8, 0x55, 0x08, 0xd4, 0x3b,
            0x89, 0x47, 0x5f, 0xe4, 0x1b, 0x1b, 0x96, 0x82, 0xf2, 0xcf, 0xad, 0xea, 0x2a, 0xf4,
            0xe9, 0xd3, 0x39, 0x3b, 0xa6, 0x85, 0x3e, 0x69, 0xa5, 0x14, 0xd6, 0xdc, 0x4c, 0xea,
            0x4e, 0xa7,
        ];

        let mut key = key_as_printed;
        key.reverse();
        let mut iv = iv_as_printed;
        iv.reverse();

        let mut expected = randblock;
        for chunk in expected.chunks_exact_mut(8) {
            chunk.reverse();
        }

        let mut actual = [0u8; 128];
        Strumok512::new(&key, &iv).apply_keystream(&mut actual);
        assert_eq!(
            actual, expected,
            "Strumok-512 official letter vector mismatch"
        );
    }
}

/// Verifies `hazmat::strumok` directly against ДСТУ 8845:2019's own Додаток Д "Приклади для
/// перевіряння" (the standard's worked examples, с.22-23 for the 256-bit cases and с.35-36 for
/// the 512-bit ones) - a genuine library scan obtained via the National Library of Ukraine's EDD
/// service (docs/DECISIONS.md D-197), not the UAPKI/outspace-derived vectors this file's other
/// tests use. Every hex word below is transcribed exactly as printed (K3..K0/K7..K0, IV3..IV0,
/// Z0..Z7, each a 16-hex-digit word) - the byte-order transform is applied in code, not baked
/// into the literals: word order is reversed to ascending (K0..K3/K0..K7, IV0..IV3) for key/IV
/// (Annex Д labels these by descending significance, same convention D-104 already found for the
/// official letter's Key/IV) and each word's own bytes are independently reversed for every one
/// of key, IV, and keystream words alike (same convention D-104 found for RandBlock) - re-derived
/// and re-confirmed for this annex independently, not assumed to carry over from the letter
/// (D-163's "a convention found once still needs re-checking each new occurrence" rule).
/// Transcription itself was cross-checked against `tests/vectors/strumok/keystream-{256,512}.json`
/// (D-197) rather than trusted by eye alone - a genuine misreading of case 3's `Z4` word (an extra
/// `e`, `b22eee96...` misread as `b22eeee96...`) was caught exactly this way, not by re-reading
/// the scan a second time.
mod official_annex_d_vectors {
    use super::*;

    fn word_bytes(word: &str) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&word[i * 2..i * 2 + 2], 16)
                .expect("valid hex digit in Annex Д transcription");
        }
        bytes.reverse();
        bytes
    }

    macro_rules! annex_d_test_256 {
        ($name:ident, $citation:literal, [$k3:literal, $k2:literal, $k1:literal, $k0:literal], [$iv3:literal, $iv2:literal, $iv1:literal, $iv0:literal], [$z0:literal, $z1:literal, $z2:literal, $z3:literal, $z4:literal, $z5:literal, $z6:literal, $z7:literal]) => {
            #[test]
            fn $name() {
                let mut key = [0u8; 32];
                for (i, w) in [$k0, $k1, $k2, $k3].into_iter().enumerate() {
                    key[i * 8..i * 8 + 8].copy_from_slice(&word_bytes(w));
                }
                let mut iv = [0u8; 32];
                for (i, w) in [$iv0, $iv1, $iv2, $iv3].into_iter().enumerate() {
                    iv[i * 8..i * 8 + 8].copy_from_slice(&word_bytes(w));
                }
                let mut expected = [0u8; 64];
                for (i, w) in [$z0, $z1, $z2, $z3, $z4, $z5, $z6, $z7]
                    .into_iter()
                    .enumerate()
                {
                    expected[i * 8..i * 8 + 8].copy_from_slice(&word_bytes(w));
                }
                let mut actual = [0u8; 64];
                Strumok256::new(&key, &iv).apply_keystream(&mut actual);
                assert_eq!(actual, expected, concat!("ДСТУ 8845:2019 ", $citation));
            }
        };
    }

    macro_rules! annex_d_test_512 {
        ($name:ident, $citation:literal, [$k7:literal, $k6:literal, $k5:literal, $k4:literal, $k3:literal, $k2:literal, $k1:literal, $k0:literal], [$iv3:literal, $iv2:literal, $iv1:literal, $iv0:literal], [$z0:literal, $z1:literal, $z2:literal, $z3:literal, $z4:literal, $z5:literal, $z6:literal, $z7:literal]) => {
            #[test]
            fn $name() {
                let mut key = [0u8; 64];
                for (i, w) in [$k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7]
                    .into_iter()
                    .enumerate()
                {
                    key[i * 8..i * 8 + 8].copy_from_slice(&word_bytes(w));
                }
                let mut iv = [0u8; 32];
                for (i, w) in [$iv0, $iv1, $iv2, $iv3].into_iter().enumerate() {
                    iv[i * 8..i * 8 + 8].copy_from_slice(&word_bytes(w));
                }
                let mut expected = [0u8; 64];
                for (i, w) in [$z0, $z1, $z2, $z3, $z4, $z5, $z6, $z7]
                    .into_iter()
                    .enumerate()
                {
                    expected[i * 8..i * 8 + 8].copy_from_slice(&word_bytes(w));
                }
                let mut actual = [0u8; 64];
                Strumok512::new(&key, &iv).apply_keystream(&mut actual);
                assert_eq!(actual, expected, concat!("ДСТУ 8845:2019 ", $citation));
            }
        };
    }

    annex_d_test_256!(
        strumok_256_case_1,
        "Додаток Д.1.1, с.22, приклад 1",
        [
            "8000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000"
        ],
        [
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000"
        ],
        [
            "e442d15345dc66ca",
            "f47d700ecc66408a",
            "b4cb284b5477e641",
            "a2afc9092e4124b0",
            "728e5fa26b11a7d9",
            "e6a7b9288c68f972",
            "70eb3606de8ba44c",
            "aced7956bd3e3de7"
        ]
    );

    annex_d_test_256!(
        strumok_256_case_2,
        "Додаток Д.1.1, с.22, приклад 2",
        [
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa"
        ],
        [
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000"
        ],
        [
            "a7510b38c7a95d1d",
            "cd5ea28a15b8654f",
            "c5e2e2771d0373b2",
            "98ae829686d5fcee",
            "45bddf65c523dbb8",
            "32a93fcdd950001f",
            "752a7fb588af8c51",
            "9de92736664212d4"
        ]
    );

    annex_d_test_256!(
        strumok_256_case_3,
        "Додаток Д.1.1, с.23, приклад 3",
        [
            "8000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000"
        ],
        [
            "0000000000000004",
            "0000000000000003",
            "0000000000000002",
            "0000000000000001"
        ],
        [
            "fe44a2508b5a2acd",
            "af355b4ed21d2742",
            "dcd7fdd6a57a9e71",
            "5d267bd2739fb5eb",
            "b22eee96b2832072",
            "c7de6a4cdaa9a847",
            "72d5da93812680f2",
            "4a0acb7e93da2ce0"
        ]
    );

    annex_d_test_256!(
        strumok_256_case_4,
        "Додаток Д.1.1, с.23, приклад 4",
        [
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa"
        ],
        [
            "0000000000000004",
            "0000000000000003",
            "0000000000000002",
            "0000000000000001"
        ],
        [
            "e6d0efd9cea5abcd",
            "1e78ba1a9b0e401e",
            "bcfbea2c02ba0781",
            "1bd375588ae08794",
            "5493cf21e114c209",
            "66cd5d7cc7d0e69a",
            "a5cdb9f3380d07fa",
            "2940d61a4d4e9ce4"
        ]
    );

    annex_d_test_512!(
        strumok_512_case_1,
        "Додаток Д.2.1, с.35, приклад 1",
        [
            "8000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000"
        ],
        [
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000"
        ],
        [
            "f5b9ab51100f8317",
            "898ef2086a4af395",
            "59571fecb5158d0b",
            "b7c45b6744c71fbb",
            "ff2efcf05d8d8db9",
            "7a585871e5c419c0",
            "6b5c4691b9125e71",
            "a55be7d2b358ec6e"
        ]
    );

    annex_d_test_512!(
        strumok_512_case_2,
        "Додаток Д.2.1, с.35, приклад 2",
        [
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa"
        ],
        [
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000"
        ],
        [
            "d2a6103c50bd4e04",
            "dc6a21af5eb13b73",
            "df4ca6cb07797265",
            "f453c253d8d01876",
            "039a64dc7a01800c",
            "688ce327dccb7e84",
            "41e0250b5e526403",
            "9936e478aa200f22"
        ]
    );

    annex_d_test_512!(
        strumok_512_case_3,
        "Додаток Д.2.1, с.36, приклад 3",
        [
            "8000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000"
        ],
        [
            "0000000000000004",
            "0000000000000003",
            "0000000000000002",
            "0000000000000001"
        ],
        [
            "cca12eae8133aaaa",
            "528d85507ce8501d",
            "da83c7fe3e1823f1",
            "21416ebf63b71a42",
            "26d76d2bf1a625eb",
            "eec66ee0cd0b1efc",
            "02dd68f338a345a8",
            "47538790a5411adb"
        ]
    );

    annex_d_test_512!(
        strumok_512_case_4,
        "Додаток Д.2.1, с.36, приклад 4",
        [
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaa"
        ],
        [
            "0000000000000004",
            "0000000000000003",
            "0000000000000002",
            "0000000000000001"
        ],
        [
            "965648e775c717d5",
            "a63c2a7376e92df3",
            "0b0eb0bbd47ca267",
            "ea593d979ae5bd39",
            "d773b5e5193cafe1",
            "b0a26671d259422b",
            "85b2aa326b280156",
            "511ace6451435f0c"
        ]
    );
}
