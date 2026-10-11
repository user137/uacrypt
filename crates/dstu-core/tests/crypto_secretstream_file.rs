//! Tests for the stream-file codec `crypto_secretstream::{FileEncryptor, FileDecryptor}` (T-284,
//! D-208's format): the one implementation of the framing that `uacrypt` and every binding drive.
//! No oracle exists for this construction (D-68); the shared vectors (D-208, T-277) are the
//! cross-reader pin, plus round trips, an independent decode with the raw `PullState`, and misuse.

#![cfg(feature = "std")]

use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, FileError, Key, PullState, Tag, CHUNK_BYTES, FILE_PREFIX_BYTES,
    FORMAT_VERSION, MAX_RECORD_BYTES, RECORD_OVERHEAD_BYTES,
};
use proptest::prelude::*;

const VECTORS: &str = include_str!("vectors/secretstream-file/v2.json");

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn field<'a>(text: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = text.find(&pattern).unwrap() + pattern.len();
    let end = start + text[start..].find('"').unwrap();
    &text[start..end]
}

fn vector_key() -> Key {
    Key::from_bytes(decode_hex(field(VECTORS, "key_hex")).try_into().unwrap())
}

/// The reader contract every consumer follows: read exactly `next_len()` bytes; at EOF before
/// that many, call `finish()`.
fn decrypt_all(key: &Key, file: &[u8]) -> Result<Vec<u8>, FileError> {
    let mut dec = FileDecryptor::new(key);
    let mut out = vec![0u8; CHUNK_BYTES];
    let mut plaintext = Vec::new();
    let mut pos = 0;
    loop {
        let want = dec.next_len();
        if file.len() - pos < want {
            let n = dec.finish(&mut out)?;
            plaintext.extend_from_slice(&out[..n]);
            return Ok(plaintext);
        }
        let n = dec.feed(&file[pos..pos + want], &mut out)?;
        pos += want;
        plaintext.extend_from_slice(&out[..n]);
    }
}

/// The writer contract: full chunks as non-final records, the last `<= CHUNK_BYTES` bytes
/// (a full chunk for an exact multiple, nothing for empty input) as `Final`.
fn encrypt_all(key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let (mut enc, prefix) = FileEncryptor::init(key).unwrap();
    let mut file = prefix.to_vec();
    let mut rest = plaintext;
    let mut record = [0u8; MAX_RECORD_BYTES];
    while rest.len() > CHUNK_BYTES {
        let (chunk, tail) = rest.split_at(CHUNK_BYTES);
        enc.seal_chunk(chunk.try_into().unwrap(), &mut record)
            .unwrap();
        file.extend_from_slice(&record);
        rest = tail;
    }
    let n = enc.seal_final(rest, &mut record).unwrap();
    file.extend_from_slice(&record[..n]);
    file
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + 7) as u8).collect()
}

#[test]
fn constants_match_the_wire_format() {
    assert_eq!(CHUNK_BYTES, 8192);
    assert_eq!(FILE_PREFIX_BYTES, 1 + 32);
    assert_eq!(RECORD_OVERHEAD_BYTES, 1 + 4 + 16);
    assert_eq!(MAX_RECORD_BYTES, CHUNK_BYTES + RECORD_OVERHEAD_BYTES);
}

#[test]
fn every_shared_vector_decrypts_or_fails_with_its_class() {
    let key = vector_key();
    let mut count = 0;
    for line in VECTORS
        .lines()
        .filter(|l| l.trim_start().starts_with("{\"name\""))
    {
        count += 1;
        let name = field(line, "name");
        let expect = field(line, "expect");
        let result = decrypt_all(&key, &decode_hex(field(line, "file_hex")));
        match expect {
            "ok" => assert_eq!(
                result.unwrap(),
                decode_hex(field(line, "plaintext_hex")),
                "{name}"
            ),
            other => {
                let err = result.expect_err(name);
                let class_ok = match other {
                    "unsupported_version" => matches!(err, FileError::UnsupportedVersion(_)),
                    "bad_chunk_length" => matches!(err, FileError::BadChunkLength(_)),
                    "truncated" => matches!(err, FileError::Truncated),
                    "auth" => matches!(err, FileError::Auth),
                    "trailing_data" => matches!(err, FileError::TrailingData),
                    "oversized_chunk" => matches!(err, FileError::ChunkTooLarge(_)),
                    "unknown_tag" => matches!(err, FileError::UnknownTag),
                    unknown => panic!("unknown expect value {unknown}"),
                };
                assert!(class_ok, "{name}: expected {other}, got {err:?}");
            }
        }
    }
    assert_eq!(count, 15, "fixture is incomplete");
}

#[test]
fn error_messages_carry_the_shared_phrases() {
    let cases = [
        (
            FileError::UnsupportedVersion(3),
            "unsupported stream format version",
        ),
        (FileError::Truncated, "truncated"),
        (
            FileError::ChunkTooLarge(u32::MAX),
            "chunk too large: declared 4294967295 bytes",
        ),
        (
            FileError::BadChunkLength(100),
            "non-final chunk of 100 bytes",
        ),
        (FileError::UnknownTag, "unrecognized chunk tag"),
        (FileError::TrailingData, "trailing data"),
        (FileError::Auth, "authentication failed"),
    ];
    for (err, phrase) in cases {
        assert!(err.to_string().contains(phrase), "{err}");
    }
}

#[test]
fn round_trips_at_the_chunk_boundaries() {
    let key = Key::generate().unwrap();
    for len in [
        0,
        1,
        CHUNK_BYTES - 1,
        CHUNK_BYTES,
        CHUNK_BYTES + 1,
        3 * CHUNK_BYTES,
        3 * CHUNK_BYTES + 5,
    ] {
        let plaintext = pattern(len);
        let file = encrypt_all(&key, &plaintext);
        assert_eq!(decrypt_all(&key, &file).unwrap(), plaintext, "len {len}");
    }
}

#[test]
fn an_exact_multiple_ends_in_a_full_final_record() {
    let key = Key::generate().unwrap();
    let file = encrypt_all(&key, &pattern(2 * CHUNK_BYTES));
    assert_eq!(file.len(), FILE_PREFIX_BYTES + 2 * MAX_RECORD_BYTES);
    assert_eq!(
        file[FILE_PREFIX_BYTES + MAX_RECORD_BYTES],
        Tag::Final.to_byte()
    );
}

/// A second, independent decoder over the raw `PullState`: the codec writes exactly D-208's
/// format, not something only the codec itself reads back.
#[test]
fn encryptor_output_decodes_with_the_raw_pull_state() {
    let key = Key::generate().unwrap();
    let plaintext = pattern(CHUNK_BYTES + 100);
    let file = encrypt_all(&key, &plaintext);
    assert_eq!(file[0], FORMAT_VERSION);
    let mut pull = PullState::init(&key, file[1..33].try_into().unwrap());
    let mut pos = FILE_PREFIX_BYTES;
    let mut decoded = Vec::new();
    loop {
        let tag_byte = file[pos];
        let len = u32::from_le_bytes(file[pos + 1..pos + 5].try_into().unwrap()) as usize;
        let ct = &file[pos + 5..pos + 5 + len];
        let auth = &file[pos + 5 + len..pos + 5 + len + 16];
        let mut out = vec![0u8; len];
        let tag = pull.pull(tag_byte, ct, auth, &mut out).unwrap();
        decoded.extend_from_slice(&out);
        pos += 5 + len + 16;
        if tag == Tag::Final {
            break;
        }
    }
    assert_eq!(pos, file.len());
    assert_eq!(decoded, plaintext);
}

#[test]
fn trailing_data_never_releases_the_final_plaintext() {
    let key = Key::generate().unwrap();
    let file = encrypt_all(&key, b"last chunk");
    let mut dec = FileDecryptor::new(&key);
    let mut out = vec![0u8; CHUNK_BYTES];
    let mut pos = 0;
    while pos < file.len() {
        let want = dec.next_len();
        assert_eq!(dec.feed(&file[pos..pos + want], &mut out).unwrap(), 0);
        pos += want;
    }
    assert_eq!(dec.next_len(), 1);
    assert!(matches!(
        dec.feed(&[0], &mut out),
        Err(FileError::TrailingData)
    ));
    assert!(
        dec.finish(&mut out).is_err(),
        "a failed decryptor stays failed"
    );
}

#[test]
fn finish_before_final_is_truncated() {
    let key = Key::generate().unwrap();
    let mut dec = FileDecryptor::new(&key);
    let mut out = vec![0u8; CHUNK_BYTES];
    assert!(matches!(dec.finish(&mut out), Err(FileError::Truncated)));
}

#[test]
fn feed_with_a_length_other_than_next_len_is_a_caller_error() {
    let key = Key::generate().unwrap();
    let file = encrypt_all(&key, b"x");
    let mut dec = FileDecryptor::new(&key);
    let mut out = vec![0u8; CHUNK_BYTES];
    assert_eq!(dec.next_len(), 1);
    assert!(matches!(
        dec.feed(&file[..2], &mut out),
        Err(FileError::InvalidLength)
    ));
    assert!(matches!(
        dec.feed(&[], &mut out),
        Err(FileError::InvalidLength)
    ));
}

#[test]
fn a_short_plaintext_buffer_is_rejected_before_any_work() {
    let key = Key::generate().unwrap();
    let file = encrypt_all(&key, &pattern(2 * CHUNK_BYTES));
    let mut dec = FileDecryptor::new(&key);
    let mut small = vec![0u8; CHUNK_BYTES - 1];
    assert!(matches!(
        dec.feed(&file[..1], &mut small),
        Err(FileError::InvalidLength)
    ));
}

#[test]
fn calls_after_finish_are_refused() {
    let key = Key::generate().unwrap();
    let file = encrypt_all(&key, b"done");
    let mut dec = FileDecryptor::new(&key);
    let mut out = vec![0u8; CHUNK_BYTES];
    let mut pos = 0;
    while pos < file.len() {
        let want = dec.next_len();
        dec.feed(&file[pos..pos + want], &mut out).unwrap();
        pos += want;
    }
    assert_eq!(dec.finish(&mut out).unwrap(), 4);
    assert_eq!(&out[..4], b"done");
    assert_eq!(dec.next_len(), 0);
    assert!(matches!(dec.finish(&mut out), Err(FileError::Finished)));
    assert!(matches!(dec.feed(&[], &mut out), Err(FileError::Finished)));
}

#[test]
fn a_failed_decryptor_stays_failed() {
    let key = Key::generate().unwrap();
    let mut file = encrypt_all(&key, &pattern(2 * CHUNK_BYTES));
    file[FILE_PREFIX_BYTES + 10] ^= 1;
    let mut dec = FileDecryptor::new(&key);
    let mut out = vec![0u8; CHUNK_BYTES];
    let mut pos = 0;
    let err = loop {
        let want = dec.next_len();
        match dec.feed(&file[pos..pos + want], &mut out) {
            Ok(_) => pos += want,
            Err(e) => break e,
        }
    };
    assert!(matches!(err, FileError::Auth));
    assert_eq!(dec.next_len(), 0);
    assert!(matches!(dec.feed(&[], &mut out), Err(FileError::Finished)));
    assert!(matches!(dec.finish(&mut out), Err(FileError::Finished)));
}

#[test]
fn seal_final_rejects_misuse() {
    let key = Key::generate().unwrap();
    let (mut enc, _) = FileEncryptor::init(&key).unwrap();
    let mut out = [0u8; MAX_RECORD_BYTES + 1];
    assert!(matches!(
        enc.seal_final(&[0u8; CHUNK_BYTES + 1], &mut out),
        Err(FileError::InvalidLength)
    ));
    let mut short = [0u8; RECORD_OVERHEAD_BYTES + 3];
    assert!(matches!(
        enc.seal_final(&[0u8; 4], &mut short),
        Err(FileError::InvalidLength)
    ));
    assert_eq!(
        enc.seal_final(&[0u8; 4], &mut out).unwrap(),
        4 + RECORD_OVERHEAD_BYTES
    );
    assert!(matches!(
        enc.seal_final(&[], &mut out),
        Err(FileError::Finished)
    ));
    let mut record = [0u8; MAX_RECORD_BYTES];
    assert!(matches!(
        enc.seal_chunk(&[0u8; CHUNK_BYTES], &mut record),
        Err(FileError::Finished)
    ));
}

#[test]
fn a_wrong_key_fails_authentication() {
    let file = encrypt_all(&Key::generate().unwrap(), b"secret");
    assert!(matches!(
        decrypt_all(&Key::generate().unwrap(), &file),
        Err(FileError::Auth)
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn any_length_round_trips(len in 0usize..(3 * CHUNK_BYTES + 64)) {
        let key = Key::generate().unwrap();
        let plaintext = pattern(len);
        let file = encrypt_all(&key, &plaintext);
        prop_assert_eq!(decrypt_all(&key, &file).unwrap(), plaintext);
    }

    /// Cutting a valid file anywhere short of its end is always `Truncated`, never accepted.
    #[test]
    fn any_cut_is_truncated(len in 0usize..(2 * CHUNK_BYTES + 64), cut_seed in any::<u32>()) {
        let key = Key::generate().unwrap();
        let file = encrypt_all(&key, &pattern(len));
        let cut = cut_seed as usize % file.len();
        prop_assert!(matches!(decrypt_all(&key, &file[..cut]), Err(FileError::Truncated)));
    }
}
