//! Tests for `crypto_pwhash::passphrase_file` (T-269, D-219's container moved into the core). No
//! oracle exists for the 28-byte header - it is this project's own format; `derive_key` has its own
//! (libsodium, `crypto_pwhash.rs`). The shared vectors are compat pins written by the released
//! 0.6.0 `uacrypt`. Argon2 here is 256 MiB, t=3 per run, so only four tests run it; every header
//! refusal stops before Argon2 and also runs under Miri.

#![cfg(feature = "pwhash")]

use dstu_core::crypto_pwhash::passphrase_file::{
    seal_stream, Header, PassphraseFileError, CONTAINER_TYPE, HEADER_BYTES,
    SEAL_STREAM_PREFIX_BYTES,
};
use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, FileError, CHUNK_BYTES, FILE_PREFIX_BYTES, MAX_RECORD_BYTES,
};

const VECTORS: &str = include_str!("vectors/pwhash/passphrase_file.json");

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

fn number(line: &str, key: &str) -> usize {
    let pattern = format!("\"{key}\": ");
    line.split(&pattern)
        .nth(1)
        .unwrap()
        .split([',', '}'])
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + 7) as u8).collect()
}

fn header_of(file: &[u8]) -> &[u8; HEADER_BYTES] {
    file[..HEADER_BYTES].try_into().unwrap()
}

/// The reader contract: read exactly `next_len()` bytes; at EOF before that many, `finish()`.
fn drain(mut dec: FileDecryptor, stream: &[u8]) -> Result<Vec<u8>, FileError> {
    let mut out = vec![0u8; CHUNK_BYTES];
    let mut plaintext = Vec::new();
    let mut pos = 0;
    loop {
        let want = dec.next_len();
        if stream.len() - pos < want {
            let n = dec.finish(&mut out)?;
            plaintext.extend_from_slice(&out[..n]);
            return Ok(plaintext);
        }
        let n = dec.feed(&stream[pos..pos + want], &mut out)?;
        pos += want;
        plaintext.extend_from_slice(&out[..n]);
    }
}

fn seal_all(mut enc: FileEncryptor, prefix: &[u8], plaintext: &[u8]) -> Vec<u8> {
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

#[derive(Debug, PartialEq)]
enum Outcome {
    Ok(Vec<u8>),
    Truncated,
    NotPassphraseFile,
    UnsupportedFormat,
    UnsupportedParams,
    InvalidCiphertext,
}

fn open_file(passphrase: &[u8], file: &[u8]) -> Outcome {
    if file.len() < HEADER_BYTES {
        return Outcome::Truncated;
    }
    let header = match Header::parse(header_of(file)) {
        Ok(h) => h,
        Err(PassphraseFileError::NotPassphraseFile) => return Outcome::NotPassphraseFile,
        Err(PassphraseFileError::UnsupportedFormat { .. }) => return Outcome::UnsupportedFormat,
        Err(PassphraseFileError::UnsupportedParams { .. }) => return Outcome::UnsupportedParams,
        Err(e) => panic!("unexpected header error {e:?}"),
    };
    let dec = header.open_stream(passphrase).unwrap();
    match drain(dec, &file[HEADER_BYTES..]) {
        Ok(p) => Outcome::Ok(p),
        Err(FileError::Auth) => Outcome::InvalidCiphertext,
        Err(FileError::Truncated) => Outcome::Truncated,
        Err(e) => panic!("unexpected stream error {e:?}"),
    }
}

fn cases(argon2: bool) -> Vec<&'static str> {
    VECTORS
        .lines()
        .filter(|l| l.contains("\"name\": "))
        .filter(|l| l.contains(&format!("\"argon2\": {argon2}")))
        .collect()
}

fn check_case(line: &str) {
    let name = field(line, "name");
    let passphrase = decode_hex(field(line, "passphrase_hex"));
    let file = decode_hex(field(line, "sealed_hex"));
    let expected = match field(line, "expect") {
        "ok" => Outcome::Ok(pattern(number(line, "plaintext_len"))),
        "truncated" => Outcome::Truncated,
        "not_passphrase_file" => Outcome::NotPassphraseFile,
        "unsupported_format" => Outcome::UnsupportedFormat,
        "unsupported_params" => Outcome::UnsupportedParams,
        "invalid_ciphertext" => Outcome::InvalidCiphertext,
        other => panic!("{name}: unknown expect {other}"),
    };
    assert_eq!(open_file(&passphrase, &file), expected, "{name}");
}

#[test]
fn constants_match_the_wire_format() {
    assert_eq!(CONTAINER_TYPE, 0x50);
    assert_eq!(HEADER_BYTES, 28);
    assert_eq!(SEAL_STREAM_PREFIX_BYTES, HEADER_BYTES + FILE_PREFIX_BYTES);
    assert_eq!(number(VECTORS, "header_bytes"), HEADER_BYTES);
}

/// Every header-level case of the shared vectors is refused before Argon2 runs.
#[test]
fn shared_header_vectors_are_refused_without_argon2() {
    let refused = cases(false);
    assert_eq!(refused.len(), 6);
    for line in refused {
        check_case(line);
    }
}

/// The 0.6.0 `uacrypt` files open (valid), and a wrong passphrase or a flipped tag bit fails.
#[test]
#[cfg_attr(miri, ignore = "four Argon2id runs at 256 MiB")]
fn shared_vectors_written_by_uacrypt_0_6_0_give_their_expected_outcome() {
    let argon2 = cases(true);
    assert_eq!(argon2.len(), 4);
    for line in argon2 {
        check_case(line);
    }
}

/// Round trip across a record boundary, and the prefix is the header plus a stream-file prefix.
#[test]
#[cfg_attr(miri, ignore = "Argon2id at 256 MiB")]
fn seal_stream_round_trips_and_writes_a_parsable_header() {
    let message = pattern(CHUNK_BYTES + 1);
    let (enc, prefix) = seal_stream(b"pw").unwrap();
    assert_eq!(prefix[0], CONTAINER_TYPE);
    let file = seal_all(enc, &prefix, &message);
    assert_eq!(open_file(b"pw", &file), Outcome::Ok(message));
}

#[test]
fn an_empty_passphrase_is_refused_on_both_sides() {
    assert!(matches!(
        seal_stream(b""),
        Err(PassphraseFileError::EmptyPassphrase)
    ));
    let line = cases(true)[0];
    let file = decode_hex(field(line, "sealed_hex"));
    let header = Header::parse(header_of(&file)).unwrap();
    assert!(matches!(
        header.open_stream(b""),
        Err(PassphraseFileError::EmptyPassphrase)
    ));
}

/// A header refusal names what it saw, and only the preset `seal_stream` writes is accepted:
/// a reader never runs Argon2 with costs taken from an untrusted file (D-219).
#[test]
fn header_refusals_carry_the_values_they_refused() {
    let line = cases(true)[0];
    let good = *header_of(&decode_hex(field(line, "sealed_hex")));
    assert!(Header::parse(&good).is_ok());

    let mut interactive = good;
    interactive[3..7].copy_from_slice(&65_536u32.to_le_bytes());
    interactive[7..11].copy_from_slice(&2u32.to_le_bytes());
    assert!(matches!(
        Header::parse(&interactive),
        Err(PassphraseFileError::UnsupportedParams {
            m_cost: 65_536,
            t_cost: 2,
            p_cost: 1
        })
    ));

    let mut kdf = good;
    kdf[2] = 0x07;
    assert!(matches!(
        Header::parse(&kdf),
        Err(PassphraseFileError::UnsupportedFormat {
            version: 0x01,
            kdf: 0x07
        })
    ));

    let mut stream = good;
    stream[0] = 0x02;
    assert!(matches!(
        Header::parse(&stream),
        Err(PassphraseFileError::NotPassphraseFile)
    ));
}

/// Two seals of the same passphrase use different salts, so their headers differ.
#[test]
#[cfg_attr(miri, ignore = "two Argon2id runs at 256 MiB")]
fn each_seal_draws_a_fresh_salt() {
    let (_, a) = seal_stream(b"same").unwrap();
    let (_, b) = seal_stream(b"same").unwrap();
    assert_ne!(a[..HEADER_BYTES], b[..HEADER_BYTES]);
    assert_eq!(a[..12], b[..12], "everything but the salt is fixed");
}
