//! Shared by the `open`/`verify` targets (T-223/T-225): the 2026-09-22 audit's negative property -
//! a modified, extended or truncated blob never opens unless it is byte-identical to the original.
//! A crash-only target could not have found F-01. Each target pins a fixed, deterministic
//! original, so a finding reproduces and minimizes.

// Each target includes this file and uses only the helpers its fixture needs.
#![allow(dead_code)]

/// Derives a candidate that always differs from `original` (non-empty): `data[0] % 4` picks the
/// edit, the rest of `data` is its operand - (0) XOR one byte with a non-zero value, (1) truncate,
/// (2) append, (3) insert. `None` for empty `data`.
pub fn mutate(original: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let (&op, rest) = data.split_first()?;
    let pos = |n: usize| {
        rest.iter().fold(0usize, |acc, &b| {
            acc.wrapping_mul(131).wrapping_add(usize::from(b))
        }) % n
    };
    let operand: &[u8] = if rest.is_empty() { &[0] } else { rest };
    let mut candidate = original.to_vec();
    match op % 4 {
        0 => {
            let at = pos(candidate.len());
            candidate[at] ^= operand[0].max(1);
        }
        1 => candidate.truncate(pos(candidate.len())),
        2 => candidate.extend_from_slice(operand),
        _ => {
            let at = pos(candidate.len() + 1);
            candidate.splice(at..at, operand.iter().copied());
        }
    }
    Some(candidate)
}

/// The negative property for an `open`: success only for the original, and then its plaintext.
pub fn check_open<E>(
    candidate: &[u8],
    original: &[u8],
    plaintext: &[u8],
    result: Result<Vec<u8>, E>,
) {
    match result {
        Ok(opened) => {
            assert!(
                candidate == original,
                "a modified blob ({} bytes) opened",
                candidate.len()
            );
            assert!(
                opened == plaintext,
                "the original opened to the wrong plaintext"
            );
        }
        Err(_) => assert!(candidate != original, "the original blob did not open"),
    }
}

/// `(i * 31 + 7) mod 256` - the plaintext every shared box/stream vector seals.
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 256) as u8).collect()
}

pub fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex in a pinned vector"))
        .collect()
}

/// The string value of `"key": "..."`, first occurrence in `text`.
pub fn field<'a>(text: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = text.find(&pattern).expect("field in a pinned vector") + pattern.len();
    &text[start..start + text[start..].find('"').expect("closing quote")]
}

/// `box/v3.json`'s `valid_8193` case at `curve` (two stream records): secret key bytes, sealed
/// blob, plaintext.
pub fn box_fixture(vectors: &str, curve: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let key = decode_hex(field(vectors, &format!("box{curve}_secret_key_hex")));
    let marker = format!("\"curve\": {curve}, \"name\": \"valid_8193\"");
    let line = vectors
        .lines()
        .find(|l| l.contains(&marker))
        .expect("valid_8193 case");
    (key, decode_hex(field(line, "sealed_hex")), pattern(8193))
}
