//! Runtime known-answer self-test (`docs/TASKS.md` T-161, `docs/DECISIONS.md` D-117): re-runs one
//! official vector per primitive against the *live compiled* implementation, so a caller can verify
//! their exact installed build produces correct output on their exact platform before trusting it
//! with real data - the same "don't just trust it compiled" instinct this project already applies
//! to itself via dual-oracle verification (`docs/SECURITY.md`, "Crypto engineering hard
//! constraints"). This is a small, fast, embedded-in-the-binary spot check - one vector per
//! primitive, not the full corpus `cargo test` already runs against `tests/vectors/`; it is not a
//! substitute for that suite.
//!
//! Built once here; every language binding wraps this one function with an idiomatically-named
//! thin wrapper (`dstu_core.selftest()` in Python, `selfTest()` in Node/Java/.NET, `dstu_selftest()`
//! in the C ABI) rather than reimplementing its own KAT check per language - see D-117, following
//! the precedent of `hazmat::tables`' shared S-box/MDS data being built once and reused rather than
//! duplicated per algorithm (`docs/DECISIONS.md` D-10).
//!
//! Requires the `selftest` Cargo feature (which requires `std`, D-48's precedent): vector text is
//! embedded via `include_str!` and parsed at runtime with a small hand-rolled string scanner (no
//! `serde` dependency, matching every other test-vector reader in this crate's `tests/` suite),
//! which needs `String`/`Vec`. Off by default in the bare crate; every binding's own `Cargo.toml`
//! turns it on.

use crate::hazmat::dstu4145::curve163::Point;
use crate::hazmat::dstu4145::gf2m163::FieldElement;
use crate::hazmat::dstu4145::signature::verify as dstu4145_verify;
use crate::hazmat::kalyna::Kalyna128_128;
use crate::hazmat::kupyna::Kupyna256;
use crate::hazmat::strumok::Strumok256;
use std::fmt;

/// A primitive [`run`] checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Primitive {
    Kalyna,
    Kupyna,
    Strumok,
    Dstu4145,
}

impl fmt::Display for Primitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Primitive::Kalyna => "Kalyna",
            Primitive::Kupyna => "Kupyna",
            Primitive::Strumok => "Strumok",
            Primitive::Dstu4145 => "DSTU 4145",
        })
    }
}

/// Why a single primitive's check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The live implementation's output did not match the embedded official vector - a real
    /// correctness failure in this build.
    Mismatch,
    /// The vector text embedded in this binary at compile time could not be parsed. This is an
    /// integrity bug in this crate's own release, not something a caller did - the embedded text is
    /// a fixed file under this crate's own `tests/vectors/`, already read the same way by
    /// `cargo test` every CI run, so this should never fire in a real build.
    MalformedEmbeddedVector,
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FailureKind::Mismatch => "output did not match the official vector",
            FailureKind::MalformedEmbeddedVector => "embedded vector data could not be parsed",
        })
    }
}

/// One primitive's self-test failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub primitive: Primitive,
    pub kind: FailureKind,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.primitive, self.kind)
    }
}

impl std::error::Error for Failure {}

/// Every primitive that failed [`run`]'s check. Never constructed empty - [`run`] returns `Ok(())`
/// instead when nothing failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub failures: Vec<Failure>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dstu_core self-test failed:")?;
        for failure in &self.failures {
            write!(f, " [{failure}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for Report {}

/// Re-runs one official test vector per primitive (Kalyna, Kupyna, Strumok, DSTU 4145) against the
/// live compiled implementation.
///
/// # Errors
///
/// Returns a [`Report`] naming every primitive whose live output didn't match its embedded vector.
/// A non-empty [`Report`] means this exact compiled binary is producing wrong cryptographic output
/// and must not be trusted with real data.
pub fn run() -> Result<(), Report> {
    type Check = (Primitive, fn() -> Result<(), FailureKind>);
    let checks: [Check; 4] = [
        (Primitive::Kalyna, check_kalyna),
        (Primitive::Kupyna, check_kupyna),
        (Primitive::Strumok, check_strumok),
        (Primitive::Dstu4145, check_dstu4145),
    ];

    let failures: Vec<Failure> = checks
        .into_iter()
        .filter_map(|(primitive, check)| check().err().map(|kind| Failure { primitive, kind }))
        .collect();

    if failures.is_empty() {
        Ok(())
    } else {
        Err(Report { failures })
    }
}

fn check_equal(actual: &[u8], expected: &[u8]) -> Result<(), FailureKind> {
    if actual == expected {
        Ok(())
    } else {
        Err(FailureKind::Mismatch)
    }
}

/// Finds the first `"key": "..."` occurrence at or after byte offset `start`, returning its value
/// and the byte offset just past the closing quote (so callers can chain calls to find a *later*
/// occurrence of a key that appears more than once in the same document, e.g. `gf2m163.json`'s
/// `base_point.x`/`public_key_q.x` both using the bare key `"x"`).
fn find_str_value<'a>(json: &'a str, key: &str, start: usize) -> Option<(&'a str, usize)> {
    let pattern = std::format!("\"{key}\": \"");
    let haystack = json.get(start..)?;
    let rel_start = haystack.find(pattern.as_str())?;
    let after = haystack.get(rel_start + pattern.len()..)?;
    let end = after.find('"')?;
    let value = after.get(..end)?;
    let abs_end = start + rel_start + pattern.len() + end + 1;
    Some((value, abs_end))
}

/// Decodes hex into bytes. An odd-length input is treated as missing a leading zero nibble (not
/// rejected) - the same convention `tests/dstu4145_signature.rs`'s own `decode_hex` helper uses,
/// needed because DSTU 4145's GF(2^163) field elements/scalars are sometimes printed one hex digit
/// short of a full byte (the standard's worked example trims the leading zero nibble).
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let owned;
    let hex = if hex.len().is_multiple_of(2) {
        hex
    } else {
        owned = std::format!("0{hex}");
        &owned
    };
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < hex.len() {
        out.push(u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()?);
        i += 2;
    }
    Some(out)
}

fn decode_hex_fixed<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let bytes = decode_hex(hex)?;
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Left-zero-pads a decoded hex value into a fixed-size array - for DSTU 4145's `r`/`s`, whose
/// decoded byte length can be exactly `N` or one short of it depending on the leading nibble (see
/// [`decode_hex`]).
fn decode_hex_padded<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let bytes = decode_hex(hex)?;
    if bytes.len() > N {
        return None;
    }
    let mut out = [0u8; N];
    out[N - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

fn check_kalyna() -> Result<(), FailureKind> {
    const JSON: &str = include_str!("../tests/vectors/kalyna/128-128.json");
    let (key_hex, at) =
        find_str_value(JSON, "key_hex", 0).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (pt_hex, at) =
        find_str_value(JSON, "plaintext_hex", at).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (ct_hex, _) =
        find_str_value(JSON, "ciphertext_hex", at).ok_or(FailureKind::MalformedEmbeddedVector)?;

    let key: [u8; 16] = decode_hex_fixed(key_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let plaintext: [u8; 16] =
        decode_hex_fixed(pt_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let ciphertext: [u8; 16] =
        decode_hex_fixed(ct_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;

    check_equal(&Kalyna128_128::encrypt(&key, &plaintext), &ciphertext)?;
    check_equal(&Kalyna128_128::decrypt(&key, &ciphertext), &plaintext)
}

fn check_kupyna() -> Result<(), FailureKind> {
    const JSON: &str = include_str!("../tests/vectors/kupyna/kupyna-256.json");
    let (msg_hex, at) =
        find_str_value(JSON, "message_hex", 0).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (hash_hex, _) =
        find_str_value(JSON, "hash_hex", at).ok_or(FailureKind::MalformedEmbeddedVector)?;

    let message = decode_hex(msg_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let expected: [u8; 32] =
        decode_hex_fixed(hash_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;

    check_equal(&Kupyna256::digest(&message), &expected)
}

fn check_strumok() -> Result<(), FailureKind> {
    const JSON: &str = include_str!("../tests/vectors/strumok/keystream-256.json");
    let (key_hex, at) =
        find_str_value(JSON, "key_hex", 0).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (iv_hex, at) =
        find_str_value(JSON, "iv_hex", at).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (ks_hex, _) =
        find_str_value(JSON, "keystream_hex", at).ok_or(FailureKind::MalformedEmbeddedVector)?;

    let key: [u8; 32] = decode_hex_fixed(key_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let iv: [u8; 32] = decode_hex_fixed(iv_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let expected = decode_hex(ks_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;

    let mut actual = std::vec![0u8; expected.len()];
    Strumok256::new(&key, &iv).apply_keystream(&mut actual);

    check_equal(&actual, &expected)
}

// `qx_hex`/`qy_hex` (and `qx`/`qy` below) trip `clippy::similar_names` - the same coordinate-pair
// naming `tests/dstu4145_signature.rs` already uses (`qx`/`qy`), a heuristic quirk not a real
// readability problem, same class of documented `#[allow]` CLAUDE.md's agent-discipline notes
// already record for `needless_range_loop`.
#[allow(clippy::similar_names)]
fn check_dstu4145() -> Result<(), FailureKind> {
    const JSON: &str = include_str!("../tests/vectors/dstu4145/gf2m163.json");
    // "x"/"y" appear twice: base_point.{x,y} first, then public_key_q.{x,y} - skip the first pair.
    let (_bp_x, at) = find_str_value(JSON, "x", 0).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (_bp_y, at) = find_str_value(JSON, "y", at).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (qx_hex, at) = find_str_value(JSON, "x", at).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (qy_hex, at) = find_str_value(JSON, "y", at).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (hash_hex, at) =
        find_str_value(JSON, "hash_h_of_t", at).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (r_hex, at) = find_str_value(JSON, "r", at).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let (s_hex, _) = find_str_value(JSON, "s", at).ok_or(FailureKind::MalformedEmbeddedVector)?;

    let qx = decode_hex(qx_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let qy = decode_hex(qy_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let hash = decode_hex(hash_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let r: [u8; 21] = decode_hex_padded(r_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;
    let s: [u8; 21] = decode_hex_padded(s_hex).ok_or(FailureKind::MalformedEmbeddedVector)?;

    let q = Point::Affine(
        FieldElement::from_be_bytes(&qx),
        FieldElement::from_be_bytes(&qy),
    );
    let g = Point::generator();

    if dstu4145_verify(&hash, &r, &s, q, g) {
        Ok(())
    } else {
        Err(FailureKind::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_equal, decode_hex, decode_hex_fixed, decode_hex_padded, find_str_value, Failure,
        FailureKind, Primitive, Report,
    };

    #[test]
    fn check_equal_detects_a_real_mismatch() {
        assert_eq!(check_equal(b"abc", b"abc"), Ok(()));
        assert_eq!(check_equal(b"abc", b"abd"), Err(FailureKind::Mismatch));
    }

    #[test]
    fn find_str_value_locates_a_key_and_reports_none_when_absent() {
        let json = r#"{"foo": "bar", "foo": "baz"}"#;
        let Some((first, at)) = find_str_value(json, "foo", 0) else {
            panic!("first occurrence must be found");
        };
        assert_eq!(first, "bar");
        let Some((second, _)) = find_str_value(json, "foo", at) else {
            panic!("second occurrence must be found");
        };
        assert_eq!(second, "baz");
        assert_eq!(find_str_value(json, "missing", 0), None);
    }

    #[test]
    fn decode_hex_pads_odd_length_and_rejects_non_hex_digits() {
        assert_eq!(decode_hex("00ff"), Some(std::vec![0x00, 0xff]));
        assert_eq!(
            decode_hex("f"),
            Some(std::vec![0x0f]),
            "odd-length hex must be treated as a missing leading zero nibble, not rejected"
        );
        assert_eq!(decode_hex("zz"), None, "non-hex digits must be rejected");
    }

    #[test]
    fn decode_hex_fixed_rejects_wrong_length() {
        assert_eq!(decode_hex_fixed::<2>("00ff"), Some([0x00, 0xff]));
        assert_eq!(decode_hex_fixed::<3>("00ff"), None);
    }

    #[test]
    fn decode_hex_padded_left_pads_a_short_scalar() {
        assert_eq!(
            decode_hex_padded::<4>("ff"),
            Some([0x00, 0x00, 0x00, 0xff]),
            "a short hex string must be treated as missing leading zero bytes, not misaligned ones"
        );
    }

    #[test]
    fn report_display_lists_every_failed_primitive() {
        let report = Report {
            failures: std::vec![
                Failure {
                    primitive: Primitive::Kalyna,
                    kind: FailureKind::Mismatch,
                },
                Failure {
                    primitive: Primitive::Dstu4145,
                    kind: FailureKind::MalformedEmbeddedVector,
                },
            ],
        };
        let text = report.to_string();
        assert!(text.contains("Kalyna"));
        assert!(text.contains("DSTU 4145"));
    }
}
