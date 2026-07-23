//! Tests for `dstu_core::crypto_sign` (`crypto_sign` equivalent, `TASKS.md` T-48) - the
//! libsodium-ergonomics wrapper over `hazmat::dstu4145`. Nonce derivation is deterministic
//! (Kupyna-KMAC, RFC-6979-style - `DECISIONS.md` D-46), so this file has no RNG dependency to
//! mock: every test below is itself deterministic.
//!
//! `verifying_key()`'s `Q = -d*G` derivation is cross-checked against the official Annex B.1
//! worked example's own `private_key_d`/`public_key_q` pair (`tests/vectors/dstu4145/gf2m163.json`)
//! - the one part of this wrapper with an external oracle. Sign/verify itself has no oracle for
//! *this* wrapper's deterministic nonce (no reference implementation derives DSTU 4145 nonces this
//! way), so it's tested via round-trip + tamper-rejection + a proptest sweep, same posture as
//! `hazmat::kupyna_kdf`'s tests (`docs/pseudocode/kupyna-kdf.md`).

use dstu_core::crypto_sign::SigningKey;
use dstu_core::hazmat::dstu4145::gf2m163::FieldElement;
use proptest::prelude::*;

fn decode_hex(s: &str) -> Vec<u8> {
    let padded;
    let s = if s.len().is_multiple_of(2) {
        s
    } else {
        padded = format!("0{s}");
        &padded
    };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit in test vector"))
        .collect()
}

fn field(s: &str) -> FieldElement {
    FieldElement::from_be_bytes(&decode_hex(s))
}

fn extract_all<'a>(json: &'a str, key: &str) -> Vec<&'a str> {
    let pattern = format!("\"{key}\": \"");
    let mut results = Vec::new();
    let mut rest = json;
    while let Some(start) = rest.find(pattern.as_str()) {
        let after = &rest[start + pattern.len()..];
        let end = after.find('"').expect("well-formed test-vector JSON");
        results.push(&after[..end]);
        rest = &after[end + 1..];
    }
    results
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    extract_all(json, key)[0]
}

fn scalar_bytes(s: &str) -> [u8; 21] {
    let bytes = decode_hex(s);
    let mut out = [0u8; 21];
    out[21 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// A small, obviously-below-`n` test scalar (`n`'s top byte is `0x04` - see
/// `hazmat::dstu4145::curve163::order`), distinguished only by its low byte.
fn small_scalar(low_byte: u8) -> [u8; 21] {
    let mut out = [0u8; 21];
    out[20] = low_byte;
    out
}

#[test]
fn verifying_key_matches_official_worked_example_q() {
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let d = scalar_bytes(extract(json, "private_key_d"));
    let expected_qx = field(extract_all(json, "x")[1]); // index 0 is base_point.x
    let expected_qy = field(extract_all(json, "y")[1]); // index 0 is base_point.y

    let mut expected = [0u8; 42];
    expected[..21].copy_from_slice(&expected_qx.to_be_bytes());
    expected[21..].copy_from_slice(&expected_qy.to_be_bytes());

    let signing_key = SigningKey::from_bytes(&d).expect("official d is a valid scalar");
    let verifying_key = signing_key.verifying_key();

    assert_eq!(
        verifying_key.to_uncompressed_bytes(),
        expected,
        "Q = -d*G must match the official Annex B.1 worked example's public key"
    );
}

#[test]
fn sign_is_deterministic() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x11)).expect("nonzero, below n");
    let sig_a = signing_key.sign(b"hello dstu4145");
    let sig_b = signing_key.sign(b"hello dstu4145");
    assert_eq!(sig_a.to_bytes(), sig_b.to_bytes());
}

#[test]
fn sign_verify_roundtrip() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let sig = signing_key.sign(b"a real message");
    assert!(verifying_key.verify(b"a real message", &sig));
}

#[test]
fn tampered_message_is_rejected() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let sig = signing_key.sign(b"a real message");
    assert!(!verifying_key.verify(b"a different message", &sig));
}

#[test]
fn tampered_signature_is_rejected() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let mut sig = signing_key.sign(b"a real message").to_bytes();
    sig[41] ^= 1; // flip the low bit of s (bytes 21..42)
    let sig = dstu_core::crypto_sign::Signature::from_bytes(&sig);
    assert!(!verifying_key.verify(b"a real message", &sig));
}

#[test]
fn wrong_verifying_key_is_rejected() {
    let signing_key_a = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let signing_key_b = SigningKey::from_bytes(&small_scalar(0x2B)).expect("nonzero, below n");
    let sig = signing_key_a.sign(b"a real message");
    assert!(!signing_key_b
        .verifying_key()
        .verify(b"a real message", &sig));
}

#[test]
fn from_bytes_rejects_zero_scalar() {
    assert!(SigningKey::from_bytes(&[0u8; 21]).is_none());
}

#[test]
fn from_bytes_rejects_scalar_at_or_above_order() {
    let n = dstu_core::hazmat::dstu4145::curve163::order();
    assert!(SigningKey::from_bytes(&n).is_none());
}

proptest! {
    #[test]
    fn dstu4145_crypto_sign_roundtrip(
        d_bytes in prop::collection::vec(any::<u8>(), 20),
        message in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut d_arr = [0u8; 21];
        d_arr[1..].copy_from_slice(&d_bytes);
        prop_assume!(d_arr != [0u8; 21]);

        let signing_key = match SigningKey::from_bytes(&d_arr) {
            Some(k) => k,
            None => return Ok(()), // astronomically unlikely d >= n from a 160-bit sample
        };
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(&message);
        prop_assert!(verifying_key.verify(&message, &sig));
    }
}
