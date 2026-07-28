//! Tests for `dstu_core::crypto_sign` (`crypto_sign` equivalent, `docs/TASKS.md` T-48) - the
//! libsodium-ergonomics wrapper over `hazmat::dstu4145`. Nonce derivation is deterministic
//! (Kupyna-KMAC, RFC-6979-style - `docs/DECISIONS.md` D-46), so this file has no RNG dependency to
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
use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna256Hasher};
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

// Every #[test] below (except the two from_bytes rejection tests, which never derive a public
// key) calls `verifying_key()`/`sign`/`verify`, each running `Point::scalar_multiply`'s
// 163-iteration constant-time ladder at least once - interpreting that under Miri takes minutes
// per call (docs/TASKS.md T-100/T-85/D-46), not seconds. Excluded from CI's required Miri gate only;
// `cargo test` (required, fast) and property/vector coverage are unaffected.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
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

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_is_deterministic() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x11)).expect("nonzero, below n");
    let sig_a = signing_key.sign(b"hello dstu4145");
    let sig_b = signing_key.sign(b"hello dstu4145");
    assert_eq!(sig_a.to_bytes(), sig_b.to_bytes());
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_verify_roundtrip() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let sig = signing_key.sign(b"a real message");
    assert!(verifying_key.verify(b"a real message", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn tampered_message_is_rejected() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let sig = signing_key.sign(b"a real message");
    assert!(!verifying_key.verify(b"a different message", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn tampered_signature_is_rejected() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let mut sig = signing_key.sign(b"a real message").to_bytes();
    sig[41] ^= 1; // flip the low bit of s (bytes 21..42)
    let sig = dstu_core::crypto_sign::Signature::from_bytes(&sig);
    assert!(!verifying_key.verify(b"a real message", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn wrong_verifying_key_is_rejected() {
    let signing_key_a = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let signing_key_b = SigningKey::from_bytes(&small_scalar(0x2B)).expect("nonzero, below n");
    let sig = signing_key_a.sign(b"a real message");
    assert!(!signing_key_b
        .verifying_key()
        .verify(b"a real message", &sig));
}

// T-113: `sign_digest`/`verify_digest` let a caller hash a large/streamed message themselves
// (via `Kupyna256Hasher`) instead of `sign`/`verify` hashing the whole message in one call.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_digest_matches_sign_on_the_same_message() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let digest = Kupyna256::digest(b"a real message");
    assert_eq!(
        signing_key.sign(b"a real message").to_bytes(),
        signing_key.sign_digest(&digest).to_bytes(),
        "sign() must be equivalent to hashing then sign_digest()"
    );
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_digest_verify_digest_roundtrip_with_streamed_hash() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();

    // A message hashed incrementally in chunks, as a caller with a large file would.
    let mut hasher = Kupyna256Hasher::new();
    hasher.update(b"a real ");
    hasher.update(b"message");
    let digest = hasher.finalize();

    assert_eq!(digest, Kupyna256::digest(b"a real message"));

    let sig = signing_key.sign_digest(&digest);
    assert!(verifying_key.verify_digest(&digest, &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn verify_digest_rejects_tampered_digest() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let digest = Kupyna256::digest(b"a real message");
    let sig = signing_key.sign_digest(&digest);

    // hash_to_field (§5.9) only consumes the digest's own last 21 bytes (`docs/pseudocode/
    // dstu4145.md`), so the flipped byte must land inside that range for this to be a real tamper.
    let mut wrong_digest = digest;
    wrong_digest[31] ^= 1;
    assert!(!verifying_key.verify_digest(&wrong_digest, &sig));
}

// T-122: `SigningKey::generate()` draws `d` from the OS CSPRNG via rejection sampling. Run
// several times, not once - a single success can't distinguish "always produces a valid,
// working key" from "got lucky this run" the way a fixed vector would.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn generate_produces_a_key_that_signs_and_verifies() {
    for _ in 0..20 {
        let signing_key = SigningKey::generate().expect("OS CSPRNG available in test environment");
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(b"a freshly generated key can sign");
        assert!(verifying_key.verify(b"a freshly generated key can sign", &sig));
    }
}

// T-124: `uacrypt sign-keygen` needs to persist a generated key to a file, so `to_bytes()` must
// round-trip through `from_bytes()` back to an equivalent key (same `verifying_key()`/signatures) -
// not just "returns 21 bytes."
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn to_bytes_round_trips_through_from_bytes() {
    let original = SigningKey::generate().expect("OS CSPRNG available in test environment");
    let bytes = original.to_bytes();
    let restored = SigningKey::from_bytes(&bytes).expect("generate() always produces a valid d");
    assert_eq!(
        original.verifying_key().to_uncompressed_bytes(),
        restored.verifying_key().to_uncompressed_bytes()
    );
    let sig = restored.sign(b"round-tripped key can still sign");
    assert!(original
        .verifying_key()
        .verify(b"round-tripped key can still sign", &sig));
}

// No oracle vector exists for "is this actually random" (same posture as `crypto_secretbox`'s
// `two_calls_use_different_nonces`/`crypto_stream`'s `two_calls_use_different_ivs`) - compare via
// the public `Q = -d*G` rather than `to_bytes()`, matching the other `crypto_*` modules' own
// distinctness tests, which compare public/derived material rather than raw key bytes.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn two_calls_to_generate_produce_different_keys() {
    let a = SigningKey::generate().expect("OS CSPRNG available in test environment");
    let b = SigningKey::generate().expect("OS CSPRNG available in test environment");
    assert_ne!(
        a.verifying_key().to_uncompressed_bytes(),
        b.verifying_key().to_uncompressed_bytes()
    );
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
    #[cfg_attr(miri, ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100")]
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
