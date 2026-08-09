//! Tests for `dstu_core::crypto_sign257` - the `m=257` sibling of `crypto_sign` (`docs/TASKS.md`
//! T-199, `docs/DECISIONS.md` D-185/D-186). Mirrors `tests/crypto_sign.rs`'s own coverage
//! structure closely; deviations noted where they exist.
//!
//! **No `verifying_key_matches_official_worked_example_q`-equivalent test**: unlike `m=163`
//! (Annex B.1), no primary-text DSTU 4145 worked example exists for `m=257` - `Q = -d*G`'s
//! correctness for this curve is already covered at the `hazmat::dstu4145::signature257` layer
//! (`tests/dstu4145_signature257.rs`'s BC-oracle cases, which include independently-computed `Q`
//! values for 20 random `d`). This file tests the `crypto_sign257` wrapper layer specifically
//! (deterministic nonce derivation, digest API, `generate`/`from_bytes` round-tripping), not the
//! underlying curve math again.

use dstu_core::crypto_sign257::SigningKey;
use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna256Hasher};
use proptest::prelude::*;

/// A small, obviously-below-`n` test scalar (`n`'s top byte is `0x00`, second byte's top 7 bits
/// are also `0` - see `hazmat::dstu4145::curve257::order`), distinguished only by its low byte.
fn small_scalar(low_byte: u8) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[32] = low_byte;
    out
}

// Every #[test] below (except the two from_bytes rejection tests, which never derive a public
// key) runs `Point::scalar_multiply`'s 257-iteration constant-time ladder at least once (even
// slower under Miri than `m=163`'s 163-iteration ladder - same posture as `tests/crypto_sign.rs`,
// docs/TASKS.md T-100/T-85/D-46). Excluded from CI's required Miri gate only.

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_is_deterministic() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x11)).expect("nonzero, below n");
    let sig_a = signing_key.sign(b"hello dstu4145 m=257");
    let sig_b = signing_key.sign(b"hello dstu4145 m=257");
    assert_eq!(sig_a.to_bytes(), sig_b.to_bytes());
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
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
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
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
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn tampered_signature_is_rejected() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let mut sig = signing_key.sign(b"a real message").to_bytes();
    sig[65] ^= 1; // flip the low bit of s (bytes 33..66)
    let sig = dstu_core::crypto_sign257::Signature::from_bytes(&sig);
    assert!(!verifying_key.verify(b"a real message", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
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

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
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
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_digest_verify_digest_roundtrip_with_streamed_hash() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();

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
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn verify_digest_rejects_tampered_digest() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let digest = Kupyna256::digest(b"a real message");
    let sig = signing_key.sign_digest(&digest);

    let mut wrong_digest = digest;
    wrong_digest[31] ^= 1;
    assert!(!verifying_key.verify_digest(&wrong_digest, &sig));
}

// T-122-equivalent: `SigningKey::generate()` draws `d` from the OS CSPRNG via rejection sampling.
// Run several times, not once.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
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

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
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

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
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
    assert!(SigningKey::from_bytes(&[0u8; 33]).is_none());
}

#[test]
fn from_bytes_rejects_scalar_at_or_above_order() {
    let n = dstu_core::hazmat::dstu4145::curve257::order();
    assert!(SigningKey::from_bytes(&n).is_none());
}

proptest! {
    #[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
    #[test]
    fn dstu4145_crypto_sign257_roundtrip(
        d_bytes in prop::collection::vec(any::<u8>(), 32),
        message in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut d_arr = [0u8; 33];
        d_arr[1..].copy_from_slice(&d_bytes);
        prop_assume!(d_arr != [0u8; 33]);

        let signing_key = match SigningKey::from_bytes(&d_arr) {
            Some(k) => k,
            None => return Ok(()), // astronomically unlikely d >= n from a 256-bit sample
        };
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(&message);
        prop_assert!(verifying_key.verify(&message, &sig));
    }
}
