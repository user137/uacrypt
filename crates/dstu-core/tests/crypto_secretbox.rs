//! Tests for `dstu_core::crypto_secretbox` (`TASKS.md` T-37, `DECISIONS.md` D-51) - the
//! `crypto_secretbox` equivalent, a single fixed `hazmat::kalyna_ccm::Kalyna256_256Ccm`
//! construction with an internally-generated nonce and a combined `nonce || ciphertext || tag`
//! wire format. No external oracle exists for this specific framing (it's this crate's own
//! construction over an already-oracle-verified primitive), so verification here is property +
//! tamper + a direct byte-layout pin against `hazmat::kalyna_ccm` itself, the same posture already
//! used for `crypto_kdf`/`crypto_sign`.

#![cfg(feature = "std")]

use dstu_core::crypto_secretbox::{open, seal, SecretKey, SecretboxError, MAX_MESSAGE_LEN};
use dstu_core::hazmat::kalyna_ccm::Kalyna256_256Ccm;
use proptest::prelude::*;

const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 16;

#[test]
fn round_trip() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"hello dstu";
    let sealed = seal(&key, plaintext).expect("plaintext within length limit");
    let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
    assert_eq!(opened, plaintext);
}

#[test]
fn zero_length_plaintext_round_trips() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed = seal(&key, &[]).expect("empty plaintext is within length limit");
    assert_eq!(sealed.len(), NONCE_LEN + TAG_LEN);
    let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
    assert_eq!(opened, Vec::<u8>::new());
}

#[test]
fn max_length_plaintext_seals_and_opens() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let plaintext = vec![0x42u8; MAX_MESSAGE_LEN];
    let sealed = seal(&key, &plaintext).expect("plaintext at the exact length limit");
    let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
    assert_eq!(opened, plaintext);
}

#[test]
fn oversized_plaintext_is_rejected_not_truncated() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let too_long = vec![0u8; MAX_MESSAGE_LEN + 1];
    let err = seal(&key, &too_long).expect_err("one byte over the length limit must be rejected");
    assert!(matches!(err, SecretboxError::MessageTooLong));
}

#[test]
fn two_calls_use_different_nonces() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let a = seal(&key, b"same plaintext").expect("plaintext within length limit");
    let b = seal(&key, b"same plaintext").expect("plaintext within length limit");
    assert_ne!(
        &a[..NONCE_LEN],
        &b[..NONCE_LEN],
        "a fresh random nonce must be drawn per call"
    );
    assert_ne!(a, b);
}

#[test]
fn truncated_input_is_rejected_not_a_panic() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    for len in [0usize, 1, 20, NONCE_LEN + TAG_LEN - 1] {
        let short = vec![0u8; len];
        let err = open(&key, &short).expect_err("input shorter than nonce+tag must be rejected");
        assert!(matches!(err, SecretboxError::Truncated), "len = {len}");
    }
}

#[test]
fn wrong_key_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let other = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed = seal(&key, b"secret").expect("plaintext within length limit");
    let err = open(&other, &sealed).expect_err("wrong key must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

#[test]
fn tampered_nonce_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let mut sealed = seal(&key, b"secret").expect("plaintext within length limit");
    sealed[0] ^= 0xFF;
    let err = open(&key, &sealed).expect_err("tampered nonce must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let mut sealed = seal(&key, b"secret").expect("plaintext within length limit");
    sealed[NONCE_LEN] ^= 0xFF;
    let err = open(&key, &sealed).expect_err("tampered ciphertext must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

#[test]
fn tampered_tag_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let mut sealed = seal(&key, b"secret").expect("plaintext within length limit");
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    let err = open(&key, &sealed).expect_err("tampered tag must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

/// Confirms `seal`'s output is exactly `nonce (32) || ciphertext || tag (16)`, not just "something
/// that round-trips through `open`" - pinned directly against a manual `hazmat::kalyna_ccm` call
/// using the nonce `seal` actually drew (`CLAUDE.md`'s "check what a fixed vector actually
/// exercises" - a round-trip-only test would pass even if the layout silently changed shape).
#[test]
fn wire_format_is_nonce_then_ciphertext_then_tag() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"pin the layout";
    let sealed = seal(&key, plaintext).expect("plaintext within length limit");

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[..NONCE_LEN]);
    let ciphertext_len = sealed.len() - NONCE_LEN - TAG_LEN;

    let mut buf = plaintext.to_vec();
    let cipher = Kalyna256_256Ccm::new(key.as_bytes());
    let tag = cipher
        .seal_in_place(&nonce, &[], &mut buf)
        .expect("plaintext within length limit");

    assert_eq!(
        &sealed[NONCE_LEN..NONCE_LEN + ciphertext_len],
        buf.as_slice(),
        "ciphertext must match a direct hazmat call with the same nonce"
    );
    assert_eq!(
        &sealed[NONCE_LEN + ciphertext_len..],
        tag.as_slice(),
        "tag must match a direct hazmat call with the same nonce"
    );
}

proptest! {
    #[test]
    fn round_trip_property(plaintext in proptest::collection::vec(any::<u8>(), 0..=MAX_MESSAGE_LEN)) {
        let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
        let sealed = seal(&key, &plaintext).expect("plaintext within length limit");
        let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
        prop_assert_eq!(opened, plaintext);
    }
}
