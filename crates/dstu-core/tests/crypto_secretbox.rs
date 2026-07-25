//! Tests for `dstu_core::crypto_secretbox` (`TASKS.md` T-37, `DECISIONS.md` D-51, migrated to
//! Kalyna-GCM by roadmap Step 3 item 1, `DECISIONS.md` D-63) - a single fixed
//! `hazmat::kalyna_gcm::Kalyna256_256Gcm` construction with an internally-generated nonce and a
//! combined `nonce || ciphertext || tag` wire format. No external oracle exists for this specific
//! framing (it's this crate's own construction over an already-oracle-verified primitive), so
//! verification here is property + tamper + a direct byte-layout pin against `hazmat::kalyna_gcm`
//! itself, the same posture already used for `crypto_kdf`/`crypto_sign`.

#![cfg(feature = "std")]

use dstu_core::crypto_secretbox::{open, seal, SecretKey, SecretboxError};
use dstu_core::hazmat::kalyna_gcm::Kalyna256_256Gcm;
use proptest::prelude::*;

const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 16;

#[test]
fn round_trip() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"hello dstu";
    let sealed = seal(&key, plaintext).expect("OS CSPRNG available in test environment");
    let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
    assert_eq!(opened, plaintext);
}

#[test]
fn zero_length_plaintext_round_trips() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed = seal(&key, &[]).expect("OS CSPRNG available in test environment");
    assert_eq!(sealed.len(), NONCE_LEN + TAG_LEN);
    let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
    assert_eq!(opened, Vec::<u8>::new());
}

/// Kalyna-GCM (unlike the previous Kalyna-CCM construction, D-41) encodes no length cap into
/// itself - `DECISIONS.md` D-63. This message is well past the old 255-byte `kalyna_ccm` limit;
/// it succeeding is what proves the cap is actually gone, not just undocumented.
#[test]
fn message_larger_than_the_old_255_byte_cap_round_trips() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let plaintext = vec![0x42u8; 4096];
    let sealed = seal(&key, &plaintext).expect("Kalyna-GCM has no message-length cap");
    let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
    assert_eq!(opened, plaintext);
}

#[test]
fn two_calls_use_different_nonces() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let a = seal(&key, b"same plaintext").expect("OS CSPRNG available in test environment");
    let b = seal(&key, b"same plaintext").expect("OS CSPRNG available in test environment");
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
    let sealed = seal(&key, b"secret").expect("OS CSPRNG available in test environment");
    let err = open(&other, &sealed).expect_err("wrong key must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

/// Regression guard for the nonce-as-AAD binding in `seal`/`open` (module doc's "No AAD" section,
/// `DECISIONS.md` D-63) - `hazmat::kalyna_gcm`'s own tag does not cover `iv` (see that module's
/// "Warning" doc section), so this would fail without it.
#[test]
fn tampered_nonce_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let mut sealed = seal(&key, b"secret").expect("OS CSPRNG available in test environment");
    sealed[0] ^= 0xFF;
    let err = open(&key, &sealed).expect_err("tampered nonce must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let mut sealed = seal(&key, b"secret").expect("OS CSPRNG available in test environment");
    sealed[NONCE_LEN] ^= 0xFF;
    let err = open(&key, &sealed).expect_err("tampered ciphertext must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

#[test]
fn tampered_tag_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let mut sealed = seal(&key, b"secret").expect("OS CSPRNG available in test environment");
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    let err = open(&key, &sealed).expect_err("tampered tag must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

/// Confirms `seal`'s output is exactly `nonce (32) || ciphertext || tag (16)`, not just "something
/// that round-trips through `open`" - pinned directly against a manual `hazmat::kalyna_gcm` call
/// using the nonce `seal` actually drew (`CLAUDE.md`'s "check what a fixed vector actually
/// exercises" - a round-trip-only test would pass even if the layout silently changed shape). The
/// tag comparison is against the first `TAG_LEN` bytes of GCM's own full-block tag - `seal`
/// truncates the same way (`DECISIONS.md` D-63), not a new convention invented for this test. The
/// direct call passes `nonce` as AAD too, matching `seal`'s internal nonce-binding (module doc's
/// "No AAD" section) - passing `&[]` here would produce a different tag and fail this test.
#[test]
fn wire_format_is_nonce_then_ciphertext_then_tag() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"pin the layout";
    let sealed = seal(&key, plaintext).expect("Kalyna-GCM has no message-length cap");

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[..NONCE_LEN]);
    let ciphertext_len = sealed.len() - NONCE_LEN - TAG_LEN;

    let mut buf = vec![0u8; plaintext.len()];
    let cipher = Kalyna256_256Gcm::new(key.as_bytes());
    let tag = cipher
        .encrypt(&nonce, &nonce, plaintext, &mut buf)
        .expect("plaintext/ciphertext_out lengths match");

    assert_eq!(
        &sealed[NONCE_LEN..NONCE_LEN + ciphertext_len],
        buf.as_slice(),
        "ciphertext must match a direct hazmat call with the same nonce"
    );
    assert_eq!(
        &sealed[NONCE_LEN + ciphertext_len..],
        &tag[..TAG_LEN],
        "tag must match a direct hazmat call with the same nonce, truncated the same way seal does"
    );
}

proptest! {
    #[test]
    fn round_trip_property(plaintext in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
        let sealed = seal(&key, &plaintext).expect("Kalyna-GCM has no message-length cap");
        let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
        prop_assert_eq!(opened, plaintext);
    }
}
