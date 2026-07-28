//! Tests for `dstu_core::crypto_stream` (`docs/TASKS.md` roadmap Step 3 item 3, `docs/DECISIONS.md` D-67) -
//! a single fixed `hazmat::strumok::Strumok256` construction with an internally-generated IV and
//! a combined `iv || ciphertext` wire format. No tag exists - this module has no rejection
//! category (D-64's convention does not apply here, see the module doc's "No authentication"
//! section); its place is taken by tests pinning the *documented absence* of tamper-detection
//! directly, the same convention `tests/kalyna_xts.rs` already established for XTS.

#![cfg(feature = "std")]

use dstu_core::crypto_stream::{decrypt, encrypt, Key, StreamError};
use dstu_core::hazmat::strumok::Strumok256;
use proptest::prelude::*;

const IV_LEN: usize = 32;

#[test]
fn round_trip() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"hello dstu";
    let sealed = encrypt(&key, plaintext).expect("OS CSPRNG available in test environment");
    let opened = decrypt(&key, &sealed).expect("input long enough to contain an IV");
    assert_eq!(opened, plaintext);
}

#[test]
fn zero_length_plaintext_round_trips() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let sealed = encrypt(&key, &[]).expect("OS CSPRNG available in test environment");
    assert_eq!(sealed.len(), IV_LEN);
    let opened = decrypt(&key, &sealed).expect("input long enough to contain an IV");
    assert_eq!(opened, Vec::<u8>::new());
}

#[test]
fn large_message_round_trips() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let plaintext = vec![0x42u8; 4096];
    let sealed = encrypt(&key, &plaintext).expect("OS CSPRNG available in test environment");
    let opened = decrypt(&key, &sealed).expect("input long enough to contain an IV");
    assert_eq!(opened, plaintext);
}

#[test]
fn two_calls_use_different_ivs() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let a = encrypt(&key, b"same plaintext").expect("OS CSPRNG available in test environment");
    let b = encrypt(&key, b"same plaintext").expect("OS CSPRNG available in test environment");
    assert_ne!(
        &a[..IV_LEN],
        &b[..IV_LEN],
        "a fresh random IV must be drawn per call"
    );
    assert_ne!(a, b);
}

#[test]
fn truncated_input_is_rejected_not_a_panic() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    for len in [0usize, 1, 20, IV_LEN - 1] {
        let short = vec![0u8; len];
        let err = decrypt(&key, &short).expect_err("input shorter than an IV must be rejected");
        assert!(matches!(err, StreamError::Truncated), "len = {len}");
    }
}

/// No tag exists to fail authentication - the wrong key still "succeeds" and returns different,
/// silently-wrong plaintext instead of an error. Pins the *absence* of rejection directly, per the
/// module doc's "No authentication" section, rather than leaving it untested.
#[test]
fn wrong_key_produces_different_plaintext_not_an_error() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let other = Key::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"secret message";
    let sealed = encrypt(&key, plaintext).expect("OS CSPRNG available in test environment");
    let opened = decrypt(&other, &sealed).expect("decrypt never fails on a wrong key");
    assert_ne!(opened, plaintext);
}

/// Same as `wrong_key_produces_different_plaintext_not_an_error`, for a tampered ciphertext byte
/// instead of a wrong key - mirrors `tests/kalyna_xts.rs`'s
/// `tampered_ciphertext_does_not_error_but_produces_garbage`.
#[test]
fn tampered_ciphertext_does_not_error_but_produces_garbage() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"secret message..";
    let mut sealed = encrypt(&key, plaintext).expect("OS CSPRNG available in test environment");
    sealed[IV_LEN] ^= 0xFF;
    let opened = decrypt(&key, &sealed).expect("decrypt never fails on tampered ciphertext");
    assert_ne!(opened, plaintext);
}

/// Confirms `encrypt`'s output is exactly `iv (32) || ciphertext`, not just "something that
/// round-trips through `decrypt`" - pinned directly against a manual `hazmat::strumok` call using
/// the IV `encrypt` actually drew.
#[test]
fn wire_format_is_iv_then_ciphertext() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"pin the layout";
    let sealed = encrypt(&key, plaintext).expect("OS CSPRNG available in test environment");

    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&sealed[..IV_LEN]);

    let mut buf = plaintext.to_vec();
    let mut cipher = Strumok256::new(key.as_bytes(), &iv);
    cipher.apply_keystream(&mut buf);

    assert_eq!(
        &sealed[IV_LEN..],
        buf.as_slice(),
        "ciphertext must match a direct hazmat call with the same key/IV"
    );
}

proptest! {
    #[test]
    fn round_trip_property(plaintext in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let key = Key::generate().expect("OS CSPRNG available in test environment");
        let sealed = encrypt(&key, &plaintext).expect("OS CSPRNG available in test environment");
        let opened = decrypt(&key, &sealed).expect("input long enough to contain an IV");
        prop_assert_eq!(opened, plaintext);
    }
}
