//! Tests for `dstu_core::crypto_box` (`docs/TASKS.md` T-178) - a hybrid public-key encryption
//! construction over `hazmat::dstu9041` (`l(p)=256` KEM, wrapping a random 25-byte seed) plus
//! `crypto_kdf`/`crypto_secretstream` (bulk encryption). No DSTU standard or reference
//! implementation defines this composite - like `crypto_secretstream` (D-68), verified by
//! property/tamper/misuse tests only, never citable as vector-verified.

#![cfg(feature = "std")]

use dstu_core::crypto_box::{open, seal, OpenError, PublicKey, SecretKey};
use proptest::prelude::*;

const KEM_CIPHERTEXT_LEN: usize = 128;
const HEADER_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MIN_SEALED_LEN: usize = KEM_CIPHERTEXT_LEN + HEADER_LEN + TAG_LEN;

#[test]
fn round_trip() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let message = b"hello dstu box";
    let sealed = seal(message, &public).expect("OS CSPRNG available in test environment");
    let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
    assert_eq!(opened, message);
}

#[test]
fn zero_length_message_round_trips() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let sealed = seal(&[], &public).expect("OS CSPRNG available in test environment");
    assert_eq!(sealed.len(), MIN_SEALED_LEN);
    let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
    assert_eq!(opened, Vec::<u8>::new());
}

/// The bulk layer is `crypto_secretstream`, which (like `crypto_secretbox`) has no message-length
/// cap - only the *asymmetric* half is capped at 25 bytes, and that cap is invisible to `seal`'s
/// own caller since it only ever wraps a fresh random seed, never the message itself.
#[test]
fn message_far_larger_than_the_25_byte_kem_payload_round_trips() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let message = vec![0x42u8; 4096];
    let sealed = seal(&message, &public).expect("OS CSPRNG available in test environment");
    let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
    assert_eq!(opened, message);
}

#[test]
fn two_calls_use_different_ephemeral_material() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let a = seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    let b = seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    assert_ne!(
        &a[..KEM_CIPHERTEXT_LEN],
        &b[..KEM_CIPHERTEXT_LEN],
        "a fresh random seed/epsilon must be drawn per call"
    );
    assert_ne!(a, b);
}

#[test]
fn public_key_round_trips_through_bytes() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let bytes = public.to_bytes();
    let reparsed = PublicKey::from_bytes(&bytes).expect("a freshly generated public key is valid");
    // Sealing under the reparsed key must produce something the original secret key can open -
    // the real invariant (equality on the compressed bytes is necessary but not sufficient, since
    // `PublicKey` may internally hold either of {Q, -Q} - see `curve256::point_from_x`'s doc).
    let sealed =
        seal(b"round trip via bytes", &reparsed).expect("OS CSPRNG available in test environment");
    let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
    assert_eq!(opened, b"round trip via bytes");
}

#[test]
fn truncated_input_is_rejected_not_a_panic() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    for len in [0usize, 1, 20, KEM_CIPHERTEXT_LEN, MIN_SEALED_LEN - 1] {
        let short = vec![0u8; len];
        let err =
            open(&short, &secret).expect_err("input shorter than the minimum must be rejected");
        assert!(matches!(err, OpenError::Truncated), "len = {len}");
    }
}

#[test]
fn wrong_secret_key_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let other = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    let err = open(&sealed, &other).expect_err("wrong secret key must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

/// Regression guard: the 128-byte KEM prefix is not covered by the secretstream's own tag by any
/// accident of layout, but tampering it must still fail closed - a wrong prefix decrypts (via
/// `hazmat::dstu9041::decrypt`) to either an error or the wrong seed, either way deriving the
/// wrong bulk key, so `PullState::pull`'s tag check catches it (`docs/DECISIONS.md` D-63's own
/// nonce/prefix-binding concern, re-derived for this construction rather than assumed).
#[test]
fn tampered_kem_prefix_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    sealed[0] ^= 0xFF;
    let err = open(&sealed, &secret).expect_err("tampered KEM prefix must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

#[test]
fn tampered_secretstream_header_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    sealed[KEM_CIPHERTEXT_LEN] ^= 0xFF;
    let err = open(&sealed, &secret).expect_err("tampered header must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    let idx = KEM_CIPHERTEXT_LEN + HEADER_LEN;
    sealed[idx] ^= 0xFF;
    let err = open(&sealed, &secret).expect_err("tampered ciphertext must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

#[test]
fn tampered_tag_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    let err = open(&sealed, &secret).expect_err("tampered tag must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

#[test]
fn secret_key_rejects_out_of_range_bytes() {
    assert!(
        SecretKey::from_bytes(&[0u8; 32]).is_none(),
        "e=0 must be invalid"
    );
    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(SecretKey::from_bytes(&one).is_none(), "e=1 must be invalid");
}

#[test]
fn public_key_rejects_degenerate_x_values() {
    assert!(
        PublicKey::from_bytes(&[0u8; 32]).is_none(),
        "x=0 must be invalid"
    );
    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(PublicKey::from_bytes(&one).is_none(), "x=1 must be invalid");
    assert!(
        PublicKey::from_bytes(&[0xFFu8; 32]).is_none(),
        "all-0xFF is not even a valid field element (>= p)"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    #[cfg_attr(miri, ignore)] // each case drives four full 256-iteration scalar multiplications
                              // (keygen x2, encrypt, decrypt) - too slow to interpret under Miri,
                              // same posture as T-100/T-177's heaviest dstu9041 proptests.
    fn round_trip_property(message in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
        let public = secret.public_key();
        let sealed = seal(&message, &public).expect("OS CSPRNG available in test environment");
        let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
        prop_assert_eq!(opened, message);
    }
}
