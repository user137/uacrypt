//! Tests for `dstu_core::crypto_box` (`docs/TASKS.md` T-178) - a hybrid public-key encryption
//! construction over `hazmat::dstu9041` (`l(p)=256` KEM, wrapping a random 25-byte seed) plus
//! `crypto_kdf`/`crypto_secretstream` (bulk encryption). No DSTU standard or reference
//! implementation defines this composite - like `crypto_secretstream` (D-68), verified by
//! property/tamper/misuse tests only, never citable as vector-verified.

#![cfg(feature = "std")]

use dstu_core::crypto_box::{open, seal, OpenError, PublicKey, SecretKey};
use dstu_core::hazmat::dstu9041::curve256::order;
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

/// `docs/TASKS.md` T-183 Group 3 / `docs/DECISIONS.md` D-169/D-171: the individual tamper tests
/// above each confirm *a* failure returns `OpenError::InvalidCiphertext`, but none of them pin the
/// actual security property - that failures with genuinely different root causes are
/// *indistinguishable* to the caller. A KEM-level failure (wrong secret key: `dstu9041_decrypt`
/// itself errors) and a secretstream-level failure (right key, tampered tag: `decrypt` succeeds,
/// `PullState::pull`'s own tag check fails) reach `OpenError::InvalidCiphertext` through
/// completely different code paths inside `open` - this test asserts they produce not just the
/// same *variant* (`matches!`, already implied by the enum only having one non-`Truncated`
/// variant today) but the identical `Debug` representation, i.e. nothing an external caller could
/// observe distinguishes them. A future refactor splitting `OpenError` into more variants (a
/// padding-oracle-shaped regression, the exact risk D-169/D-171 flag) would break this
/// immediately.
///
/// The third failure mode T-183 names - a KEM-internal success with a wrong-*length* recovered
/// seed (`crypto_box.rs`'s own `if bit_len != L_MAX_P` defense-in-depth check) - is not
/// constructed here: `hazmat::dstu9041::decrypt`'s own `DecryptError` is already collapsed to one
/// variant for the same padding-oracle reason (D-167), so black-box-forging a ciphertext that
/// passes KEM decryption yet yields a wrong `bit_len` may not be reachable at all without breaking
/// the KEM's own hash check first - the same "foreclosed by contract, document rather than force a
/// test" posture as D-111's `dstu4145` findings, not a gap being silently skipped.
#[test]
fn kem_failure_and_secretstream_failure_are_indistinguishable() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let other = SecretKey::generate().expect("OS CSPRNG available in test environment");

    // KEM-level: right ciphertext, wrong key - `dstu9041_decrypt` itself fails.
    let sealed_a = seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    let kem_level_err = open(&sealed_a, &other).expect_err("wrong key must fail");

    // Secretstream-level: right key, tampered tag - KEM decrypt succeeds, `PullState::pull` fails.
    let mut sealed_b =
        seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    let last = sealed_b.len() - 1;
    sealed_b[last] ^= 0xFF;
    let secretstream_level_err = open(&sealed_b, &secret).expect_err("tampered tag must fail");

    assert!(matches!(kem_level_err, OpenError::InvalidCiphertext));
    assert!(matches!(
        secretstream_level_err,
        OpenError::InvalidCiphertext
    ));
    assert_eq!(
        format!("{kem_level_err:?}"),
        format!("{secretstream_level_err:?}"),
        "a KEM-level failure and a secretstream-level failure must be identically observable"
    );
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

/// `docs/TASKS.md` T-183 Group 1: `secret_key_rejects_out_of_range_bytes` above only ever checked
/// the *lower* boundary (`e=0,1`) - `is_valid_scalar`'s strict upper bound (`e < n-1`) and the
/// all-`0xFF` degenerate case were never exercised at this (`crypto_box`) layer, only at
/// `hazmat::dstu9041::curve256`'s own `is_valid_scalar_boundaries` (`tests/dstu9041_curve.rs`).
/// This isn't a duplicate of that test - it confirms `SecretKey::from_bytes` actually *wires up*
/// to the same validation, not a hazmat-level guarantee that happens not to reach this wrapper.
#[test]
fn secret_key_rejects_out_of_range_bytes_upper_boundary() {
    let n = order();
    let mut n_minus_1 = n;
    n_minus_1[31] -= 1;
    let mut n_plus_1 = n;
    n_plus_1[31] += 1;

    assert!(
        SecretKey::from_bytes(&n_minus_1).is_none(),
        "e=n-1 must be invalid (strict upper bound)"
    );
    assert!(SecretKey::from_bytes(&n).is_none(), "e=n must be invalid");
    assert!(
        SecretKey::from_bytes(&n_plus_1).is_none(),
        "e=n+1 must be invalid"
    );
    assert!(
        SecretKey::from_bytes(&[0xFFu8; 32]).is_none(),
        "e=all-0xFF (far above n) must be invalid"
    );
}

/// `docs/TASKS.md` T-183 Group 1: `truncated_input_is_rejected_not_a_panic` above only ever
/// checked lengths at or below `MIN_SEALED_LEN` - nothing checked that `open` rejects *trailing
/// garbage* appended after an otherwise-valid sealed message (a "reject a lied-about length" gap,
/// distinct from truncation).
#[test]
fn trailing_garbage_after_valid_ciphertext_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    sealed.push(0x00);
    let err = open(&sealed, &secret).expect_err("trailing garbage must be rejected, not ignored");
    assert!(matches!(
        err,
        OpenError::InvalidCiphertext | OpenError::Truncated
    ));
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
