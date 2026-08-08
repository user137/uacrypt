//! Tests for `dstu_core::crypto_box512` (`docs/TASKS.md` T-193) - direct sibling of
//! `tests/crypto_box.rs` at `l(p)=512`'s widths. No DSTU standard or reference implementation
//! defines this composite - verified by property/tamper/misuse tests only, never citable as
//! vector-verified (same posture as `crypto_box`, D-68/T-178).

#![cfg(feature = "std")]

use dstu_core::crypto_box512::{open, seal, OpenError, PublicKey, SecretKey};
use dstu_core::hazmat::dstu9041::curve512::order;
use proptest::prelude::*;

const KEM_CIPHERTEXT_LEN: usize = 256;
const HEADER_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MIN_SEALED_LEN: usize = KEM_CIPHERTEXT_LEN + HEADER_LEN + TAG_LEN;

#[test]
fn round_trip() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let message = b"hello dstu box 512";
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

/// The bulk layer is `crypto_secretstream`, which has no message-length cap - only the
/// *asymmetric* half is capped (D-182: the seed uses a fixed 32-byte/256-bit width, well under
/// `l(p)=512`'s own 424-bit KEM capacity), and that cap is invisible to `seal`'s own caller since
/// it only ever wraps a fresh random seed, never the message itself.
#[test]
fn message_far_larger_than_the_seed_kem_payload_round_trips() {
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
    // `PublicKey` may internally hold either of {Q, -Q} - see `curve512::point_from_x`'s doc).
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

/// Regression guard: the 256-byte KEM prefix is not covered by the secretstream's own tag by any
/// accident of layout, but tampering it must still fail closed - `docs/DECISIONS.md` D-63's own
/// nonce/prefix-binding concern, re-derived for this construction rather than assumed.
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

/// `docs/TASKS.md` T-183 Group 3 (mirrors `crypto_box.rs`'s own
/// `kem_failure_and_secretstream_failure_are_indistinguishable`): a KEM-level failure and a
/// secretstream-level failure must reach `OpenError::InvalidCiphertext` through different code
/// paths but be identically observable to an external caller - the CCA-oracle-avoidance property.
#[test]
fn kem_failure_and_secretstream_failure_are_indistinguishable() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let other = SecretKey::generate().expect("OS CSPRNG available in test environment");

    let sealed_a = seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    let kem_level_err = open(&sealed_a, &other).expect_err("wrong key must fail");

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
        SecretKey::from_bytes(&[0u8; 64]).is_none(),
        "e=0 must be invalid"
    );
    let mut one = [0u8; 64];
    one[63] = 1;
    assert!(SecretKey::from_bytes(&one).is_none(), "e=1 must be invalid");
}

/// `docs/TASKS.md` T-183 Group 1 (mirrors `crypto_box.rs`'s own
/// `secret_key_rejects_out_of_range_bytes_upper_boundary`): confirms `SecretKey::from_bytes`
/// actually wires up to `curve512::is_valid_scalar`, not a hazmat-level guarantee that happens
/// not to reach this wrapper.
#[test]
fn secret_key_rejects_out_of_range_bytes_upper_boundary() {
    let n = order();
    let mut n_minus_1 = n;
    n_minus_1[63] -= 1;
    let mut n_plus_1 = n;
    n_plus_1[63] += 1;

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
        SecretKey::from_bytes(&[0xFFu8; 64]).is_none(),
        "e=all-0xFF (far above n) must be invalid"
    );
}

/// `docs/TASKS.md` T-183 Group 1: reject trailing garbage appended after an otherwise-valid sealed
/// message, distinct from truncation.
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

/// `docs/TASKS.md` T-183 fourth ("active-attack") category: invalid-curve-shaped inputs -
/// `PublicKey::from_bytes` must reuse `curve512::point_from_x`'s own rejection gauntlet (reject
/// `x in {0,1,p-1}`, non-residues, out-of-subgroup reconstructions), not a second copy.
#[test]
fn public_key_rejects_degenerate_x_values() {
    assert!(
        PublicKey::from_bytes(&[0u8; 64]).is_none(),
        "x=0 must be invalid"
    );
    let mut one = [0u8; 64];
    one[63] = 1;
    assert!(PublicKey::from_bytes(&one).is_none(), "x=1 must be invalid");
    assert!(
        PublicKey::from_bytes(&[0xFFu8; 64]).is_none(),
        "all-0xFF is not even a valid field element (>= p)"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    #[cfg_attr(miri, ignore)] // each case drives multiple full 512-iteration scalar
                              // multiplications (keygen x2, encrypt, decrypt) - too slow to
                              // interpret under Miri, same posture as `crypto_box.rs`'s own
                              // `round_trip_property`.
    fn round_trip_property(message in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
        let public = secret.public_key();
        let sealed = seal(&message, &public).expect("OS CSPRNG available in test environment");
        let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
        prop_assert_eq!(opened, message);
    }
}
