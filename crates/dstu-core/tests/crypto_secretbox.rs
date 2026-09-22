//! Tests for `dstu_core::crypto_secretbox` (`docs/TASKS.md` T-37, `docs/DECISIONS.md` D-51, migrated to
//! Kalyna-GCM by roadmap Step 3 item 1, `docs/DECISIONS.md` D-63) - a single fixed
//! `hazmat::kalyna_gcm::Kalyna256_256Gcm` construction with an internally-generated nonce and a
//! combined `version || nonce || ciphertext || tag` wire format. No external oracle exists for this specific
//! framing (it's this crate's own construction over an already-oracle-verified primitive), so
//! verification here is property + tamper + a direct byte-layout pin against `hazmat::kalyna_gcm`
//! itself, the same posture already used for `crypto_kdf`/`crypto_sign`.

#![cfg(feature = "std")]

use dstu_core::crypto_secretbox::{open, seal, SecretKey, SecretboxError};
use dstu_core::hazmat::kalyna_gcm::Kalyna256_256Gcm;
use proptest::prelude::*;

const VERSION: u8 = 2;
const NONCE_LEN: usize = 32;
/// `version (1) || nonce (32)` - everything in front of the ciphertext.
const HEADER_LEN: usize = 1 + NONCE_LEN;
const TAG_LEN: usize = 16;
const BLOCK_LEN: usize = 32;

/// Inserts `80 00..` between ciphertext and tag, up to the next 32-byte Kalyna-256 block boundary
/// (a full block if already aligned) - `hazmat::kalyna_gcm`'s own ciphertext padding (D-56
/// divergence 2), which F-01 (T-232) showed shares a tag with the unpadded ciphertext unless the
/// true length is bound in separately.
fn append_gcm_padding(sealed: &[u8]) -> Vec<u8> {
    let ct_len = sealed.len() - HEADER_LEN - TAG_LEN;
    let pad_len = BLOCK_LEN - ct_len % BLOCK_LEN;
    let tag_start = sealed.len() - TAG_LEN;
    let mut forged = sealed[..tag_start].to_vec();
    forged.push(0x80);
    forged.resize(tag_start + pad_len, 0);
    forged.extend_from_slice(&sealed[tag_start..]);
    forged
}

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
    assert_eq!(sealed.len(), HEADER_LEN + TAG_LEN);
    let opened = open(&key, &sealed).expect("valid ciphertext under the right key");
    assert_eq!(opened, Vec::<u8>::new());
}

/// Kalyna-GCM (unlike the previous Kalyna-CCM construction, D-41) encodes no length cap into
/// itself - `docs/DECISIONS.md` D-63. This message is well past the old 255-byte `kalyna_ccm` limit;
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
        &a[1..HEADER_LEN],
        &b[1..HEADER_LEN],
        "a fresh random nonce must be drawn per call"
    );
    assert_ne!(a, b);
}

#[test]
fn truncated_input_is_rejected_not_a_panic() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    for len in [0usize, 1, 20, HEADER_LEN + TAG_LEN - 1] {
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
/// `docs/DECISIONS.md` D-63) - `hazmat::kalyna_gcm`'s own tag does not cover `iv` (see that module's
/// "Warning" doc section), so this would fail without it.
#[test]
fn tampered_nonce_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let mut sealed = seal(&key, b"secret").expect("OS CSPRNG available in test environment");
    sealed[1] ^= 0xFF;
    let err = open(&key, &sealed).expect_err("tampered nonce must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let mut sealed = seal(&key, b"secret").expect("OS CSPRNG available in test environment");
    sealed[HEADER_LEN] ^= 0xFF;
    let err = open(&key, &sealed).expect_err("tampered ciphertext must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

#[test]
fn unknown_version_byte_is_rejected_with_its_own_error() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed = seal(&key, b"secret").expect("OS CSPRNG available in test environment");
    assert_eq!(sealed[0], VERSION);
    for version in [0u8, 1, 3, 0xFF] {
        let mut other = sealed.clone();
        other[0] = version;
        let err = open(&key, &other).expect_err("only the current format version is accepted");
        assert!(
            matches!(err, SecretboxError::UnsupportedVersion),
            "version = {version}"
        );
    }
}

/// V5(a), T-232/F-01: appending `80 00..` to a non-block-aligned ciphertext used to open
/// successfully, returning the original plaintext plus attacker-appended keystream bytes.
#[test]
fn appended_gcm_padding_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed =
        seal(&key, b"PAY 100 UAH TO ALICE").expect("OS CSPRNG available in test environment");
    let forged = append_gcm_padding(&sealed);
    assert_eq!(forged.len(), HEADER_LEN + BLOCK_LEN + TAG_LEN);
    let err = open(&key, &forged).expect_err("an extended ciphertext must fail authentication");
    assert!(matches!(err, SecretboxError::TagMismatch));
}

/// V5(b), T-232/F-01: a block-aligned ciphertext ending in `0x80` with that byte removed used to
/// verify under the same tag. Retries `seal` until the last ciphertext byte is `0x80` (~1/256 per
/// try; 4096 tries miss with probability ~1e-7) - too many GCM calls to run under Miri.
#[test]
#[cfg_attr(miri, ignore)]
fn truncated_trailing_0x80_is_rejected() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let tag_start = HEADER_LEN + BLOCK_LEN;
    let sealed = (0..4096)
        .map(|_| seal(&key, &[0x55; BLOCK_LEN]).expect("OS CSPRNG available in test environment"))
        .find(|sealed| sealed[tag_start - 1] == 0x80)
        .expect("a ciphertext ending in 0x80 within 4096 tries");
    let mut forged = sealed[..tag_start - 1].to_vec();
    forged.extend_from_slice(&sealed[tag_start..]);
    let err = open(&key, &forged).expect_err("a shortened ciphertext must fail authentication");
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

/// Confirms `seal`'s output is exactly `version (1) || nonce (32) || ciphertext || tag (16)`, not
/// just "something that round-trips through `open`" - pinned directly against a manual
/// `hazmat::kalyna_gcm` call using the nonce `seal` actually drew (`CLAUDE.md`'s "check what a
/// fixed vector actually exercises"). The tag is the first `TAG_LEN` bytes of GCM's full-block tag
/// (D-63), and the AAD is `version || nonce || ciphertext_len as u64 LE` (T-232) - any other AAD
/// produces a different tag and fails this test.
#[test]
fn wire_format_is_version_nonce_ciphertext_tag() {
    let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"pin the layout";
    let sealed = seal(&key, plaintext).expect("Kalyna-GCM has no message-length cap");

    assert_eq!(sealed[0], VERSION);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[1..HEADER_LEN]);
    let ciphertext_len = sealed.len() - HEADER_LEN - TAG_LEN;
    assert_eq!(ciphertext_len, plaintext.len());

    let mut aad = vec![VERSION];
    aad.extend_from_slice(&nonce);
    aad.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());

    let mut buf = vec![0u8; plaintext.len()];
    let cipher = Kalyna256_256Gcm::new(key.as_bytes());
    let tag = cipher
        .encrypt(&nonce, &aad, plaintext, &mut buf)
        .expect("plaintext/ciphertext_out lengths match");

    assert_eq!(
        &sealed[HEADER_LEN..HEADER_LEN + ciphertext_len],
        buf.as_slice(),
        "ciphertext must match a direct hazmat call with the same nonce"
    );
    assert_eq!(
        &sealed[HEADER_LEN + ciphertext_len..],
        &tag[..TAG_LEN],
        "tag must match a direct hazmat call with the same nonce and AAD, truncated like seal does"
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

    /// T-232/F-01 negative property: extending any sealed blob with `80 00..` never opens.
    #[test]
    fn appended_gcm_padding_never_opens(plaintext in proptest::collection::vec(any::<u8>(), 0..=256)) {
        let key = SecretKey::generate().expect("OS CSPRNG available in test environment");
        let sealed = seal(&key, &plaintext).expect("Kalyna-GCM has no message-length cap");
        prop_assert!(open(&key, &append_gcm_padding(&sealed)).is_err());
    }
}
