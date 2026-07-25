//! Tests for `dstu_core::crypto_auth` (`TASKS.md` T-105, `DECISIONS.md` D-66) - the
//! libsodium-ergonomics wrapper over `hazmat::kupyna_kmac::Kupyna256Kmac`. `Kupyna256Kmac` itself
//! is already official-vector-tested (`tests/kupyna_kmac.rs`); this file exercises delegation
//! (correctness), tamper/wrong-key rejection, and misuse (degenerate-but-legal inputs) at this
//! wrapper's own layer, per `CLAUDE.md`'s standing three-category rule (D-64/D-65).
//! `WrongKeyLength` is not exercised here - `Key`'s fixed `[u8; 32]` constructor forecloses it at
//! the type level, see the module doc and D-66.

use dstu_core::crypto_auth::{auth, verify, Key, TagMismatch};
use dstu_core::hazmat::kupyna_kmac::Kupyna256Kmac;

#[test]
fn auth_matches_hazmat_kupyna256_kmac() {
    let raw_key = [0x5Au8; 32];
    let message = b"a real message";
    let key = Key::from_bytes(raw_key);

    let tag = auth(&key, message);
    let expected = Kupyna256Kmac::mac(&raw_key, message).unwrap();
    assert_eq!(tag, expected);
}

#[test]
fn verify_roundtrip_succeeds() {
    let key = Key::from_bytes([0x11u8; 32]);
    let message = b"hello crypto_auth";
    let tag = auth(&key, message);
    assert_eq!(verify(&key, message, &tag), Ok(()));
}

#[test]
fn tampered_tag_is_rejected() {
    let key = Key::from_bytes([0x22u8; 32]);
    let message = b"hello crypto_auth";
    let mut tag = auth(&key, message);
    tag[0] ^= 0x01;
    assert_eq!(verify(&key, message, &tag), Err(TagMismatch));
}

#[test]
fn tampered_message_is_rejected() {
    let key = Key::from_bytes([0x33u8; 32]);
    let tag = auth(&key, b"original message");
    assert_eq!(verify(&key, b"different message", &tag), Err(TagMismatch));
}

#[test]
fn wrong_key_is_rejected() {
    let key_a = Key::from_bytes([0x44u8; 32]);
    let key_b = Key::from_bytes([0x45u8; 32]);
    let message = b"hello crypto_auth";
    let tag = auth(&key_a, message);
    assert_eq!(verify(&key_b, message, &tag), Err(TagMismatch));
}

#[test]
fn empty_message_succeeds() {
    let key = Key::from_bytes([0x66u8; 32]);
    let tag = auth(&key, b"");
    assert_eq!(verify(&key, b"", &tag), Ok(()));
}

#[test]
fn all_zero_key_succeeds() {
    let key = Key::from_bytes([0u8; 32]);
    let message = b"degenerate but legal";
    let tag = auth(&key, message);
    assert_eq!(verify(&key, message, &tag), Ok(()));
}

#[cfg(feature = "std")]
#[test]
fn generate_produces_a_usable_key() {
    let key = Key::generate().expect("OS CSPRNG available in tests");
    let message = b"generated key roundtrip";
    let tag = auth(&key, message);
    assert_eq!(verify(&key, message, &tag), Ok(()));
}
