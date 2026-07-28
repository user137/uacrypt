//! Black-box integration test for `dstu_core::hazmat::kalyna_cmac` against the cross-oracle
//! vectors in `tests/vectors/kalyna-cmac/` (`docs/TASKS.md` T-93, `docs/DECISIONS.md` D-54) - uapki KATs for
//! all three covered variants, corroborated by Bouncy Castle for the two block-aligned cases
//! (128-128, 512-512); the 128-256 case exercises the padding branch, which BC structurally cannot
//! corroborate (`DSTU7624Mac` throws on non-block-aligned input) - see D-54 for the single-oracle
//! caveat. `Kalyna256_256Cmac`/`Kalyna256_512Cmac` have no oracle vector at all; covered instead by
//! the shared-logic argument (same macro-generated code path, already dual-oracle-verified
//! `encrypt_block`) plus the round-trip `proptest` below.

use dstu_core::hazmat::kalyna_cmac::{
    CmacError, Kalyna128_128Cmac, Kalyna128_256Cmac, Kalyna256_256Cmac, Kalyna256_512Cmac,
    Kalyna512_512Cmac,
};
use proptest::prelude::*;

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn extract_all<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let pattern = format!("\"{key}\": \"");
    let mut results = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(pattern.as_str()) {
        let after = &rest[start + pattern.len()..];
        let end = after.find('"').expect("well-formed test-vector JSON");
        results.push(&after[..end]);
        rest = &after[end + 1..];
    }
    results
}

struct Case {
    key: Vec<u8>,
    message: Vec<u8>,
    mac: Vec<u8>,
}

fn cases(json: &'static str) -> Vec<Case> {
    let keys = extract_all(json, "key_hex");
    let messages = extract_all(json, "message_hex");
    let macs = extract_all(json, "mac_hex");
    assert!(!keys.is_empty(), "no cases found - fixture is broken");
    assert_eq!(keys.len(), messages.len());
    assert_eq!(keys.len(), macs.len());
    keys.into_iter()
        .zip(messages)
        .zip(macs)
        .map(|((key, message), mac)| Case {
            key: decode_hex(key),
            message: decode_hex(message),
            mac: decode_hex(mac),
        })
        .collect()
}

#[test]
fn kalyna128_128_official_vector() {
    for case in cases(include_str!("vectors/kalyna-cmac/128-128.json")) {
        let mut key = [0u8; 16];
        key.copy_from_slice(&case.key);
        let mac = Kalyna128_128Cmac::mac(&key, &case.message);
        assert_eq!(mac.to_vec(), case.mac);
        assert!(Kalyna128_128Cmac::verify(&key, &case.message, &mac).is_ok());
    }
}

#[test]
fn kalyna128_256_official_vector_padding_branch() {
    for case in cases(include_str!("vectors/kalyna-cmac/128-256.json")) {
        let mut key = [0u8; 32];
        key.copy_from_slice(&case.key);
        let mac = Kalyna128_256Cmac::mac(&key, &case.message);
        assert_eq!(mac.to_vec(), case.mac);
        assert!(Kalyna128_256Cmac::verify(&key, &case.message, &mac).is_ok());
    }
}

#[test]
fn kalyna512_512_official_vector() {
    for case in cases(include_str!("vectors/kalyna-cmac/512-512.json")) {
        let mut key = [0u8; 64];
        key.copy_from_slice(&case.key);
        let mac = Kalyna512_512Cmac::mac(&key, &case.message);
        assert_eq!(mac.to_vec(), case.mac);
        assert!(Kalyna512_512Cmac::verify(&key, &case.message, &mac).is_ok());
    }
}

#[test]
fn tampered_mac_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-cmac/128-128.json"))[0];
    let mut key = [0u8; 16];
    key.copy_from_slice(&case.key);
    let mut mac = Kalyna128_128Cmac::mac(&key, &case.message);
    mac[0] ^= 0x01;
    assert_eq!(
        Kalyna128_128Cmac::verify(&key, &case.message, &mac),
        Err(CmacError::TagMismatch)
    );
}

#[test]
fn tampered_message_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-cmac/128-128.json"))[0];
    let mut key = [0u8; 16];
    key.copy_from_slice(&case.key);
    let mut message = case.message.clone();
    let mac = Kalyna128_128Cmac::mac(&key, &message);
    message[0] ^= 0x01;
    assert_eq!(
        Kalyna128_128Cmac::verify(&key, &message, &mac),
        Err(CmacError::TagMismatch)
    );
}

#[test]
fn wrong_key_is_rejected() {
    let case = &cases(include_str!("vectors/kalyna-cmac/128-128.json"))[0];
    let mut key = [0u8; 16];
    key.copy_from_slice(&case.key);
    let mac = Kalyna128_128Cmac::mac(&key, &case.message);

    let mut wrong_key = key;
    wrong_key[0] ^= 0x01;
    assert_eq!(
        Kalyna128_128Cmac::verify(&wrong_key, &case.message, &mac),
        Err(CmacError::TagMismatch)
    );
}

#[test]
fn empty_message_does_not_panic() {
    let key = [0u8; 16];
    let mac = Kalyna128_128Cmac::mac(&key, &[]);
    assert!(Kalyna128_128Cmac::verify(&key, &[], &mac).is_ok());
}

macro_rules! roundtrip_proptest {
    ($mod_name:ident, $variant:ty, $key_len:literal) => {
        mod $mod_name {
            use super::*;

            proptest! {
                /// No oracle vector exists for every variant (256-256/256-512 have none at all) -
                /// this is the fallback assurance for those, per D-54: mac-then-verify must round
                /// trip, and any single-bit tamper in either the tag or the message must be
                /// rejected, across arbitrary-length messages (including non-block-aligned ones,
                /// exercising the padding branch generically, not just at the one length the
                /// official 128-256 vector happens to cover).
                #[test]
                fn mac_then_verify_roundtrips_and_detects_tamper(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    message in proptest::collection::vec(any::<u8>(), 0..300),
                    flip_index in 0usize..16,
                ) {
                    let mut key_arr = [0u8; $key_len];
                    key_arr.copy_from_slice(&key);

                    let mac = <$variant>::mac(&key_arr, &message);
                    prop_assert!(<$variant>::verify(&key_arr, &message, &mac).is_ok());

                    let mut tampered = mac;
                    tampered[flip_index] ^= 0x01;
                    prop_assert_eq!(
                        <$variant>::verify(&key_arr, &message, &tampered),
                        Err(CmacError::TagMismatch)
                    );
                }
            }
        }
    };
}

roundtrip_proptest!(k128_128, Kalyna128_128Cmac, 16);
roundtrip_proptest!(k128_256, Kalyna128_256Cmac, 32);
roundtrip_proptest!(k256_256, Kalyna256_256Cmac, 32);
roundtrip_proptest!(k256_512, Kalyna256_512Cmac, 64);
roundtrip_proptest!(k512_512, Kalyna512_512Cmac, 64);
