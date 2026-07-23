//! Official-vector tests for `hazmat::kupyna_kmac` (DSTU 7564:2014's MAC mode, `DECISIONS.md`
//! D-44) - dual-oracle-cited (UAPKI C + Bouncy Castle Java), still provisional pending the primary
//! standard text, see `docs/pseudocode/kupyna-kmac.md`. Same hand-rolled extractor convention as
//! `tests/kalyna_ccm.rs`.

use dstu_core::hazmat::kupyna_kmac::{KmacError, Kupyna256Kmac, Kupyna384Kmac, Kupyna512Kmac};

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "odd-length hex string in test vector: {s}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit in test vector"))
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
    assert!(
        !keys.is_empty(),
        "no cases found - extractor or fixture is broken"
    );
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
fn kmac_256_official_vector() {
    for case in cases(include_str!("vectors/kupyna-kmac/kmac-256.json")) {
        let mac = Kupyna256Kmac::mac(&case.key, &case.message).expect("valid key length");
        assert_eq!(mac.to_vec(), case.mac);
        assert!(Kupyna256Kmac::verify(&case.key, &case.message, &mac).is_ok());
    }
}

#[test]
fn kmac_384_official_vector() {
    for case in cases(include_str!("vectors/kupyna-kmac/kmac-384.json")) {
        let mac = Kupyna384Kmac::mac(&case.key, &case.message).expect("valid key length");
        assert_eq!(mac.to_vec(), case.mac);
        assert!(Kupyna384Kmac::verify(&case.key, &case.message, &mac).is_ok());
    }
}

#[test]
fn kmac_512_official_vector() {
    for case in cases(include_str!("vectors/kupyna-kmac/kmac-512.json")) {
        let mac = Kupyna512Kmac::mac(&case.key, &case.message).expect("valid key length");
        assert_eq!(mac.to_vec(), case.mac);
        assert!(Kupyna512Kmac::verify(&case.key, &case.message, &mac).is_ok());
    }
}

#[test]
fn wrong_key_length_is_rejected() {
    let short_key = [0u8; 16];
    let message = b"message";
    assert_eq!(
        Kupyna256Kmac::mac(&short_key, message),
        Err(KmacError::WrongKeyLength)
    );
}

#[test]
fn tampered_mac_is_rejected() {
    let case = &cases(include_str!("vectors/kupyna-kmac/kmac-256.json"))[0];
    let mut mac = Kupyna256Kmac::mac(&case.key, &case.message).unwrap();
    mac[0] ^= 0x01;
    assert_eq!(
        Kupyna256Kmac::verify(&case.key, &case.message, &mac),
        Err(KmacError::TagMismatch)
    );
}

#[test]
fn tampered_message_is_rejected() {
    let case = &cases(include_str!("vectors/kupyna-kmac/kmac-256.json"))[0];
    let mut message = case.message.clone();
    let mac = Kupyna256Kmac::mac(&case.key, &message).unwrap();
    message[0] ^= 0x01;
    assert_eq!(
        Kupyna256Kmac::verify(&case.key, &message, &mac),
        Err(KmacError::TagMismatch)
    );
}
