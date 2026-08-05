//! Black-box tests for `dstu_core::hazmat::dstu9041::message` against
//! `tests/vectors/dstu9041/g1-worked-example.json` (`l(p)=256`, Додаток Г.1 - see
//! `docs/pseudocode/dstu9041.md` and `docs/DECISIONS.md` D-163/D-165/D-166). Test-first per T-177:
//! written before `hazmat::dstu9041::message` exists, per this project's own standing rule.

use dstu_core::hazmat::dstu9041::message::{
    build_m_prime, encode_l_m_tilde, format_m_tilde, kw_plaintext_from_m_prime, parse_m_prime,
    L_MAX_P,
};
use proptest::prelude::*;

fn decode_hex(s: &str) -> Vec<u8> {
    let padded;
    let s = if s.len().is_multiple_of(2) {
        s
    } else {
        padded = format!("0{s}");
        &padded
    };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit in test vector"))
        .collect()
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = json.find(pattern.as_str()).expect("key present in vector");
    let after = &json[start + pattern.len()..];
    let end = after.find('"').expect("well-formed test-vector JSON");
    &after[..end]
}

const VECTOR: &str = include_str!("vectors/dstu9041/g1-worked-example.json");

// The vector's own `message_M_bits` is a bare JSON number (128), not a quoted string - hardcoded
// here rather than parsed, cited directly to the vector file's own field of the same name.
const MESSAGE_BITS: usize = 128;

#[test]
fn build_m_prime_matches_worked_example() {
    let message = decode_hex(extract(VECTOR, "message_M_hex"));
    let m_tilde = format_m_tilde(&message, MESSAGE_BITS).expect("128 bits <= L_MAX_P");
    let l_m_tilde = encode_l_m_tilde(MESSAGE_BITS);
    let m_prime = build_m_prime(0x01, &m_tilde, &l_m_tilde);

    let expected = decode_hex(extract(VECTOR, "M_prime_hex"));
    assert_eq!(m_prime.to_vec(), expected);
}

#[test]
fn kw_plaintext_matches_worked_example() {
    let message = decode_hex(extract(VECTOR, "message_M_hex"));
    let m_tilde = format_m_tilde(&message, MESSAGE_BITS).unwrap();
    let l_m_tilde = encode_l_m_tilde(MESSAGE_BITS);
    let m_prime = build_m_prime(0x01, &m_tilde, &l_m_tilde);

    let kw_plaintext = kw_plaintext_from_m_prime(&m_prime);
    let expected = decode_hex(extract(VECTOR, "kalyna_kw_plaintext_hex"));
    assert_eq!(kw_plaintext.to_vec(), expected);
}

/// The negative/regression counterpart: `M'` alone (without the extra all-zero block) must NOT
/// reproduce the vector's own KW-input length or content - protects the padding quirk
/// (`docs/pseudocode/dstu9041.md`'s "Open question", D-165) from a future "this looks redundant,
/// let's simplify" edit silently reintroducing the bug two sessions already spent confirming.
#[test]
fn kw_plaintext_without_extra_block_does_not_match_vector() {
    let message = decode_hex(extract(VECTOR, "message_M_hex"));
    let m_tilde = format_m_tilde(&message, MESSAGE_BITS).unwrap();
    let l_m_tilde = encode_l_m_tilde(MESSAGE_BITS);
    let m_prime = build_m_prime(0x01, &m_tilde, &l_m_tilde);

    let expected_kw_plaintext = decode_hex(extract(VECTOR, "kalyna_kw_plaintext_hex"));
    assert_ne!(m_prime.len(), expected_kw_plaintext.len());
    assert_ne!(m_prime.to_vec(), expected_kw_plaintext);
}

#[test]
fn hash_field_matches_worked_example() {
    let message = decode_hex(extract(VECTOR, "message_M_hex"));
    let m_tilde = format_m_tilde(&message, MESSAGE_BITS).unwrap();
    let l_m_tilde = encode_l_m_tilde(MESSAGE_BITS);

    let mut hashed_input = Vec::with_capacity(l_m_tilde.len() + m_tilde.len());
    hashed_input.extend_from_slice(&l_m_tilde);
    hashed_input.extend_from_slice(&m_tilde);
    let digest = dstu_core::hazmat::kupyna::Kupyna256::digest(&hashed_input);

    // clause 5.7: truncate to l_H=32 bits, taken from the hash's LOW-order end (verified in
    // docs/pseudocode/dstu9041.md's "Verification performed" section).
    assert_eq!(&digest[28..32], &[0xBF, 0x8B, 0x86, 0x20]);
}

#[test]
fn format_m_tilde_rejects_message_over_l_max_p() {
    let message = [0u8; 26]; // 208 bits > L_MAX_P (200 bits)
    assert!(format_m_tilde(&message, L_MAX_P + 8).is_err());
}

#[test]
fn format_m_tilde_accepts_message_at_exactly_l_max_p() {
    // Boundary: L_MAX_P itself must succeed, not be rejected - the positive counterpart to the
    // "over" test above (an off-by-one on this comparison is the same shape as a field-modulus
    // boundary bug, just at the message layer).
    let message = [0xAAu8; 25]; // exactly 200 bits
    assert!(format_m_tilde(&message, L_MAX_P).is_ok());
}

#[test]
fn format_m_tilde_rejects_zero_length_message() {
    let message = [0u8; 1];
    assert!(format_m_tilde(&message, 0).is_err());
}

#[test]
fn parse_m_prime_recovers_worked_example_message() {
    let m_prime = decode_hex(extract(VECTOR, "M_prime_hex"));
    let m_prime: [u8; 32] = m_prime.try_into().unwrap();
    let parsed = parse_m_prime(&m_prime).expect("vector's own M' must parse");
    assert_eq!(parsed.bit_length, MESSAGE_BITS);
    let recovered_message = &parsed.m_tilde[parsed.m_tilde.len() - MESSAGE_BITS / 8..];
    assert_eq!(
        recovered_message,
        decode_hex(extract(VECTOR, "message_M_hex"))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn parse_m_prime_round_trips_build_m_prime(
        hash_id in any::<u8>(),
        // Byte-aligned messages only (message_bits == message.len()*8) - keeps the property test
        // free of the "top unused bits of a non-byte-aligned message must already be zero"
        // precondition (clause 5.1's convention), which every real caller in this crate satisfies
        // by construction anyway (`hazmat` message buffers are always whole bytes).
        message in proptest::collection::vec(any::<u8>(), 1..=25),
    ) {
        let message_bits = message.len() * 8;
        let m_tilde = format_m_tilde(&message, message_bits).expect("within L_MAX_P by construction");
        let l_m_tilde = encode_l_m_tilde(message_bits);
        let m_prime = build_m_prime(hash_id, &m_tilde, &l_m_tilde);

        let parsed = parse_m_prime(&m_prime).expect("self-built M' must always parse");
        prop_assert_eq!(parsed.hash_id, hash_id);
        prop_assert_eq!(parsed.bit_length, message_bits);
        prop_assert_eq!(parsed.m_tilde, m_tilde);
    }
}
