//! Black-box tests for `dstu_core::hazmat::dstu9041::message384` (T-297 - Table 1's `l(p)=384` row,
//! `docs/DECISIONS.md` D-241/D-244). `M'` is checked against Додаток Г.2's printed `M'` (which uses
//! the printed `H` exactly); the rest mirrors `dstu9041_message_512.rs`.

use dstu_core::hazmat::dstu9041::message384::{
    build_m_prime, encode_l_m_tilde, format_m_tilde, parse_m_prime, L_MAX_P,
};
use proptest::prelude::*;

fn field(json: &str, key: &str) -> Vec<u8> {
    let pattern = format!("\"{key}\": \"");
    let start = json.find(pattern.as_str()).expect("key present") + pattern.len();
    let end = json[start..].find('"').expect("closing quote");
    let s = &json[start..start + end];
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

#[test]
fn l_max_p_is_table_1s_296_bits() {
    assert_eq!(L_MAX_P, 296);
}

#[test]
fn build_m_prime_matches_g2_worked_example() {
    let json = include_str!("vectors/dstu9041/g2-worked-example.json");
    let message = field(json, "message_M_hex");
    let m_tilde = format_m_tilde(&message, 256).expect("256-bit message");
    let m_prime = build_m_prime(0x01, &m_tilde, &encode_l_m_tilde(256));
    assert_eq!(m_prime.as_slice(), field(json, "M_prime_hex").as_slice());
    assert_eq!(&m_prime[1..9], field(json, "H_hex").as_slice());
}

#[test]
fn format_m_tilde_rejects_message_over_l_max_p() {
    let message = [0u8; 38]; // 304 bits > L_MAX_P (296 bits)
    assert!(format_m_tilde(&message, L_MAX_P + 8).is_err());
}

#[test]
fn format_m_tilde_accepts_message_at_exactly_l_max_p() {
    let message = [0xAAu8; 37]; // exactly 296 bits
    assert!(format_m_tilde(&message, L_MAX_P).is_ok());
}

#[test]
fn format_m_tilde_rejects_zero_length_message() {
    assert!(format_m_tilde(&[0u8; 1], 0).is_err());
}

#[test]
fn format_m_tilde_rejects_length_mismatch() {
    assert!(format_m_tilde(&[0u8; 2], 8).is_err()); // message_bits says 1 byte, slice has 2
}

#[test]
fn m_prime_is_48_bytes_not_a_kalyna_256_multiple() {
    let m_tilde = format_m_tilde(&[0x11u8; 37], L_MAX_P).expect("in range");
    let m_prime = build_m_prime(0x01, &m_tilde, &encode_l_m_tilde(L_MAX_P));
    assert_eq!(m_prime.len(), 48);
    assert_ne!(m_prime.len() % 32, 0, "why l(p)=384 needs KW-p (D-241)");
}

#[test]
fn parse_m_prime_round_trips_a_hand_built_m_prime() {
    let m_tilde = format_m_tilde(&[0x42u8; 37], L_MAX_P).expect("in range");
    let m_prime = build_m_prime(0x01, &m_tilde, &encode_l_m_tilde(L_MAX_P));
    let parsed = parse_m_prime(&m_prime).expect("self-built M' must always parse");
    assert_eq!(parsed.hash_id, 0x01);
    assert_eq!(parsed.bit_length, L_MAX_P);
    assert_eq!(parsed.m_tilde, m_tilde);
}

#[test]
fn parse_m_prime_rejects_tampered_hash() {
    let m_tilde = format_m_tilde(&[0x77u8; 37], L_MAX_P).expect("in range");
    let mut m_prime = build_m_prime(0x01, &m_tilde, &encode_l_m_tilde(L_MAX_P));
    m_prime[1] ^= 0xFF;
    assert!(parse_m_prime(&m_prime).is_err());
}

#[test]
fn parse_m_prime_rejects_nonzero_padding() {
    let m_tilde = format_m_tilde(&[0xFFu8; 10], 80).expect("in range");
    let mut m_prime = build_m_prime(0x01, &m_tilde, &encode_l_m_tilde(80));
    // index 11 = 1 (hash id) + 8 (hash) + 2 (length): the first M~ byte, zero padding at 80 bits
    m_prime[11] = 0x01;
    assert!(parse_m_prime(&m_prime).is_err());
}

#[test]
fn parse_m_prime_rejects_length_over_l_max_p() {
    let m_tilde = format_m_tilde(&[0x01u8; 37], L_MAX_P).expect("in range");
    let mut m_prime = build_m_prime(0x01, &m_tilde, &encode_l_m_tilde(L_MAX_P));
    m_prime[9..11].copy_from_slice(&304u16.to_be_bytes());
    assert!(parse_m_prime(&m_prime).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn parse_m_prime_round_trips_build_m_prime(
        hash_id in any::<u8>(),
        message in proptest::collection::vec(any::<u8>(), 1..=37),
    ) {
        let message_bits = message.len() * 8;
        let m_tilde = format_m_tilde(&message, message_bits).expect("within L_MAX_P by construction");
        let m_prime = build_m_prime(hash_id, &m_tilde, &encode_l_m_tilde(message_bits));
        let parsed = parse_m_prime(&m_prime).expect("self-built M' must always parse");
        prop_assert_eq!(parsed.hash_id, hash_id);
        prop_assert_eq!(parsed.bit_length, message_bits);
        prop_assert_eq!(parsed.m_tilde, m_tilde);
    }
}
