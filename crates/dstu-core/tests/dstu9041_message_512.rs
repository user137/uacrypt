//! Black-box tests for `dstu_core::hazmat::dstu9041::message512` (T-192 Phase 3 - see
//! `docs/pseudocode/dstu9041.md` "Message formatting", Table 1's `l(p)=512` row). Test-first per
//! T-192's own plan: written before `message512` exists.
//!
//! No Додаток Г.3 worked example is transcribed yet (that's T-192 Phase 4) - unlike
//! `dstu9041_message.rs`, this file has no vector-matching tests for `build_m_prime`/
//! `kw_plaintext_from_m_prime`/`parse_m_prime`'s exact output against a real worked example; it
//! checks internal self-consistency (round-trip, boundary lengths) instead. See
//! `message512.rs`'s own doc comment for why `kw_plaintext_from_m_prime`'s shape is provisional
//! until Phase 4 confirms it against Додаток Г.3, same posture this project uses elsewhere for an
//! empirical-but-unconfirmed primitive (D-15/D-41's pattern).

use dstu_core::hazmat::dstu9041::message512::{
    build_m_prime, encode_l_m_tilde, format_m_tilde, kw_plaintext_from_m_prime, parse_m_prime,
    L_MAX_P,
};
use proptest::prelude::*;

#[test]
fn format_m_tilde_rejects_message_over_l_max_p() {
    let message = [0u8; 54]; // 432 bits > L_MAX_P (424 bits)
    assert!(format_m_tilde(&message, L_MAX_P + 8).is_err());
}

#[test]
fn format_m_tilde_accepts_message_at_exactly_l_max_p() {
    let message = [0xAAu8; 53]; // exactly 424 bits
    assert!(format_m_tilde(&message, L_MAX_P).is_ok());
}

#[test]
fn format_m_tilde_rejects_zero_length_message() {
    let message = [0u8; 1];
    assert!(format_m_tilde(&message, 0).is_err());
}

#[test]
fn format_m_tilde_rejects_length_mismatch() {
    let message = [0u8; 2];
    assert!(format_m_tilde(&message, 8).is_err()); // message_bits says 1 byte, slice has 2
}

#[test]
fn kw_plaintext_appends_exactly_one_zero_block() {
    // Structural check, not a vector match (none exists yet, see this file's own doc comment):
    // M' is 64 bytes (one Kalyna-512 block); the provisional convention appends one more
    // all-zero 64-byte block, mirroring l(p)=256's own confirmed "M' || 0x00*32" shape at this
    // field width.
    let message = [0x11u8; 53];
    let m_tilde = format_m_tilde(&message, L_MAX_P).unwrap();
    let l_m_tilde = encode_l_m_tilde(L_MAX_P);
    let m_prime = build_m_prime(0x01, &m_tilde, &l_m_tilde);

    let kw_plaintext = kw_plaintext_from_m_prime(&m_prime);
    assert_eq!(kw_plaintext.len(), 128);
    assert_eq!(&kw_plaintext[..64], &m_prime);
    assert_eq!(&kw_plaintext[64..], &[0u8; 64]);
}

#[test]
fn parse_m_prime_round_trips_a_hand_built_m_prime() {
    let message = [0x42u8; 53];
    let m_tilde = format_m_tilde(&message, L_MAX_P).unwrap();
    let l_m_tilde = encode_l_m_tilde(L_MAX_P);
    let m_prime = build_m_prime(0x01, &m_tilde, &l_m_tilde);

    let parsed = parse_m_prime(&m_prime).expect("self-built M' must always parse");
    assert_eq!(parsed.hash_id, 0x01);
    assert_eq!(parsed.bit_length, L_MAX_P);
    assert_eq!(parsed.m_tilde, m_tilde);
}

#[test]
fn parse_m_prime_rejects_tampered_hash() {
    let message = [0x77u8; 53];
    let m_tilde = format_m_tilde(&message, L_MAX_P).unwrap();
    let l_m_tilde = encode_l_m_tilde(L_MAX_P);
    let mut m_prime = build_m_prime(0x01, &m_tilde, &l_m_tilde);
    m_prime[1] ^= 0xFF; // flip a byte inside the embedded hash field
    assert!(parse_m_prime(&m_prime).is_err());
}

#[test]
fn parse_m_prime_rejects_nonzero_padding() {
    let message = [0xFFu8; 10]; // short message, most of m_tilde is zero padding
    let message_bits = 80;
    let m_tilde = format_m_tilde(&message, message_bits).unwrap();
    let l_m_tilde = encode_l_m_tilde(message_bits);
    let mut m_prime = build_m_prime(0x01, &m_tilde, &l_m_tilde);
    // corrupt a padding byte (index 11 = 1(hash_id) + 8(l_H bytes) + 2(l_m_tilde) = start of
    // m_tilde, still within the zero-padded region since message_bits=80 < L_MAX_P=424)
    m_prime[11] = 0x01;
    assert!(parse_m_prime(&m_prime).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn parse_m_prime_round_trips_build_m_prime(
        hash_id in any::<u8>(),
        message in proptest::collection::vec(any::<u8>(), 1..=53),
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
