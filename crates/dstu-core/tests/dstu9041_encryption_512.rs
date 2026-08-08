//! Black-box tests for `dstu_core::hazmat::dstu9041::encryption512` (encrypt/decrypt composition
//! for `l(p)=512`, T-192 Phase 4 - see `docs/pseudocode/dstu9041.md`, `docs/DECISIONS.md` D-180).
//! Test-first per T-192's own plan: written before `encryption512` exists. Mirrors
//! `dstu9041_encryption.rs`'s structure and its three CLAUDE.md-mandated categories
//! (correctness/rejection-tamper/misuse-degenerate) plus the D-110/T-152 boundary cluster.

use dstu_core::hazmat::dstu9041::curve512::{base_point, order, Point};
use dstu_core::hazmat::dstu9041::encryption512::{decrypt, encrypt};
use dstu_core::hazmat::dstu9041::fp512::FieldElement;
use proptest::prelude::*;

fn decode_hex_padded(s: &str) -> [u8; 64] {
    let mut padded = String::with_capacity(128);
    for _ in 0..(128 - s.len()) {
        padded.push('0');
    }
    padded.push_str(s);
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).expect("valid hex digit");
    }
    out
}

fn scalar(hex: &str) -> [u8; 64] {
    decode_hex_padded(hex)
}

fn decode_hex_vec(s: &str) -> Vec<u8> {
    let padded;
    let s = if s.len().is_multiple_of(2) {
        s
    } else {
        padded = format!("0{s}");
        &padded
    };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = json.find(pattern.as_str()).expect("key present in vector");
    let after = &json[start + pattern.len()..];
    let end = after.find('"').expect("well-formed test-vector JSON");
    &after[..end]
}

fn point_from_block(json: &str, block_key: &str) -> Point {
    let pattern = format!("\"{block_key}\": {{");
    let start = json.find(pattern.as_str()).expect("block present");
    let block = &json[start..];
    let end = block.find('}').expect("well-formed block");
    let block = &block[..end];
    Point {
        x: FieldElement::from_be_bytes(&decode_hex_padded(extract(block, "x_hex"))),
        y: FieldElement::from_be_bytes(&decode_hex_padded(extract(block, "y_hex"))),
    }
}

const CURVE_VECTOR: &str = include_str!("vectors/dstu9041/curve-E512-1.json");
const EXAMPLE_VECTOR: &str = include_str!("vectors/dstu9041/g3-worked-example.json");

fn q_point() -> Point {
    point_from_block(EXAMPLE_VECTOR, "public_key_Q")
}

fn epsilon() -> [u8; 64] {
    scalar(extract(EXAMPLE_VECTOR, "ephemeral_key_epsilon_hex"))
}

fn private_key_e() -> [u8; 64] {
    scalar(extract(EXAMPLE_VECTOR, "private_key_e_hex"))
}

fn message() -> Vec<u8> {
    decode_hex_vec(extract(EXAMPLE_VECTOR, "message_M_hex"))
}

const MESSAGE_BITS: usize = 256;

fn ciphertext_c() -> [u8; 256] {
    let bytes = decode_hex_vec(extract(EXAMPLE_VECTOR, "ciphertext_C_hex"));
    bytes.try_into().expect("vector's C is 256 bytes")
}

// --- Correctness ---

#[test]
fn encrypt_matches_worked_example_ciphertext() {
    let c = encrypt(&message(), MESSAGE_BITS, q_point(), &epsilon()).expect("valid inputs");
    assert_eq!(c, ciphertext_c());
}

#[test]
fn decrypt_matches_worked_example_message() {
    let (m_tilde, bit_length) =
        decrypt(&ciphertext_c(), &private_key_e()).expect("vector's own ciphertext");
    assert_eq!(bit_length, MESSAGE_BITS);
    let message_bytes = bit_length.div_ceil(8);
    assert_eq!(
        &m_tilde[m_tilde.len() - message_bytes..],
        message().as_slice()
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    #[cfg_attr(miri, ignore = "each case runs 4 full 512-iteration scalar-multiply ladders (Q derivation, R, T, T') - too slow to interpret under Miri, see docs/TASKS.md T-100/T-177/T-192")]
    fn round_trip_encrypt_decrypt(
        message in proptest::collection::vec(any::<u8>(), 1..=53),
        epsilon_byte in 2u8..=250,
        e_byte in 2u8..=250,
    ) {
        let message_bits = message.len() * 8;
        let mut eps = [0u8; 64];
        eps[63] = epsilon_byte;
        let mut e = [0u8; 64];
        e[63] = e_byte;

        let q = base_point().scalar_multiply(&e);
        let c = encrypt(&message, message_bits, q, &eps).expect("within L_MAX_P by construction");
        let (m_tilde, recovered_bits) = decrypt(&c, &e).expect("self-encrypted ciphertext");
        prop_assert_eq!(recovered_bits, message_bits);
        let message_bytes = recovered_bits.div_ceil(8);
        prop_assert_eq!(&m_tilde[m_tilde.len() - message_bytes..], message.as_slice());
    }
}

// --- Rejection / tamper: every case must return Err, never panic ---

#[test]
fn tampered_r_is_rejected() {
    let mut c = ciphertext_c();
    c[0] ^= 0x01;
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn tampered_t_is_rejected() {
    let mut c = ciphertext_c();
    c[200] ^= 0x01;
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn tampered_kw_appended_zero_block_is_rejected() {
    let mut c = ciphertext_c();
    let last = c.len() - 1;
    c[last] ^= 0x01;
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn wrong_private_key_is_rejected() {
    let mut wrong_e = private_key_e();
    wrong_e[63] ^= 0x02;
    assert!(decrypt(&ciphertext_c(), &wrong_e).is_err());
}

#[test]
fn wrong_public_key_is_rejected() {
    let mut other_e = private_key_e();
    other_e[63] ^= 0x04;
    let other_q = base_point().scalar_multiply(&other_e);
    let c = encrypt(&message(), MESSAGE_BITS, other_q, &epsilon()).expect("valid inputs");
    assert!(decrypt(&c, &private_key_e()).is_err());
}

// --- Misuse / degenerate ---

#[test]
fn encrypt_rejects_zero_length_message() {
    assert!(encrypt(&[], 0, q_point(), &epsilon()).is_err());
}

#[test]
fn encrypt_rejects_message_over_l_max_p() {
    let over = [0u8; 54]; // 432 bits > 424
    assert!(encrypt(&over, 432, q_point(), &epsilon()).is_err());
}

#[test]
fn encrypt_rejects_epsilon_out_of_range() {
    assert!(encrypt(&message(), MESSAGE_BITS, q_point(), &[0u8; 64]).is_err());
    let mut one = [0u8; 64];
    one[63] = 1;
    assert!(encrypt(&message(), MESSAGE_BITS, q_point(), &one).is_err());
    let n = order();
    assert!(encrypt(&message(), MESSAGE_BITS, q_point(), &n).is_err());
}

// The boundary-value cluster (same D-176/D-178 findings re-derived for E512/1): r=0, r=1, r=p-1,
// and r^2=a*d^-1 mod p must all reject identically via crafted ciphertext.
#[test]
fn crafted_ciphertext_r_zero_is_rejected() {
    let mut c = [0u8; 256];
    c[64..].copy_from_slice(&[0xAAu8; 192]); // r=0 (all-zero prefix), arbitrary t
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn crafted_ciphertext_r_one_is_rejected() {
    let mut c = [0xAAu8; 256];
    c[..64].copy_from_slice(&[0u8; 64]);
    c[63] = 1;
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn crafted_ciphertext_r_p_minus_one_is_rejected() {
    let p_hex = extract(CURVE_VECTOR, "p_hex");
    let mut c = [0xAAu8; 256];
    let p_minus_1 = FieldElement::from_be_bytes(&decode_hex_padded(p_hex)).sub(FieldElement::ONE);
    c[..64].copy_from_slice(&p_minus_1.to_be_bytes());
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn crafted_ciphertext_r_squared_equals_a_over_d_is_rejected() {
    let a = {
        let mut b = [0u8; 64];
        b[63] = 2;
        FieldElement::from_be_bytes(&b)
    };
    let d = {
        let mut b = [0u8; 64];
        b[62] = 0x01;
        b[63] = 0x0D;
        FieldElement::from_be_bytes(&b)
    };
    let a_over_d = a.multiply(d.invert());
    let r = a_over_d.sqrt();
    assert_eq!(
        r.square(),
        a_over_d,
        "sanity: a/d must actually be a residue for this curve"
    );
    let mut c = [0xAAu8; 256];
    c[..64].copy_from_slice(&r.to_be_bytes());
    assert!(decrypt(&c, &private_key_e()).is_err());
}

// --- Boundary conditions (message-length and epsilon-range positive boundaries) ---

#[test]
fn message_bits_at_exactly_l_max_p_round_trips() {
    let message = [0xAAu8; 53]; // exactly 424 bits, L_MAX_P
    let c =
        encrypt(&message, 424, q_point(), &epsilon()).expect("424 bits == L_MAX_P, must succeed");
    let (m_tilde, bit_length) = decrypt(&c, &private_key_e()).expect("valid ciphertext");
    assert_eq!(bit_length, 424);
    assert_eq!(m_tilde, message);
}

#[test]
fn message_bits_at_l_max_p_minus_one_round_trips() {
    // 423 bits: same 53-byte buffer as the 424-bit case, top bit of the first byte cleared.
    let mut message = [0xAAu8; 53];
    message[0] = 0x2A;
    let c = encrypt(&message, 423, q_point(), &epsilon()).expect("423 <= L_MAX_P");
    let (_m_tilde, bit_length) = decrypt(&c, &private_key_e()).expect("valid ciphertext");
    assert_eq!(bit_length, 423);
}

#[test]
fn message_bits_at_one_round_trips() {
    let message = [0x01u8];
    let c = encrypt(&message, 1, q_point(), &epsilon()).expect("1 bit is the minimum valid length");
    let (m_tilde, bit_length) = decrypt(&c, &private_key_e()).expect("valid ciphertext");
    assert_eq!(bit_length, 1);
    assert_eq!(*m_tilde.last().expect("non-empty"), 0x01);
}

#[test]
fn epsilon_at_minimum_valid_value_round_trips() {
    let mut eps = [0u8; 64];
    eps[63] = 2;
    let c = encrypt(&message(), MESSAGE_BITS, q_point(), &eps).expect("epsilon=2 is valid");
    assert!(decrypt(&c, &private_key_e()).is_ok());
}

#[test]
fn epsilon_at_maximum_valid_value_round_trips() {
    let mut eps = order();
    eps[63] -= 2;
    let c = encrypt(&message(), MESSAGE_BITS, q_point(), &eps).expect("epsilon=n-2 is valid");
    assert!(decrypt(&c, &private_key_e()).is_ok());
}
