//! Black-box tests for `dstu_core::hazmat::dstu9041::encryption384` (encrypt/decrypt for
//! `l(p)=384`, T-297 - `docs/DECISIONS.md` D-241/D-244). Generated from
//! `dstu9041_encryption_512.rs` by script, same categories (correctness, rejection/tamper,
//! misuse/degenerate, the D-110/T-152 boundary cluster). Correctness anchors on what Додаток Г.2
//! confirms (`r`, `kappa`, `M'`) and pins its printed `t` as not DSTU 7624 KW-p (D-241).

use dstu_core::hazmat::dstu9041::curve384::{base_point, order, Point};
use dstu_core::hazmat::dstu9041::encryption384::{
    decrypt, encrypt, EncryptError, CIPHERTEXT_BYTES,
};
use dstu_core::hazmat::dstu9041::fp384::FieldElement;
use dstu_core::hazmat::kalyna_kw_p::Kalyna256_256KwP;
use proptest::prelude::*;

fn decode_hex_padded(s: &str) -> [u8; 48] {
    let mut padded = String::with_capacity(96);
    for _ in 0..(96 - s.len()) {
        padded.push('0');
    }
    padded.push_str(s);
    let mut out = [0u8; 48];
    for i in 0..48 {
        out[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).expect("valid hex digit");
    }
    out
}

fn scalar(hex: &str) -> [u8; 48] {
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

const CURVE_VECTOR: &str = include_str!("vectors/dstu9041/curve-E384-1.json");
const EXAMPLE_VECTOR: &str = include_str!("vectors/dstu9041/g2-worked-example.json");

fn q_point() -> Point {
    point_from_block(EXAMPLE_VECTOR, "public_key_Q")
}

fn epsilon() -> [u8; 48] {
    scalar(extract(EXAMPLE_VECTOR, "ephemeral_key_epsilon_hex"))
}

fn private_key_e() -> [u8; 48] {
    scalar(extract(EXAMPLE_VECTOR, "private_key_e_hex"))
}

fn message() -> Vec<u8> {
    decode_hex_vec(extract(EXAMPLE_VECTOR, "message_M_hex"))
}

const MESSAGE_BITS: usize = 256;

/// A ciphertext this crate produced for the worked example's inputs - Г.2's own `C` does not
/// follow DSTU 7624 §15.4 (D-241), so the tamper tests below start from this one.
fn ciphertext_c() -> [u8; CIPHERTEXT_BYTES] {
    encrypt(&message(), MESSAGE_BITS, q_point(), &epsilon()).expect("valid inputs")
}

// --- Correctness ---

#[test]
fn encrypt_r_matches_worked_example() {
    let c = ciphertext_c();
    assert_eq!(
        &c[..48],
        decode_hex_vec(extract(EXAMPLE_VECTOR, "printed_ciphertext_C_hex"))[..48].as_ref()
    );
}

/// `t` is Kalyna-256/256-KW-p of the document's printed `M'` under its printed `kappa` - both of
/// which this crate reproduces exactly (D-241) - so this pins the composition to the document.
#[test]
fn encrypt_t_is_kw_p_of_the_printed_m_prime_under_the_printed_kappa() {
    let kappa: [u8; 32] = decode_hex_vec(extract(EXAMPLE_VECTOR, "kappa_kw_key_hex"))
        .try_into()
        .expect("32-byte kappa");
    let m_prime = decode_hex_vec(extract(EXAMPLE_VECTOR, "M_prime_hex"));
    let mut t = [0u8; 128];
    Kalyna256_256KwP::wrap(&kappa, &m_prime, &mut t).expect("48-byte M'");
    assert_eq!(&ciphertext_c()[48..], t.as_slice());
}

#[test]
fn decrypt_round_trips_the_worked_example_message() {
    let (m_tilde, bit_length) =
        decrypt(&ciphertext_c(), &private_key_e()).expect("this crate's own ciphertext");
    assert_eq!(bit_length, MESSAGE_BITS);
    let message_bytes = bit_length.div_ceil(8);
    assert_eq!(
        &m_tilde[m_tilde.len() - message_bytes..],
        message().as_slice()
    );
}

/// The divergence D-241 records, pinned: the document's own `C` is refused.
#[test]
fn decrypt_rejects_the_documents_printed_ciphertext() {
    let printed: [u8; CIPHERTEXT_BYTES] =
        decode_hex_vec(extract(EXAMPLE_VECTOR, "printed_ciphertext_C_hex"))
            .try_into()
            .expect("176-byte C");
    assert_ne!(printed, ciphertext_c());
    assert!(decrypt(&printed, &private_key_e()).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    #[cfg_attr(miri, ignore = "each case runs 4 full 384-iteration scalar-multiply ladders (Q derivation, R, T, T') - too slow to interpret under Miri, see docs/TASKS.md T-100/T-177/T-297")]
    fn round_trip_encrypt_decrypt(
        message in proptest::collection::vec(any::<u8>(), 1..=37),
        epsilon_byte in 2u8..=250,
        e_byte in 2u8..=250,
    ) {
        let message_bits = message.len() * 8;
        let mut eps = [0u8; 48];
        eps[47] = epsilon_byte;
        let mut e = [0u8; 48];
        e[47] = e_byte;

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
    c[120] ^= 0x01;
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn tampered_last_kw_p_byte_is_rejected() {
    let mut c = ciphertext_c();
    let last = c.len() - 1;
    c[last] ^= 0x01;
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn wrong_private_key_is_rejected() {
    let mut wrong_e = private_key_e();
    wrong_e[47] ^= 0x02;
    assert!(decrypt(&ciphertext_c(), &wrong_e).is_err());
}

#[test]
fn wrong_public_key_is_rejected() {
    let mut other_e = private_key_e();
    other_e[47] ^= 0x04;
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
    let over = [0u8; 38]; // 304 bits > 296
    assert!(encrypt(&over, 304, q_point(), &epsilon()).is_err());
}

#[test]
fn encrypt_rejects_epsilon_out_of_range() {
    assert!(encrypt(&message(), MESSAGE_BITS, q_point(), &[0u8; 48]).is_err());
    let mut one = [0u8; 48];
    one[47] = 1;
    assert!(encrypt(&message(), MESSAGE_BITS, q_point(), &one).is_err());
    let n = order();
    assert!(encrypt(&message(), MESSAGE_BITS, q_point(), &n).is_err());
}

// The boundary-value cluster (the D-167 findings re-derived for E384/1, D-241): r=0, r=1, r=p-1,
// and r^2=a*d^-1 mod p must all reject identically via crafted ciphertext.
#[test]
fn crafted_ciphertext_r_zero_is_rejected() {
    let mut c = [0u8; CIPHERTEXT_BYTES];
    c[48..].copy_from_slice(&[0xAAu8; 128]); // r=0 (all-zero prefix), arbitrary t
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn crafted_ciphertext_r_one_is_rejected() {
    let mut c = [0xAAu8; CIPHERTEXT_BYTES];
    c[..48].copy_from_slice(&[0u8; 48]);
    c[47] = 1;
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn crafted_ciphertext_r_p_minus_one_is_rejected() {
    let p_hex = extract(CURVE_VECTOR, "p_hex");
    let mut c = [0xAAu8; CIPHERTEXT_BYTES];
    let p_minus_1 = FieldElement::from_be_bytes(&decode_hex_padded(p_hex)).sub(FieldElement::ONE);
    c[..48].copy_from_slice(&p_minus_1.to_be_bytes());
    assert!(decrypt(&c, &private_key_e()).is_err());
}

#[test]
fn crafted_ciphertext_r_squared_equals_a_over_d_is_rejected() {
    let a = {
        let mut b = [0u8; 48];
        b[47] = 2;
        FieldElement::from_be_bytes(&b)
    };
    let d = {
        let mut b = [0u8; 48];
        b[46] = 0x02;
        b[47] = 0x14;
        FieldElement::from_be_bytes(&b)
    };
    let a_over_d = a.multiply(d.invert());
    let r = a_over_d.sqrt();
    assert_eq!(
        r.square(),
        a_over_d,
        "sanity: a/d must actually be a residue for this curve"
    );
    let mut c = [0xAAu8; CIPHERTEXT_BYTES];
    c[..48].copy_from_slice(&r.to_be_bytes());
    assert!(decrypt(&c, &private_key_e()).is_err());
}

// --- Boundary conditions (message-length and epsilon-range positive boundaries) ---

#[test]
fn message_bits_at_exactly_l_max_p_round_trips() {
    let message = [0xAAu8; 37]; // exactly 296 bits, L_MAX_P
    let c =
        encrypt(&message, 296, q_point(), &epsilon()).expect("296 bits == L_MAX_P, must succeed");
    let (m_tilde, bit_length) = decrypt(&c, &private_key_e()).expect("valid ciphertext");
    assert_eq!(bit_length, 296);
    assert_eq!(m_tilde, message);
}

#[test]
fn message_bits_at_l_max_p_minus_one_round_trips() {
    // 295 bits: same 37-byte buffer as the 296-bit case, top bit of the first byte cleared.
    let mut message = [0xAAu8; 37];
    message[0] = 0x2A;
    let c = encrypt(&message, 295, q_point(), &epsilon()).expect("295 <= L_MAX_P");
    let (_m_tilde, bit_length) = decrypt(&c, &private_key_e()).expect("valid ciphertext");
    assert_eq!(bit_length, 295);
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
    let mut eps = [0u8; 48];
    eps[47] = 2;
    let c = encrypt(&message(), MESSAGE_BITS, q_point(), &eps).expect("epsilon=2 is valid");
    assert!(decrypt(&c, &private_key_e()).is_ok());
}

#[test]
fn epsilon_at_maximum_valid_value_round_trips() {
    let mut eps = order();
    eps[47] -= 2;
    let c = encrypt(&message(), MESSAGE_BITS, q_point(), &eps).expect("epsilon=n-2 is valid");
    assert!(decrypt(&c, &private_key_e()).is_ok());
}

// T-307: `encrypt` takes a caller-built `Point` (public fields). A recipient point of small order
// or off the curve makes `T = eps*Q` - and so the KW key - computable without any secret; such a
// `Q` is refused before anything is wrapped.
#[test]
fn t307_degenerate_recipient_point_is_rejected() {
    let p_minus_1 = FieldElement::ZERO.sub(FieldElement::ONE);
    let order_two = Point {
        x: p_minus_1,
        y: FieldElement::ZERO,
    };
    let off_curve = Point {
        x: FieldElement::ZERO,
        y: FieldElement::ZERO,
    };
    for q in [Point::NEUTRAL, order_two, off_curve] {
        assert_eq!(
            encrypt(&message(), MESSAGE_BITS, q, &epsilon()),
            Err(EncryptError::InvalidPublicKey)
        );
    }
}
