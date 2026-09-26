//! Tests for `dstu_core::crypto_sign257` - the `m=257` sibling of `crypto_sign` (`docs/TASKS.md`
//! T-199, `docs/DECISIONS.md` D-185/D-186). Mirrors `tests/crypto_sign.rs`'s own coverage
//! structure closely; deviations noted where they exist.
//!
//! **No `verifying_key_matches_official_worked_example_q`-equivalent test**: unlike `m=163`
//! (Annex B.1), no primary-text DSTU 4145 worked example exists for `m=257` - `Q = -d*G`'s
//! correctness for this curve is already covered at the `hazmat::dstu4145::signature257` layer
//! (`tests/dstu4145_signature257.rs`'s BC-oracle cases, which include independently-computed `Q`
//! values for 20 random `d`). This file tests the `crypto_sign257` wrapper layer specifically
//! (deterministic nonce derivation, digest API, `generate`/`from_bytes` round-tripping), not the
//! underlying curve math again.

use dstu_core::crypto_sign257::{Signature, SigningKey, VerifyingKey};
use dstu_core::hazmat::dstu4145::curve257::Point;
use dstu_core::hazmat::dstu4145::gf2m257::FieldElement;
use dstu_core::hazmat::dstu4145::signature257;
use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna256Hasher};
use proptest::prelude::*;

/// A small, obviously-below-`n` test scalar (`n`'s top byte is `0x00`, second byte's top 7 bits
/// are also `0` - see `hazmat::dstu4145::curve257::order`), distinguished only by its low byte.
fn small_scalar(low_byte: u8) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[32] = low_byte;
    out
}

// Every #[test] below (except the two from_bytes rejection tests, which never derive a public
// key) runs `Point::scalar_multiply`'s 257-iteration constant-time ladder at least once (even
// slower under Miri than `m=163`'s 163-iteration ladder - same posture as `tests/crypto_sign.rs`,
// docs/TASKS.md T-100/T-85/D-46). Excluded from CI's required Miri gate only.

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_is_deterministic() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x11)).expect("nonzero, below n");
    let sig_a = signing_key.sign(b"hello dstu4145 m=257");
    let sig_b = signing_key.sign(b"hello dstu4145 m=257");
    assert_eq!(sig_a.to_bytes(), sig_b.to_bytes());
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_verify_roundtrip() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let sig = signing_key.sign(b"a real message");
    assert!(verifying_key.verify(b"a real message", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn tampered_message_is_rejected() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let sig = signing_key.sign(b"a real message");
    assert!(!verifying_key.verify(b"a different message", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn tampered_signature_is_rejected() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let mut sig = signing_key.sign(b"a real message").to_bytes();
    sig[65] ^= 1; // flip the low bit of s (bytes 33..66)
    let sig = dstu_core::crypto_sign257::Signature::from_bytes(&sig);
    assert!(!verifying_key.verify(b"a real message", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn wrong_verifying_key_is_rejected() {
    let signing_key_a = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let signing_key_b = SigningKey::from_bytes(&small_scalar(0x2B)).expect("nonzero, below n");
    let sig = signing_key_a.sign(b"a real message");
    assert!(!signing_key_b
        .verifying_key()
        .verify(b"a real message", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_digest_matches_sign_on_the_same_message() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let digest = Kupyna256::digest(b"a real message");
    assert_eq!(
        signing_key.sign(b"a real message").to_bytes(),
        signing_key.sign_digest(&digest).to_bytes(),
        "sign() must be equivalent to hashing then sign_digest()"
    );
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn sign_digest_verify_digest_roundtrip_with_streamed_hash() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();

    let mut hasher = Kupyna256Hasher::new();
    hasher.update(b"a real ");
    hasher.update(b"message");
    let digest = hasher.finalize();

    assert_eq!(digest, Kupyna256::digest(b"a real message"));

    let sig = signing_key.sign_digest(&digest);
    assert!(verifying_key.verify_digest(&digest, &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn verify_digest_rejects_tampered_digest() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let verifying_key = signing_key.verifying_key();
    let digest = Kupyna256::digest(b"a real message");
    let sig = signing_key.sign_digest(&digest);

    let mut wrong_digest = digest;
    wrong_digest[31] ^= 1;
    assert!(!verifying_key.verify_digest(&wrong_digest, &sig));
}

// T-122-equivalent: `SigningKey::generate()` draws `d` from the OS CSPRNG via rejection sampling.
// Run several times, not once.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn generate_produces_a_key_that_signs_and_verifies() {
    for _ in 0..20 {
        let signing_key = SigningKey::generate().expect("OS CSPRNG available in test environment");
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(b"a freshly generated key can sign");
        assert!(verifying_key.verify(b"a freshly generated key can sign", &sig));
    }
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn to_bytes_round_trips_through_from_bytes() {
    let original = SigningKey::generate().expect("OS CSPRNG available in test environment");
    let bytes = original.to_bytes();
    let restored = SigningKey::from_bytes(&bytes).expect("generate() always produces a valid d");
    assert_eq!(
        original.verifying_key().to_uncompressed_bytes(),
        restored.verifying_key().to_uncompressed_bytes()
    );
    let sig = restored.sign(b"round-tripped key can still sign");
    assert!(original
        .verifying_key()
        .verify(b"round-tripped key can still sign", &sig));
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn two_calls_to_generate_produce_different_keys() {
    let a = SigningKey::generate().expect("OS CSPRNG available in test environment");
    let b = SigningKey::generate().expect("OS CSPRNG available in test environment");
    assert_ne!(
        a.verifying_key().to_uncompressed_bytes(),
        b.verifying_key().to_uncompressed_bytes()
    );
}

// T-239: `n` is ~2^255, so a uniform `d` in [1, n-1] lies at or above 2^249 (byte 1 >= 0x02) with
// probability ~63/64. The old generator masked byte 1 to its low bit and never reached it. Needing
// only 48 of 64 keeps a false failure far below 2^-40.
#[test]
fn generate_covers_the_full_range_below_n() {
    let high = (0..64)
        .filter(|_| {
            let d = SigningKey::generate()
                .expect("OS CSPRNG available in test environment")
                .to_bytes();
            d[1] >= 0x02
        })
        .count();
    assert!(high >= 48, "only {high} of 64 keys reached d >= 2^249");
}

#[test]
fn from_bytes_rejects_zero_scalar() {
    assert!(SigningKey::from_bytes(&[0u8; 33]).is_none());
}

#[test]
fn from_bytes_rejects_scalar_at_or_above_order() {
    let n = dstu_core::hazmat::dstu4145::curve257::order();
    assert!(SigningKey::from_bytes(&n).is_none());
}

proptest! {
    #[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
    #[test]
    fn dstu4145_crypto_sign257_roundtrip(
        d_bytes in prop::collection::vec(any::<u8>(), 32),
        message in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut d_arr = [0u8; 33];
        d_arr[1..].copy_from_slice(&d_bytes);
        prop_assume!(d_arr != [0u8; 33]);

        let signing_key = match SigningKey::from_bytes(&d_arr) {
            Some(k) => k,
            None => return Ok(()), // astronomically unlikely d >= n from a 256-bit sample
        };
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(&message);
        prop_assert!(verifying_key.verify(&message, &sig));
    }
}

// T-278: the malicious-key rejections of `tests/dstu4145_signature257.rs`, through the public
// `VerifyingKey::from_uncompressed_bytes` decoding path. `Infinity` has no 66-byte encoding here;
// the all-zero encoding decodes to the off-curve `(0, 0)` instead.

fn curve257_order_two_point() -> (FieldElement, FieldElement) {
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    let pattern = "\"b\": \"";
    let start = json.find(pattern).expect("curve b in test vector JSON") + pattern.len();
    let hex = &json[start..start + json[start..].find('"').expect("well-formed JSON")];
    let mut b_bytes = [0u8; 33];
    let digits = hex.len() / 2;
    for i in 0..digits {
        b_bytes[33 - digits + i] =
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("valid hex digit");
    }
    let b = FieldElement::from_be_bytes(&b_bytes);
    let mut y = b;
    for _ in 0..256 {
        y = y.square();
    }
    assert_eq!(y.square(), b, "test setup: y must satisfy y^2 = b");
    (FieldElement::ZERO, y)
}

fn encode_point(x: FieldElement, y: FieldElement) -> [u8; 66] {
    let mut out = [0u8; 66];
    out[..33].copy_from_slice(&x.to_be_bytes());
    out[33..].copy_from_slice(&y.to_be_bytes());
    out
}

/// A forgery for any key `Q` with `r*Q == Infinity` for even `r`: `s*G + r*Q == s*G`, so
/// `r = truncate(h * (s*G).x)` satisfies the verify equation unless `Q` is validated first.
fn forge_even_r(digest: &[u8; 32]) -> Signature {
    let h = signature257::hash_to_field(digest);
    (1..200u8)
        .find_map(|k| {
            let mut s = [0u8; 33];
            s[32] = k;
            s[20] = k.wrapping_mul(29);
            let Point::Affine(x, _) = Point::generator().scalar_multiply(&s) else {
                return None;
            };
            let mut r = h.multiply(x).to_be_bytes();
            r[0] = 0;
            r[1] &= 0x7F;
            (r != [0u8; 33] && r[32] & 1 == 0).then(|| {
                let mut bytes = [0u8; 66];
                bytes[..33].copy_from_slice(&r);
                bytes[33..].copy_from_slice(&s);
                Signature::from_bytes(&bytes)
            })
        })
        .expect("about half of all candidates give a nonzero even r")
}

/// The unvalidated verify equation: `r == truncate(h * (s*G + r*Q).x)`.
fn passes_verify_equation(digest: &[u8; 32], sig: &Signature, q: Point) -> bool {
    let bytes = sig.to_bytes();
    let r: [u8; 33] = bytes[..33].try_into().unwrap();
    let s: [u8; 33] = bytes[33..].try_into().unwrap();
    let h = signature257::hash_to_field(digest);
    match Point::generator().scalar_multiply(&s) + q.scalar_multiply(&r) {
        Point::Affine(x, _) => {
            let mut candidate = h.multiply(x).to_be_bytes();
            candidate[0] = 0;
            candidate[1] &= 0x7F;
            candidate == r
        }
        Point::Infinity => false,
    }
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn malformed_verifying_keys_are_rejected() {
    let digest = [0x55u8; 32];
    let sig = forge_even_r(&digest);
    let (zero, t2_y) = curve257_order_two_point();
    for (name, bytes) in [
        ("all-zero", [0u8; 66]),
        ("off-curve (0, 1)", encode_point(zero, FieldElement::ONE)),
        ("order-2 (0, sqrt(b))", encode_point(zero, t2_y)),
    ] {
        let q = Point::Affine(
            FieldElement::from_be_bytes(bytes[..33].try_into().unwrap()),
            FieldElement::from_be_bytes(bytes[33..].try_into().unwrap()),
        );
        assert!(
            passes_verify_equation(&digest, &sig, q),
            "test setup: the forgery must satisfy the unvalidated verify equation under {name}"
        );
        let key = VerifyingKey::from_uncompressed_bytes(&bytes);
        assert!(!key.verify_digest(&digest, &sig), "{name}");
    }
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn order_2n_verifying_key_is_rejected() {
    let signing_key = SigningKey::from_bytes(&small_scalar(0x2A)).expect("nonzero, below n");
    let genuine = signing_key.verifying_key();
    let q_bytes = genuine.to_uncompressed_bytes();
    let q = Point::Affine(
        FieldElement::from_be_bytes(q_bytes[..33].try_into().unwrap()),
        FieldElement::from_be_bytes(q_bytes[33..].try_into().unwrap()),
    );
    let (t2_x, t2_y) = curve257_order_two_point();
    let Point::Affine(x, y) = q + Point::Affine(t2_x, t2_y) else {
        panic!("Q + T2 is never Infinity: Q has odd order n");
    };
    let substituted = VerifyingKey::from_uncompressed_bytes(&encode_point(x, y));

    // An even r means r*T2 == O, so this genuine signature also satisfies the equation under Q + T2.
    let (message, sig) = (0u8..=255)
        .map(|i| {
            let message = [b'm', i];
            let sig = signing_key.sign(&message);
            (message, sig)
        })
        .find(|(_, sig)| sig.to_bytes()[32] & 1 == 0)
        .expect("about half of all signatures have an even r");
    assert!(
        genuine.verify(&message, &sig),
        "the genuine key must still verify"
    );
    assert!(
        !substituted.verify(&message, &sig),
        "a verifying key of order 2n must be rejected"
    );
}
