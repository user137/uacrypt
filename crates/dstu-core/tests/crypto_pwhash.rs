#![cfg(feature = "pwhash")]

use dstu_core::crypto_pwhash::{hash_password, verify_password, Strength};

#[test]
fn hash_then_verify_round_trips() {
    let hash = hash_password(b"correct horse battery staple", Strength::Interactive)
        .expect("hashing a valid password never fails");
    assert!(verify_password(b"correct horse battery staple", &hash));
}

#[test]
fn wrong_password_is_rejected() {
    let hash = hash_password(b"correct horse battery staple", Strength::Interactive)
        .expect("hashing a valid password never fails");
    assert!(!verify_password(b"wrong password", &hash));
}

#[test]
fn malformed_hash_string_is_rejected_not_a_panic() {
    assert!(!verify_password(b"anything", "not a PHC string"));
}

#[test]
fn two_calls_use_different_salts() {
    let a = hash_password(b"same password", Strength::Interactive)
        .expect("hashing a valid password never fails");
    let b = hash_password(b"same password", Strength::Interactive)
        .expect("hashing a valid password never fails");
    assert_ne!(a, b, "a fresh random salt must be drawn per call");
}

/// Each `Strength` preset must encode its own libsodium-equivalent `m`/`t`/`p` parameters into the
/// PHC string - not just whatever `argon2`'s own `Params::default()` happens to be. A roundtrip
/// test alone would pass even if `Strength` were silently ignored (`verify_password` re-derives
/// params from the string itself), so this asserts the encoded params directly instead
/// (`DECISIONS.md` D-49/D-50, `CLAUDE.md`'s "check what a fixed vector actually exercises" lesson).
///
/// `Sensitive` (1024 MiB, t=4) is deliberately not exercised here through a real hash - in an
/// unoptimized debug build that one preset alone took ~85s, which is too expensive to pay on every
/// CI push for marginal signal: `Interactive`/`Moderate` already prove `Strength` flows through
/// `hash_password` into the PHC string via the exact same code path, just a different constant.
/// `Sensitive`'s own constant is instead checked directly, at zero cost, in
/// `crypto_pwhash::tests::sensitive_preset_has_libsodiums_sensitive_params` (`src/crypto_pwhash.rs`).
#[test]
fn each_cheap_strength_encodes_its_own_libsodium_equivalent_params() {
    let cases = [
        (Strength::Interactive, "m=65536,t=2,p=1"),
        (Strength::Moderate, "m=262144,t=3,p=1"),
    ];
    for (strength, expected_params) in cases {
        let hash =
            hash_password(b"password", strength).expect("hashing a valid password never fails");
        assert!(
            hash.contains(expected_params),
            "expected {expected_params:?} in PHC string, got {hash:?}"
        );
    }
}
