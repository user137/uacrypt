#![cfg(feature = "pwhash")]

use dstu_core::crypto_pwhash::{derive_key, hash_password, verify_password, Strength, SALT_BYTES};

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
/// (`docs/DECISIONS.md` D-49/D-50, `CLAUDE.md`'s "check what a fixed vector actually exercises" lesson).
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

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
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

/// `derive_key` against libsodium's own `crypto_pwhash` (ARGON2ID13, `OPSLIMIT_MODERATE`,
/// `MEMLIMIT_MODERATE`), generated with PyNaCl 1.6.2's bundled libsodium - an implementation
/// independent of the `argon2` crate (`docs/DECISIONS.md` D-219). Also the shared cross-language
/// vector file for T-269.
#[test]
fn derive_key_matches_libsodium_crypto_pwhash_moderate() {
    let json = include_str!("vectors/pwhash/derive_key.json");
    let passwords = extract_all(json, "password_hex");
    let salts = extract_all(json, "salt_hex");
    let keys = extract_all(json, "key_hex");
    assert_eq!(passwords.len(), 3, "extractor or fixture is broken");
    assert_eq!(passwords.len(), salts.len());
    assert_eq!(passwords.len(), keys.len());
    for ((password, salt), key) in passwords.into_iter().zip(salts).zip(keys) {
        let salt: [u8; SALT_BYTES] = decode_hex(salt).try_into().expect("16-byte salt");
        let derived = derive_key(&decode_hex(password), &salt, Strength::Moderate)
            .expect("derivation with a valid preset succeeds");
        assert_eq!(derived.as_slice(), decode_hex(key).as_slice());
    }
}

#[test]
fn derive_key_depends_on_salt_and_strength() {
    let a = derive_key(b"pw", &[0u8; SALT_BYTES], Strength::Interactive).expect("derive");
    let b = derive_key(b"pw", &[1u8; SALT_BYTES], Strength::Interactive).expect("derive");
    let c = derive_key(b"pw", &[0u8; SALT_BYTES], Strength::Moderate).expect("derive");
    let again = derive_key(b"pw", &[0u8; SALT_BYTES], Strength::Interactive).expect("derive");
    assert_eq!(*a, *again, "same inputs must give the same key");
    assert_ne!(*a, *b);
    assert_ne!(*a, *c);
}

#[test]
fn strength_cost_round_trips_and_rejects_anything_else() {
    for strength in [
        Strength::Interactive,
        Strength::Moderate,
        Strength::Sensitive,
    ] {
        let (m, t, p) = strength.cost();
        assert_eq!(Strength::from_cost(m, t, p), Some(strength));
    }
    assert_eq!(Strength::Moderate.cost(), (262_144, 3, 1));
    assert_eq!(Strength::from_cost(262_144, 3, 2), None);
    assert_eq!(Strength::from_cost(u32::MAX, 3, 1), None);
    assert_eq!(Strength::from_cost(262_144, 4, 1), None);
}

/// `verify_password` against hashes made by libsodium and the reference C implementation
/// (`tests/vectors/pwhash/verify.json`, `docs/DECISIONS.md` D-222). Accepts argon2id/argon2i
/// v=19 within the bounds; rejects argon2d, v=16, short tags, extra/duplicate/missing
/// parameters, and costs above the Sensitive preset - the last without allocating or hashing
/// (T-272: `m=2^31` used to abort the process, `t=2^32-1` used to run for hours). Also the shared
/// cross-language vector file for the bindings.
#[test]
fn verify_password_matches_shared_accept_reject_vectors() {
    let json = include_str!("vectors/pwhash/verify.json");
    let names = extract_all(json, "name");
    let passwords = extract_all(json, "password");
    let hashes = extract_all(json, "hash");
    let expects = extract_all(json, "expect");
    assert_eq!(names.len(), 22, "extractor or fixture is broken");
    assert_eq!(names.len(), passwords.len());
    assert_eq!(names.len(), hashes.len());
    assert_eq!(names.len(), expects.len());
    for (((name, password), hash), expect) in
        names.into_iter().zip(passwords).zip(hashes).zip(expects)
    {
        let accept = match expect {
            "accept" => true,
            "reject" => false,
            other => panic!("{name}: unknown expect {other:?}"),
        };
        assert_eq!(verify_password(password.as_bytes(), hash), accept, "{name}");
        assert!(!verify_password(b"wrong", hash), "{name}: wrong password");
    }
}
