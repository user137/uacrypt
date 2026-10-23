#![no_main]

#[path = "../common/negative.rs"]
mod negative;

use dstu_core::crypto_sign::{Signature, SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// T-225: `VerifyingKey::from_uncompressed_bytes` and `verify` take a key, a signature and a
// message from outside (uacrypt's --key/--sig, every binding). The input is `key (42) || sig (42)
// || message`. Arbitrary bytes must never panic, and no modification of the pinned triple may
// verify (`common/negative.rs`) - spare key bits included (5 per coordinate, checked by hand
// before this target: they fail `is_on_curve`). Signing is deterministic (D-46), so the fixture
// is the same in every run.
const KEY_LEN: usize = 42;
const SIG_LEN: usize = 42;
const MESSAGE: &[u8] = b"uacrypt fuzz fixture, crypto_sign";

fn original() -> &'static [u8] {
    static ORIGINAL: OnceLock<Vec<u8>> = OnceLock::new();
    ORIGINAL.get_or_init(|| {
        let mut d = [0u8; 21];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let signing = SigningKey::from_bytes(&d).expect("pinned scalar below n");
        let mut triple = signing.verifying_key().to_uncompressed_bytes().to_vec();
        triple.extend_from_slice(&signing.sign(MESSAGE).to_bytes());
        triple.extend_from_slice(MESSAGE);
        triple
    })
}

fn verifies(input: &[u8]) -> bool {
    if input.len() < KEY_LEN + SIG_LEN {
        return false;
    }
    let (key, rest) = input.split_at(KEY_LEN);
    let (sig, message) = rest.split_at(SIG_LEN);
    let key = VerifyingKey::from_uncompressed_bytes(key.try_into().expect("split at KEY_LEN"));
    key.verify(
        message,
        &Signature::from_bytes(sig.try_into().expect("split at SIG_LEN")),
    )
}

fn check(candidate: &[u8], original: &[u8]) {
    let accepted = verifies(candidate);
    assert_eq!(
        accepted,
        candidate == original,
        "verify = {accepted} for a {}-byte input",
        candidate.len()
    );
}

fuzz_target!(|data: &[u8]| {
    let original = original();
    check(data, original);
    if let Some(candidate) = negative::mutate(original, data) {
        check(&candidate, original);
    }
});
