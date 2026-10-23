#![no_main]

#[path = "../common/negative.rs"]
mod negative;

use dstu_core::crypto_box512::{open, SecretKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// T-223 (l(p)=512): `open` takes the sealed blob from uacrypt's --in and every binding's caller.
// Arbitrary bytes must never panic, and no modification of the pinned `box/v3.json` blob - a
// flipped byte, a cut, appended or inserted bytes - may open (`common/negative.rs`).
const VECTORS: &str = include_str!("../../tests/vectors/box/v3.json");

struct Fixture {
    secret: SecretKey,
    sealed: Vec<u8>,
    plaintext: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (key, sealed, plaintext) = negative::box_fixture(VECTORS, 512);
        let key: [u8; 64] = key.try_into().expect("64-byte key");
        Fixture {
            secret: SecretKey::from_bytes(&key).expect("valid pinned key"),
            sealed,
            plaintext,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    negative::check_open(data, &f.sealed, &f.plaintext, open(data, &f.secret));
    if let Some(candidate) = negative::mutate(&f.sealed, data) {
        negative::check_open(
            &candidate,
            &f.sealed,
            &f.plaintext,
            open(&candidate, &f.secret),
        );
    }
});
