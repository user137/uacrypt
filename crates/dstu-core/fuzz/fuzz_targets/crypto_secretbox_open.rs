#![no_main]

#[path = "../common/negative.rs"]
mod negative;

use dstu_core::crypto_secretbox::{open, SecretKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// T-223: `open` parses `version || nonce || ciphertext || tag` from the caller. Arbitrary bytes
// must never panic, and no modification of the pinned blob may open (`common/negative.rs`) - the
// nonce and the true length are covered through the internal AAD (D-63, D-204).
//
// Self-generated pin, not an oracle (D-68): `seal` at 5d32cc2 under the counting key 01 02 .. 20
// over the 70-byte `(i * 31 + 7) mod 256` plaintext (a partial last block).
const SEALED_HEX: &str = "022c5c3201e8d965c2c1e513c8b8614fe9f612aee6ada56912de6a749169173c91f2126eb946059f5d776d476adbe2deb0ab193d78fbc0bb1e8baeb99ca7131fc5db65f0a529f7bcfd873a4c06c873ebe9db77c6525a7af2b88c0368b7724c6bdb41eb8a5ca40f6b30359c38553682be3506815c9e71ec";

struct Fixture {
    key: SecretKey,
    sealed: Vec<u8>,
    plaintext: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        Fixture {
            key: SecretKey::from_bytes(key),
            sealed: negative::decode_hex(SEALED_HEX),
            plaintext: negative::pattern(70),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    negative::check_open(data, &f.sealed, &f.plaintext, open(&f.key, data));
    if let Some(candidate) = negative::mutate(&f.sealed, data) {
        negative::check_open(
            &candidate,
            &f.sealed,
            &f.plaintext,
            open(&f.key, &candidate),
        );
    }
});
