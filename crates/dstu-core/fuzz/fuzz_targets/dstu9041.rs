#![no_main]

use dstu_core::hazmat::dstu9041::{encryption, encryption384, encryption512};
use libfuzzer_sys::fuzz_target;

// T-225: clause 12's `decrypt` parses the KEM ciphertext (`R'`, `t`) from outside and must never
// panic for any ciphertext and private key - an invalid scalar, a point not on the curve or of
// the wrong order, or a bad `t` is a typed `DecryptError` (the two T-177 findings). `data[0]`
// picks the curve, so a slow 512-bit run does not starve the other two.
macro_rules! fuzz_curve {
    ($rest:expr, $module:ident, $ct_len:expr, $key_len:literal) => {
        if $rest.len() >= $ct_len + $key_len {
            let (ciphertext, rest) = $rest.split_at($ct_len);
            let _ = $module::decrypt(
                ciphertext.try_into().expect("ciphertext slice"),
                rest[..$key_len].try_into().expect("key slice"),
            );
        }
    };
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    match selector % 3 {
        0 => fuzz_curve!(rest, encryption, 128, 32),
        1 => fuzz_curve!(rest, encryption384, encryption384::CIPHERTEXT_BYTES, 48),
        _ => fuzz_curve!(rest, encryption512, 256, 64),
    }
});
