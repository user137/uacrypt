#![no_main]

use dstu_core::hazmat::kalyna_kw_p::{
    Kalyna128_128KwP, Kalyna128_256KwP, Kalyna256_256KwP, Kalyna256_512KwP, Kalyna512_512KwP,
};
use libfuzzer_sys::fuzz_target;

// T-253 (docs/SECURITY.md: cargo fuzz is required). `unwrap` parses the recovered padding of
// untrusted input: it must never panic, and a wrapped message must come back exactly. Arbitrary
// bytes go straight into both functions at any length, including the right `out` length for
// `unwrap` so the padding check itself is reached.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len {
            let mut key = [0u8; $key_len];
            key.copy_from_slice(&$data[..$key_len]);
            let rest = &$data[$key_len..];
            let cap = rest.len().min(20 * $block_len);
            let message = &rest[..cap];

            if let Some(len) = <$variant>::wrapped_len(message.len()) {
                let mut wrapped = vec![0u8; len];
                <$variant>::wrap(&key, message, &mut wrapped).expect("wrapped_len said valid");
                let mut out = vec![0u8; len - $block_len];
                let n = <$variant>::unwrap(&key, &wrapped, &mut out).expect("round trip");
                assert_eq!(&out[..n], message);
            }

            let mut out = vec![0u8; cap];
            let _ = <$variant>::wrap(&key, message, &mut out);
            let _ = <$variant>::unwrap(&key, message, &mut out);
            if cap >= $block_len {
                let mut out = vec![0u8; cap - $block_len];
                let _ = <$variant>::unwrap(&key, message, &mut out);
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128KwP, 16, 16);
    fuzz_variant!(data, Kalyna128_256KwP, 32, 16);
    fuzz_variant!(data, Kalyna256_256KwP, 32, 32);
    fuzz_variant!(data, Kalyna256_512KwP, 64, 32);
    fuzz_variant!(data, Kalyna512_512KwP, 64, 64);
});
