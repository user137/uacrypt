#![no_main]

use dstu_core::hazmat::kalyna_cmac::{
    Kalyna128_128Cmac, Kalyna128_256Cmac, Kalyna256_256Cmac, Kalyna256_512Cmac, Kalyna512_512Cmac,
};
use libfuzzer_sys::fuzz_target;

// Required by SECURITY.md ("cargo fuzz is required ... not optional"). `mac`/`verify` must never
// panic/crash regardless of key/message/tag content or length. Not a correctness check, which the
// vector/proptest suites cover.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal) => {
        if $data.len() >= $key_len + 16 {
            let mut key = [0u8; $key_len];
            key.copy_from_slice(&$data[..$key_len]);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&$data[$key_len..$key_len + 16]);
            let message = &$data[$key_len + 16..];

            let _ = <$variant>::mac(&key, message);
            let _ = <$variant>::verify(&key, message, &tag);
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Cmac, 16);
    fuzz_variant!(data, Kalyna128_256Cmac, 32);
    fuzz_variant!(data, Kalyna256_256Cmac, 32);
    fuzz_variant!(data, Kalyna256_512Cmac, 64);
    fuzz_variant!(data, Kalyna512_512Cmac, 64);
});
