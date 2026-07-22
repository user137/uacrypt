#![no_main]

use dstu_core::hazmat::kalyna::{
    Kalyna128_128, Kalyna128_256, Kalyna256_256, Kalyna256_512, Kalyna512_512,
};
use libfuzzer_sys::fuzz_target;

// Required by SECURITY.md ("cargo fuzz is required ... not optional"). Each variant's
// encrypt/decrypt must never panic/crash regardless of key or block content - that's the only
// property this target checks (not correctness, which the vector tests cover).
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len + $block_len {
            let mut key = [0u8; $key_len];
            key.copy_from_slice(&$data[..$key_len]);
            let mut block = [0u8; $block_len];
            block.copy_from_slice(&$data[$key_len..$key_len + $block_len]);

            let ciphertext = <$variant>::encrypt(&key, &block);
            let _ = <$variant>::decrypt(&key, &ciphertext);
            // Also feed arbitrary (not necessarily valid-ciphertext) bytes through decrypt.
            let _ = <$variant>::decrypt(&key, &block);
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128, 16, 16);
    fuzz_variant!(data, Kalyna128_256, 32, 16);
    fuzz_variant!(data, Kalyna256_256, 32, 32);
    fuzz_variant!(data, Kalyna256_512, 64, 32);
    fuzz_variant!(data, Kalyna512_512, 64, 64);
});
