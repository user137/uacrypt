#![no_main]

use dstu_core::hazmat::kalyna_cfb::{
    Kalyna128_128Cfb, Kalyna128_256Cfb, Kalyna256_256Cfb, Kalyna256_512Cfb, Kalyna512_512Cfb,
};
use libfuzzer_sys::fuzz_target;

// Required by SECURITY.md ("cargo fuzz is required ... not optional"). `new`/`encrypt_in_place`
// must never panic/crash regardless of q/key/iv/buffer content, length, or call-boundary shape -
// in particular a non-`q`-aligned intermediate call followed by another must return
// `Err(CfbError::NonAlignedIntermediateCall)` (T-101/D-60), never panic, which this target checks
// directly by feeding arbitrary (usually non-aligned) chunk boundaries across multiple calls on
// the same cipher.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len + $block_len + 2 {
            let mut key = [0u8; $key_len];
            key.copy_from_slice(&$data[..$key_len]);
            let mut iv = [0u8; $block_len];
            iv.copy_from_slice(&$data[$key_len..$key_len + $block_len]);
            let rest = &$data[$key_len + $block_len..];

            let q_choices = [1usize, 8, 16, 32, 64];
            let q = q_choices[rest[0] as usize % q_choices.len()];
            let n_calls = (rest[1] as usize % 4) + 1;
            let rest = &rest[2..];

            if let Ok(mut cipher) = <$variant>::new(&key, &iv, q) {
                let chunk_len = if rest.is_empty() {
                    0
                } else {
                    rest.len() / n_calls
                };
                let mut offset = 0usize;
                for _ in 0..n_calls {
                    let end = (offset + chunk_len).min(rest.len());
                    let mut buf = rest[offset..end].to_vec();
                    // Err is an expected outcome here (T-101), not a fuzz finding - only a panic
                    // is. Deliberately ignored, not unwrapped.
                    let _ = cipher.encrypt_in_place(&mut buf);
                    offset = end;
                }
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Cfb, 16, 16);
    fuzz_variant!(data, Kalyna128_256Cfb, 32, 16);
    fuzz_variant!(data, Kalyna256_256Cfb, 32, 32);
    fuzz_variant!(data, Kalyna256_512Cfb, 64, 32);
    fuzz_variant!(data, Kalyna512_512Cfb, 64, 64);
});
