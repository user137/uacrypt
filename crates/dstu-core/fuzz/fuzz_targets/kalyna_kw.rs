#![no_main]

use dstu_core::hazmat::kalyna_kw::{
    Kalyna128_128Kw, Kalyna128_256Kw, Kalyna256_256Kw, Kalyna256_512Kw, Kalyna512_512Kw,
};
use libfuzzer_sys::fuzz_target;

// Required by docs/SECURITY.md ("cargo fuzz is required ... not optional"). `wrap`/`unwrap` must never
// panic/crash regardless of key/plaintext/ciphertext/out-buffer length, including deliberately
// malformed shapes (non-block-aligned, too many blocks, mismatched out-buffer length) that must
// hit `KwError::InvalidLength` rather than panic - the module's own doc comment names exactly
// this class of caller-supplied length as the thing its fixed-size internal buffers depend on the
// length check to guard.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len {
            let mut key = [0u8; $key_len];
            key.copy_from_slice(&$data[..$key_len]);
            let rest = &$data[$key_len..];

            // Round-trip: wrap a well-formed, block-aligned plaintext (capped to a few blocks,
            // comfortably under MAX_R), then unwrap the result.
            let max_blocks = 5;
            let plaintext_len = (rest.len() / $block_len).min(max_blocks) * $block_len;
            if plaintext_len > 0 {
                let plaintext = &rest[..plaintext_len];
                let mut wrapped = vec![0u8; plaintext_len + $block_len];
                if <$variant>::wrap(&key, plaintext, &mut wrapped).is_ok() {
                    let mut unwrapped = vec![0u8; plaintext_len];
                    let _ = <$variant>::unwrap(&key, &wrapped, &mut unwrapped);
                }
            }

            // Direct attack surface: arbitrary (possibly non-block-aligned, over-long, or
            // out-buffer-mismatched) bytes straight into both functions.
            let cap = rest.len().min(256);
            let arbitrary = &rest[..cap];
            let mut out_a = vec![0u8; cap];
            let _ = <$variant>::wrap(&key, arbitrary, &mut out_a);
            let mut out_b = vec![0u8; cap];
            let _ = <$variant>::unwrap(&key, arbitrary, &mut out_b);
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Kw, 16, 16);
    fuzz_variant!(data, Kalyna128_256Kw, 32, 16);
    fuzz_variant!(data, Kalyna256_256Kw, 32, 32);
    fuzz_variant!(data, Kalyna256_512Kw, 64, 32);
    fuzz_variant!(data, Kalyna512_512Kw, 64, 64);
});
