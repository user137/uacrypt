#![no_main]

use dstu_core::hazmat::strumok::{Strumok256, Strumok512};
use libfuzzer_sys::fuzz_target;

// Required by SECURITY.md ("cargo fuzz is required ... not optional"). apply_keystream must
// never panic/crash regardless of key/IV/data content or length (including the zero-length and
// non-8-aligned cases the chunk-invariance unit test also targets) - not a correctness check,
// which the vector tests cover.
fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 + 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[..32]);
        let mut iv = [0u8; 32];
        iv.copy_from_slice(&data[32..64]);
        let mut buf = data[64..].to_vec();
        Strumok256::new(&key, &iv).apply_keystream(&mut buf);
    }

    if data.len() >= 64 + 32 {
        let mut key = [0u8; 64];
        key.copy_from_slice(&data[..64]);
        let mut iv = [0u8; 32];
        iv.copy_from_slice(&data[64..96]);
        let mut buf = data[96..].to_vec();
        Strumok512::new(&key, &iv).apply_keystream(&mut buf);
    }
});
