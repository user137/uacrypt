#![no_main]

use dstu_core::hazmat::kalyna_gcm::{
    Kalyna128_128Gcm, Kalyna128_256Gcm, Kalyna256_256Gcm, Kalyna256_512Gcm, Kalyna512_512Gcm,
};
use libfuzzer_sys::fuzz_target;

// Required by docs/SECURITY.md ("cargo fuzz is required ... not optional"). `encrypt`/`decrypt` must
// never panic/crash regardless of key/iv/aad/plaintext/ciphertext/tag content or length -
// `decrypt` in particular makes an authentication decision on fully attacker-controlled input, so
// it's also fuzzed directly with ciphertext/tag bytes never produced by a real `encrypt` call,
// including tag lengths outside the valid 8..=block_len range.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len + $block_len + 2 {
            let mut key = [0u8; $key_len];
            key.copy_from_slice(&$data[..$key_len]);
            let mut iv = [0u8; $block_len];
            iv.copy_from_slice(&$data[$key_len..$key_len + $block_len]);
            let rest = &$data[$key_len + $block_len..];

            let aad_len = (rest[0] as usize).min(rest.len().saturating_sub(2)).min(32);
            let tag_len_choice = rest[1] as usize; // deliberately unbounded here
            let rest = &rest[2..];
            let aad = &rest[..aad_len.min(rest.len())];
            let rest = &rest[aad_len.min(rest.len())..];
            let plaintext = &rest[..rest.len().min(64)];

            let cipher = <$variant>::new(&key);

            // Round-trip: encrypt whatever's left, then decrypt the result.
            let mut ciphertext = vec![0u8; plaintext.len()];
            if let Ok(tag) = cipher.encrypt(&iv, aad, plaintext, &mut ciphertext) {
                let mut recovered = vec![0u8; ciphertext.len()];
                let _ = cipher.decrypt(&iv, aad, &ciphertext, &tag, &mut recovered);
            }

            // Direct attack surface: `plaintext`'s own bytes reused as arbitrary ciphertext, with
            // an attacker-chosen (possibly out-of-range) tag length.
            let tag_bytes = &plaintext[..plaintext.len().min(tag_len_choice.min($block_len))];
            let mut attacker_out = vec![0u8; plaintext.len()];
            let _ = cipher.decrypt(&iv, aad, plaintext, tag_bytes, &mut attacker_out);
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Gcm, 16, 16);
    fuzz_variant!(data, Kalyna128_256Gcm, 32, 16);
    fuzz_variant!(data, Kalyna256_256Gcm, 32, 32);
    fuzz_variant!(data, Kalyna256_512Gcm, 64, 32);
    fuzz_variant!(data, Kalyna512_512Gcm, 64, 64);
});
