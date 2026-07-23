#![no_main]

use dstu_core::hazmat::kalyna_ccm::{
    Kalyna128_128Ccm, Kalyna128_256Ccm, Kalyna256_256Ccm, Kalyna256_512Ccm, Kalyna512_512Ccm,
};
use libfuzzer_sys::fuzz_target;

// Required by SECURITY.md ("cargo fuzz is required ... not optional"). `seal_in_place`/
// `open_in_place` must never panic/crash regardless of key/nonce/aad/buffer content or length -
// `open_in_place` in particular is the first code in this crate that makes an authentication
// decision on fully attacker-controlled input, so it's also fuzzed directly with ciphertext/tag
// bytes that were never produced by a real `seal_in_place` call, not just round-tripped through
// one. Not a correctness check, which the vector/proptest suites cover.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal, $tag_len:literal) => {
        if $data.len() >= $key_len + $block_len + 1 {
            let mut key = [0u8; $key_len];
            key.copy_from_slice(&$data[..$key_len]);
            let mut nonce = [0u8; $block_len];
            nonce.copy_from_slice(&$data[$key_len..$key_len + $block_len]);
            let rest = &$data[$key_len + $block_len..];

            let aad_len = (rest[0] as usize).min(rest.len().saturating_sub(1)).min(32);
            let aad = &rest[1..1 + aad_len];
            let buf_source = &rest[1 + aad_len..];
            let cap = buf_source.len().min(64);
            let buf_source = &buf_source[..cap];

            let cipher = <$variant>::new(&key);

            // Round-trip: seal whatever's left, then open the result.
            let mut buf = buf_source.to_vec();
            if let Ok(tag) = cipher.seal_in_place(&nonce, aad, &mut buf) {
                let mut opened = buf.clone();
                let _ = cipher.open_in_place(&nonce, aad, &mut opened, &tag);
            }

            // Direct attack surface: feed arbitrary bytes as ciphertext+tag, never produced by
            // `seal_in_place`, straight into `open_in_place`.
            if buf_source.len() >= $tag_len {
                let (ct, tag_bytes) = buf_source.split_at(buf_source.len() - $tag_len);
                let mut tag = [0u8; $tag_len];
                tag.copy_from_slice(tag_bytes);
                let mut attacker_buf = ct.to_vec();
                let _ = cipher.open_in_place(&nonce, aad, &mut attacker_buf, &tag);
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Ccm, 16, 16, 16);
    fuzz_variant!(data, Kalyna128_256Ccm, 32, 16, 16);
    fuzz_variant!(data, Kalyna256_256Ccm, 32, 32, 16);
    fuzz_variant!(data, Kalyna256_512Ccm, 64, 32, 32);
    fuzz_variant!(data, Kalyna512_512Ccm, 64, 64, 64);
});
