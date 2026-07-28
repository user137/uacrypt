#![no_main]

use dstu_core::hazmat::kalyna_gmac::{
    Kalyna128_128Gmac, Kalyna128_256Gmac, Kalyna256_256Gmac, Kalyna256_512Gmac, Kalyna512_512Gmac,
};
use libfuzzer_sys::fuzz_target;

// Required by docs/SECURITY.md ("cargo fuzz is required ... not optional"). `mac`/`verify` must never
// panic/crash regardless of key/message/tag content or length - including tag lengths outside the
// valid 8..=block_bytes range, which `verify` must reject with `GmacError::InvalidLength`, not
// panic on.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len + 1 {
            let mut key = [0u8; $key_len];
            key.copy_from_slice(&$data[..$key_len]);
            let rest = &$data[$key_len..];

            // Deliberately allowed to fall outside 8..=block_len - exercises InvalidLength too.
            let tag_len = (rest[0] as usize % ($block_len + 2)).min(rest.len() - 1);
            let (tag, message) = rest[1..].split_at(tag_len);

            let _ = <$variant>::mac(&key, message);
            let _ = <$variant>::verify(&key, message, tag);
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Gmac, 16, 16);
    fuzz_variant!(data, Kalyna128_256Gmac, 32, 16);
    fuzz_variant!(data, Kalyna256_256Gmac, 32, 32);
    fuzz_variant!(data, Kalyna256_512Gmac, 64, 32);
    fuzz_variant!(data, Kalyna512_512Gmac, 64, 64);
});
