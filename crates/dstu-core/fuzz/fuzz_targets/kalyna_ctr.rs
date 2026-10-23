#![no_main]

use dstu_core::hazmat::kalyna_ctr::{
    Kalyna128_128Ctr, Kalyna128_256Ctr, Kalyna256_256Ctr, Kalyna256_512Ctr, Kalyna512_512Ctr,
};
use libfuzzer_sys::fuzz_target;

// T-225: `apply_in_place` must never panic, applying it twice is the identity, and the keystream
// continues across calls - two calls split at a fuzz-chosen (usually non-aligned) offset give
// exactly the one-call result.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() > $key_len + $block_len {
            let key: &[u8; $key_len] = $data[..$key_len].try_into().expect("key slice");
            let iv: &[u8; $block_len] = $data[$key_len..$key_len + $block_len]
                .try_into()
                .expect("iv slice");
            let split = usize::from($data[$key_len + $block_len]);
            let rest = &$data[$key_len + $block_len + 1..];

            let mut whole = rest.to_vec();
            <$variant>::new(key, iv).apply_in_place(&mut whole);

            let mut parts = rest.to_vec();
            let (a, b) = parts.split_at_mut(split.min(rest.len()));
            let mut cipher = <$variant>::new(key, iv);
            cipher.apply_in_place(a);
            cipher.apply_in_place(b);
            assert_eq!(parts, whole);

            <$variant>::new(key, iv).apply_in_place(&mut whole);
            assert_eq!(whole, rest);
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Ctr, 16, 16);
    fuzz_variant!(data, Kalyna128_256Ctr, 32, 16);
    fuzz_variant!(data, Kalyna256_256Ctr, 32, 32);
    fuzz_variant!(data, Kalyna256_512Ctr, 64, 32);
    fuzz_variant!(data, Kalyna512_512Ctr, 64, 64);
});
