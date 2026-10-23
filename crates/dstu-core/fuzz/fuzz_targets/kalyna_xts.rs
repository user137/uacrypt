#![no_main]

use dstu_core::hazmat::kalyna_xts::{
    Kalyna128_128Xts, Kalyna128_256Xts, Kalyna256_256Xts, Kalyna256_512Xts, Kalyna512_512Xts,
};
use libfuzzer_sys::fuzz_target;

// T-225: `encrypt_in_place`/`decrypt_in_place` must never panic for any key/iv/buffer - below one
// block is `InvalidLength`; from one block up, any length works (ciphertext stealing covers the
// partial last block) and decryption undoes encryption.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len + $block_len {
            let key: &[u8; $key_len] = $data[..$key_len].try_into().expect("key slice");
            let iv: &[u8; $block_len] = $data[$key_len..$key_len + $block_len]
                .try_into()
                .expect("iv slice");
            let rest = &$data[$key_len + $block_len..];
            let cipher = <$variant>::new(key);

            let mut garbage = rest.to_vec();
            let _ = cipher.decrypt_in_place(iv, &mut garbage);

            let mut buf = rest.to_vec();
            let long_enough = cipher.encrypt_in_place(iv, &mut buf).is_ok();
            assert_eq!(long_enough, rest.len() >= $block_len);
            if long_enough {
                cipher
                    .decrypt_in_place(iv, &mut buf)
                    .expect("at least one block");
                assert_eq!(buf, rest);
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Xts, 16, 16);
    fuzz_variant!(data, Kalyna128_256Xts, 32, 16);
    fuzz_variant!(data, Kalyna256_256Xts, 32, 32);
    fuzz_variant!(data, Kalyna256_512Xts, 64, 32);
    fuzz_variant!(data, Kalyna512_512Xts, 64, 64);
});
