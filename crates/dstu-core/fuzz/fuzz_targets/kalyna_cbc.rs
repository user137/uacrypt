#![no_main]

use dstu_core::hazmat::kalyna_cbc::{
    Kalyna128_128Cbc, Kalyna128_256Cbc, Kalyna256_256Cbc, Kalyna256_512Cbc, Kalyna512_512Cbc,
};
use libfuzzer_sys::fuzz_target;

// T-225: `new`/`encrypt_in_place`/`decrypt_in_place` must never panic for any key/iv/buffer -
// a length that is not a block multiple is `InvalidLength`, and decryption undoes encryption.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len + $block_len {
            let key: &[u8; $key_len] = $data[..$key_len].try_into().expect("key slice");
            let iv: &[u8; $block_len] = $data[$key_len..$key_len + $block_len]
                .try_into()
                .expect("iv slice");
            let rest = &$data[$key_len + $block_len..];

            let mut garbage = rest.to_vec();
            let _ = <$variant>::new(key, iv).decrypt_in_place(&mut garbage);

            let mut buf = rest.to_vec();
            let aligned = <$variant>::new(key, iv).encrypt_in_place(&mut buf).is_ok();
            assert_eq!(aligned, rest.len() % $block_len == 0);
            if aligned {
                <$variant>::new(key, iv)
                    .decrypt_in_place(&mut buf)
                    .expect("aligned length");
                assert_eq!(buf, rest);
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Cbc, 16, 16);
    fuzz_variant!(data, Kalyna128_256Cbc, 32, 16);
    fuzz_variant!(data, Kalyna256_256Cbc, 32, 32);
    fuzz_variant!(data, Kalyna256_512Cbc, 64, 32);
    fuzz_variant!(data, Kalyna512_512Cbc, 64, 64);
});
