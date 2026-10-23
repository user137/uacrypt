#![no_main]

use dstu_core::hazmat::kalyna_ecb::{
    Kalyna128_128Ecb, Kalyna128_256Ecb, Kalyna256_256Ecb, Kalyna256_512Ecb, Kalyna512_512Ecb,
};
use libfuzzer_sys::fuzz_target;

// T-225: `new`/`encrypt_in_place`/`decrypt_in_place` must never panic for any key/buffer - a
// length that is not a block multiple is `InvalidLength`, and decryption undoes encryption.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal, $block_len:literal) => {
        if $data.len() >= $key_len {
            let key: &[u8; $key_len] = $data[..$key_len].try_into().expect("key slice");
            let rest = &$data[$key_len..];
            let cipher = <$variant>::new(key);

            let mut garbage = rest.to_vec();
            let _ = cipher.decrypt_in_place(&mut garbage);

            let mut buf = rest.to_vec();
            let aligned = cipher.encrypt_in_place(&mut buf).is_ok();
            assert_eq!(aligned, rest.len() % $block_len == 0);
            if aligned {
                cipher.decrypt_in_place(&mut buf).expect("aligned length");
                assert_eq!(buf, rest);
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kalyna128_128Ecb, 16, 16);
    fuzz_variant!(data, Kalyna128_256Ecb, 32, 16);
    fuzz_variant!(data, Kalyna256_256Ecb, 32, 32);
    fuzz_variant!(data, Kalyna256_512Ecb, 64, 32);
    fuzz_variant!(data, Kalyna512_512Ecb, 64, 64);
});
