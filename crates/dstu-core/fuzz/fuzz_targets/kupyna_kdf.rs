#![no_main]

use dstu_core::hazmat::kupyna_kdf::{Kupyna256Kdf, Kupyna384Kdf, Kupyna512Kdf};
use libfuzzer_sys::fuzz_target;

// T-225: `derive_subkey` must never panic for any master key/id/context (its internal KMAC call
// is `unreachable!` on error, so a reachable error would show up here), is deterministic, and
// a different subkey id gives a different subkey (D-45's property, here on fuzz-chosen inputs).
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $key_len:literal) => {
        if $data.len() >= $key_len + 16 {
            let key: &[u8; $key_len] = $data[..$key_len].try_into().expect("key slice");
            let id = u64::from_le_bytes($data[$key_len..$key_len + 8].try_into().expect("id"));
            let context: &[u8; 8] = $data[$key_len + 8..$key_len + 16]
                .try_into()
                .expect("context");
            let subkey = <$variant>::derive_subkey(key, id, context);
            assert_eq!(<$variant>::derive_subkey(key, id, context), subkey);
            assert_ne!(
                <$variant>::derive_subkey(key, id.wrapping_add(1), context),
                subkey
            );
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_variant!(data, Kupyna256Kdf, 32);
    fuzz_variant!(data, Kupyna384Kdf, 48);
    fuzz_variant!(data, Kupyna512Kdf, 64);
});
