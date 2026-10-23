#![no_main]

use dstu_core::hazmat::kupyna_kmac::{Kupyna256Kmac, Kupyna384Kmac, Kupyna512Kmac};
use libfuzzer_sys::fuzz_target;

// T-225: `mac`/`verify` must never panic for any key/message - a key of the wrong length is an
// error, a right-length key gives a deterministic tag that `verify` accepts, and the same tag
// with one bit flipped is rejected.
macro_rules! fuzz_variant {
    ($data:expr, $variant:ty, $mac_len:literal) => {
        let key_len = usize::from($data[0]) % ($mac_len + 2);
        if $data.len() > key_len {
            let (key, message) = $data[1..].split_at(key_len.min($data.len() - 1));
            match <$variant>::mac(key, message) {
                Ok(tag) => {
                    assert_eq!(key.len(), $mac_len);
                    assert_eq!(<$variant>::mac(key, message).expect("same key"), tag);
                    assert!(<$variant>::verify(key, message, &tag).is_ok());
                    let mut forged = tag;
                    forged[usize::from($data[0]) % $mac_len] ^= 1;
                    assert!(<$variant>::verify(key, message, &forged).is_err());
                }
                Err(_) => assert_ne!(key.len(), $mac_len),
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    fuzz_variant!(data, Kupyna256Kmac, 32);
    fuzz_variant!(data, Kupyna384Kmac, 48);
    fuzz_variant!(data, Kupyna512Kmac, 64);
});
