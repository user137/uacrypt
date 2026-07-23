//! Property tests for `hazmat::kupyna_kdf` (`crypto_kdf` equivalent, `DECISIONS.md` D-45) - no
//! oracle vector exists anywhere for this construction (see `docs/pseudocode/kupyna-kdf.md`), so
//! verification here is limited to determinism, distinctness, and an exact byte-layout pin against
//! a manual `hazmat::kupyna_kmac` call.

use dstu_core::hazmat::kupyna_kdf::{Kupyna256Kdf, Kupyna384Kdf, Kupyna512Kdf};
use dstu_core::hazmat::kupyna_kmac::{Kupyna256Kmac, Kupyna384Kmac, Kupyna512Kmac};
use proptest::prelude::*;

#[test]
fn kupyna256_kdf_is_deterministic() {
    let key = [0x11u8; 32];
    let context = *b"testctx1";
    let a = Kupyna256Kdf::derive_subkey(&key, 42, &context);
    let b = Kupyna256Kdf::derive_subkey(&key, 42, &context);
    assert_eq!(a, b);
}

#[test]
fn kupyna256_kdf_matches_manual_kmac_call() {
    let key = [0x22u8; 32];
    let context = *b"abcdefgh";
    let subkey_id: u64 = 7;

    let mut message = [0u8; 16];
    message[..8].copy_from_slice(&context);
    message[8..].copy_from_slice(&subkey_id.to_le_bytes());
    let expected = Kupyna256Kmac::mac(&key, &message).unwrap();

    assert_eq!(
        Kupyna256Kdf::derive_subkey(&key, subkey_id, &context),
        expected
    );
}

#[test]
fn kupyna384_kdf_matches_manual_kmac_call() {
    let key = [0x33u8; 48];
    let context = *b"ctxctxct";
    let subkey_id: u64 = 99;

    let mut message = [0u8; 16];
    message[..8].copy_from_slice(&context);
    message[8..].copy_from_slice(&subkey_id.to_le_bytes());
    let expected = Kupyna384Kmac::mac(&key, &message).unwrap();

    assert_eq!(
        Kupyna384Kdf::derive_subkey(&key, subkey_id, &context),
        expected
    );
}

#[test]
fn kupyna512_kdf_matches_manual_kmac_call() {
    let key = [0x44u8; 64];
    let context = *b"zzzzzzzz";
    let subkey_id: u64 = 1;

    let mut message = [0u8; 16];
    message[..8].copy_from_slice(&context);
    message[8..].copy_from_slice(&subkey_id.to_le_bytes());
    let expected = Kupyna512Kmac::mac(&key, &message).unwrap();

    assert_eq!(
        Kupyna512Kdf::derive_subkey(&key, subkey_id, &context),
        expected
    );
}

proptest! {
    #[test]
    fn different_subkey_id_gives_different_subkey(key in prop::array::uniform32(any::<u8>()), id_a in any::<u64>(), id_b in any::<u64>()) {
        prop_assume!(id_a != id_b);
        let context = *b"fixedctx";
        let a = Kupyna256Kdf::derive_subkey(&key, id_a, &context);
        let b = Kupyna256Kdf::derive_subkey(&key, id_b, &context);
        prop_assert_ne!(a, b);
    }

    #[test]
    fn different_context_gives_different_subkey(key in prop::array::uniform32(any::<u8>()), context_a in prop::array::uniform8(any::<u8>()), context_b in prop::array::uniform8(any::<u8>())) {
        prop_assume!(context_a != context_b);
        let a = Kupyna256Kdf::derive_subkey(&key, 0, &context_a);
        let b = Kupyna256Kdf::derive_subkey(&key, 0, &context_b);
        prop_assert_ne!(a, b);
    }

    #[test]
    fn different_key_gives_different_subkey(key_a in prop::array::uniform32(any::<u8>()), key_b in prop::array::uniform32(any::<u8>())) {
        prop_assume!(key_a != key_b);
        let context = *b"fixedctx";
        let a = Kupyna256Kdf::derive_subkey(&key_a, 0, &context);
        let b = Kupyna256Kdf::derive_subkey(&key_b, 0, &context);
        prop_assert_ne!(a, b);
    }
}
