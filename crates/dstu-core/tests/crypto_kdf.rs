//! Tests for `dstu_core::crypto_kdf` (`TASKS.md` T-105, `DECISIONS.md` D-66) - the
//! libsodium-ergonomics wrapper over `hazmat::kupyna_kdf::Kupyna256Kdf`. `Kupyna256Kdf` itself is
//! already covered by determinism/distinctness property tests (`tests/kupyna_kdf.rs` - no oracle
//! vector exists for this construction at all, D-45); this file exercises delegation
//! (correctness) and misuse (degenerate-but-legal inputs) at this wrapper's own layer, per
//! `CLAUDE.md`'s standing three-category rule (D-64/D-65). There is no rejection category here -
//! `derive_subkey` has no tag or checksum to tamper with, see the module doc and D-66.

use dstu_core::crypto_kdf::MasterKey;
use dstu_core::hazmat::kupyna_kdf::Kupyna256Kdf;

#[test]
fn derive_subkey_matches_hazmat_kupyna256_kdf() {
    let raw_key = [0x5Au8; 32];
    let context = *b"testctx1";
    let key = MasterKey::from_bytes(raw_key);

    let subkey = key.derive_subkey(42, &context);
    let expected = Kupyna256Kdf::derive_subkey(&raw_key, 42, &context);
    assert_eq!(subkey, expected);
}

#[test]
fn derive_subkey_is_deterministic() {
    let key = MasterKey::from_bytes([0x11u8; 32]);
    let context = *b"kdftest1";
    let a = key.derive_subkey(7, &context);
    let b = key.derive_subkey(7, &context);
    assert_eq!(a, b);
}

#[test]
fn different_subkey_id_gives_different_subkey() {
    let key = MasterKey::from_bytes([0x22u8; 32]);
    let context = *b"fixedctx";
    assert_ne!(
        key.derive_subkey(0, &context),
        key.derive_subkey(1, &context)
    );
}

#[test]
fn all_zero_master_key_succeeds() {
    let key = MasterKey::from_bytes([0u8; 32]);
    let context = *b"zzzzzzzz";
    let subkey_a = key.derive_subkey(0, &context);
    let subkey_b = key.derive_subkey(1, &context);
    assert_ne!(subkey_a, subkey_b);
}

#[cfg(feature = "std")]
#[test]
fn generate_produces_a_usable_key() {
    let key = MasterKey::generate().expect("OS CSPRNG available in tests");
    let context = *b"generatd";
    let subkey = key.derive_subkey(0, &context);
    assert_eq!(subkey, key.derive_subkey(0, &context));
}
