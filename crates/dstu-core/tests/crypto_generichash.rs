//! Smoke test for `dstu_core::crypto_generichash` (`docs/TASKS.md` T-105, `docs/DECISIONS.md` D-66) - a bare
//! re-export of `hazmat::kupyna`, already official-vector-tested under its own path
//! (`tests/kupyna.rs`). Nothing new to verify behaviorally (see the module doc); this only proves
//! the re-export path itself is wired correctly.

use dstu_core::crypto_generichash::{Kupyna256, Kupyna256Hasher, Kupyna512};
use dstu_core::hazmat::kupyna;

#[test]
fn reexported_digest_matches_hazmat() {
    let message = b"crypto_generichash re-export smoke test";
    assert_eq!(
        Kupyna256::digest(message),
        kupyna::Kupyna256::digest(message)
    );
    assert_eq!(
        Kupyna512::digest(message),
        kupyna::Kupyna512::digest(message)
    );
}

#[test]
fn reexported_hasher_matches_hazmat() {
    let mut streaming = Kupyna256Hasher::new();
    streaming.update(b"part one ");
    streaming.update(b"part two");
    assert_eq!(
        streaming.finalize(),
        kupyna::Kupyna256::digest(b"part one part two")
    );
}
