//! Tests for `dstu_core::randombytes` (`randombytes` equivalent, `TASKS.md` T-72,
//! `DECISIONS.md` D-48) - the OS-CSPRNG wrapper (`getrandom`), `std`-gated so the `no_std` core
//! build never depends on it (`DECISIONS.md` D-04 addendum).
//!
//! Not a DSTU question, and there's no oracle for OS randomness by definition - verification here
//! is limited to determinism-of-shape properties (buffer actually gets filled, two calls don't
//! collide), the same posture already established for `hazmat::kupyna_kdf`'s distinctness tests.

#![cfg(feature = "std")]

use dstu_core::randombytes::randombytes_buf;

#[test]
fn fills_a_nonzero_length_buffer() {
    let mut buf = [0u8; 32];
    randombytes_buf(&mut buf).expect("OS CSPRNG available in test environment");
    assert_ne!(
        buf, [0u8; 32],
        "32 random bytes matching the all-zero sentinel is a ~2^-256 event"
    );
}

#[test]
fn two_calls_produce_different_output() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    randombytes_buf(&mut a).expect("OS CSPRNG available in test environment");
    randombytes_buf(&mut b).expect("OS CSPRNG available in test environment");
    assert_ne!(
        a, b,
        "two independent 32-byte draws colliding is a ~2^-256 event"
    );
}

#[test]
fn zero_length_buffer_is_not_an_error() {
    let mut buf: [u8; 0] = [];
    randombytes_buf(&mut buf).expect("filling zero bytes must not fail");
}

#[test]
fn does_not_touch_bytes_outside_the_given_buffer() {
    let mut storage = [0xAAu8; 40];
    randombytes_buf(&mut storage[8..32]).expect("OS CSPRNG available in test environment");
    assert_eq!(
        &storage[..8],
        &[0xAA; 8],
        "bytes before the slice must be untouched"
    );
    assert_eq!(
        &storage[32..],
        &[0xAA; 8],
        "bytes after the slice must be untouched"
    );
}
