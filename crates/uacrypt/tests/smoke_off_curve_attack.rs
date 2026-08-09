//! T-200 Phase 4: attacker-supplied off-curve/small-subgroup public keys through `verify --key`,
//! at the real CLI/file boundary rather than the library's own in-process API. Previously deferred
//! ("these need constructed invalid curve points, real further work, not a same-session extension
//! of what's already spec'd from reading lib.rs alone") - implemented once the construction turned
//! out tractable: both DSTU 4145 curves reject a small-subgroup public key via an explicit
//! upfront `x == 0` check in `hazmat::dstu4145::signature{,257}::verify` (`docs/DECISIONS.md`
//! D-186's "general check" for m=257; T-189's original `x != 0` shortcut for m=163), reached before
//! `r`/`s` are ever examined - so any syntactically-valid signature bytes trigger the same
//! rejection path. This file constructs the curve's own order-2 point (`x = 0`, `y = sqrt(b)`) the
//! same way `crates/dstu-core/tests/dstu4145_signature{,257}.rs` already do at the library level,
//! encodes it into the exact tagged-verifying-key file format `verify --key` reads
//! (`read_tagged_verifying_key`, D-186 Decision 1), and confirms the real binary rejects it.
//!
//! `dstu9041`/`crypto_box`'s own order-2/order-4 finding (T-183, `docs/DECISIONS.md` D-176) is a
//! different shape and stays deferred: it is about a compressed x-only point reconstructing to a
//! small-subgroup `R'` *inside `box-open`'s ciphertext decoding*, not about `PublicKey` bytes fed
//! to `box-seal --key`/`box-open --key` directly - attacking it at the CLI boundary means
//! constructing a crafted *sealed file* (crypto_box's own wire format), not a crafted key file, a
//! genuinely separate task.

mod support;
use support::{uacrypt, write_bytes, TempDir};

use dstu_core::hazmat::dstu4145::{curve163, curve257, gf2m163, gf2m257};

/// Left-pads an odd-length hex string with one `0` nibble first - the vector files store field
/// elements as plain big-integer hex with no fixed-width zero-padding, so a value whose top nibble
/// is small drops it entirely (confirmed by counting programmatically, not by eye, per this
/// project's own `CLAUDE.md` note on exactly this failure mode: `B_M163_HEX` is 41 hex digits, one
/// short of the 42 a zero-padded 21-byte value would have).
fn decode_hex(hex: &str) -> Vec<u8> {
    let padded;
    let hex = if hex.len() % 2 == 1 {
        padded = format!("0{hex}");
        &padded
    } else {
        hex
    };
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex in this file's own constant")
        })
        .collect()
}

/// `crates/dstu-core/tests/vectors/dstu4145/gf2m163.json`'s own `"b"` field - the curve's own
/// domain parameter, not attacker-controlled; copied here (not read via `include_str!` across
/// crates) so this file depends only on its own crate's public API.
const B_M163_HEX: &str = "5FF6108462A2DC8210AB403925E638A19C1455D21";

/// `crates/dstu-core/tests/vectors/dstu4145/gf2m257_arith.json`'s own `"curve": { "b": ... }`.
const B_M257_HEX: &str = "01CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10";

/// One byte short of a 21-byte big-endian scalar equal to 1 - used for both `r` and `s`, since the
/// order-2 rejection fires before either is examined for real (same construction
/// `dstu4145_signature.rs`'s own `t189_public_key_validation` module documents: "any nonzero r/s
/// that passes the basic length/range check reaches the x==0 rejection").
fn scalar_one_be(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    v[len - 1] = 1;
    v
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn verify_rejects_order_two_public_key_m163() {
    // y = sqrt(b) = b^(2^162) - squaring is a bijection over GF(2^163) (Frobenius has order 163).
    let b = gf2m163::FieldElement::from_be_bytes(&decode_hex(B_M163_HEX));
    let mut y = b;
    for _ in 0..162 {
        y = y.square();
    }
    assert_eq!(y.square(), b, "constructed y must satisfy y^2 = b");

    let q = curve163::Point::Affine(gf2m163::FieldElement::from_be_bytes(&[0u8; 21]), y);
    assert!(
        q.is_on_curve(),
        "constructed order-2 point must be on-curve"
    );

    let dir = TempDir::new("off_curve_m163");
    let key_path = dir.file("attacker.key");
    let mut key_bytes = vec![0x01u8]; // CurveId::M163
    if let curve163::Point::Affine(x, y) = q {
        key_bytes.extend_from_slice(&x.to_be_bytes());
        key_bytes.extend_from_slice(&y.to_be_bytes());
    }
    assert_eq!(
        key_bytes.len(),
        43,
        "1 tag byte + 42-byte uncompressed x||y"
    );
    write_bytes(&key_path, &key_bytes);

    let msg_path = dir.file("msg.bin");
    write_bytes(
        &msg_path,
        b"arbitrary message - rejection does not depend on it",
    );
    let sig_path = dir.file("sig.bin");
    let mut sig = scalar_one_be(21);
    sig.extend(scalar_one_be(21));
    assert_eq!(sig.len(), 42);
    write_bytes(&sig_path, &sig);

    let r = uacrypt([
        "verify",
        "--key",
        key_path.to_str().unwrap(),
        "--in",
        msg_path.to_str().unwrap(),
        "--sig",
        sig_path.to_str().unwrap(),
    ]);
    assert!(
        r.failure(),
        "an order-2 (small-subgroup) m=163 public key must never verify, regardless of r/s"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn verify_rejects_order_two_public_key_m257() {
    // y = sqrt(b) = b^(2^256) - Frobenius has order 257 over GF(2^257).
    let b = gf2m257::FieldElement::from_be_bytes(&decode_hex(B_M257_HEX));
    let mut y = b;
    for _ in 0..256 {
        y = y.square();
    }
    assert_eq!(y.square(), b, "constructed y must satisfy y^2 = b");

    let q = curve257::Point::Affine(gf2m257::FieldElement::from_be_bytes(&[0u8; 33]), y);
    assert!(
        q.is_on_curve(),
        "constructed order-2 point must be on-curve"
    );

    let dir = TempDir::new("off_curve_m257");
    let key_path = dir.file("attacker.key");
    let mut key_bytes = vec![0x02u8]; // CurveId::M257
    if let curve257::Point::Affine(x, y) = q {
        key_bytes.extend_from_slice(&x.to_be_bytes());
        key_bytes.extend_from_slice(&y.to_be_bytes());
    }
    assert_eq!(
        key_bytes.len(),
        67,
        "1 tag byte + 66-byte uncompressed x||y"
    );
    write_bytes(&key_path, &key_bytes);

    let msg_path = dir.file("msg.bin");
    write_bytes(
        &msg_path,
        b"arbitrary message - rejection does not depend on it",
    );
    let sig_path = dir.file("sig.bin");
    let mut sig = scalar_one_be(33);
    sig.extend(scalar_one_be(33));
    assert_eq!(sig.len(), 66);
    write_bytes(&sig_path, &sig);

    let r = uacrypt([
        "verify",
        "--key",
        key_path.to_str().unwrap(),
        "--in",
        msg_path.to_str().unwrap(),
        "--sig",
        sig_path.to_str().unwrap(),
    ]);
    assert!(
        r.failure(),
        "an order-2 (small-subgroup) m=257 public key must never verify, regardless of r/s"
    );
}
