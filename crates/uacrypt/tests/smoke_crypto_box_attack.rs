//! T-200 Phase 4: `box-seal`/`box-open`'s own small-subgroup attack, at the real CLI/sealed-file
//! boundary - the item this task's own deferred list called "a genuinely different shape" from
//! `verify --key`'s off-curve attack (`smoke_off_curve_attack.rs`): it needs a crafted *sealed
//! file* in `crypto_box`'s own wire format, not a crafted key file.
//!
//! Grounded directly in `docs/DECISIONS.md` D-167 Finding 1 (a real security fix, not a
//! hypothetical): DSTU 9041's clause 12 step 2 rejects `r=0`/`r=1`/`r^2=a*d^-1 (mod p)`, but not
//! `r=p-1`, which reconstructs to `R'=(p-1,0)` - a genuine order-2 point outside the base point's
//! own subgroup `<P>`. Left unrejected, a chosen-ciphertext query with `r=p-1` leaks the private
//! key's parity bit. `hazmat::dstu9041::curve256::point_from_x` was fixed to reject `r=p-1`
//! explicitly. This file re-exercises that fix through the real `uacrypt` binary and file format,
//! not just `hazmat`'s own in-process API (`crates/dstu-core/tests/dstu9041_curve.rs`'s
//! `r_equals_p_minus_1_reconstructs_the_order_2_point` proves the curve-level arithmetic fact;
//! `crypto_box`'s own test suite proves the library-level `open()` rejects it; this proves the
//! *CLI/sealed-file* boundary does too).
//!
//! **Deliberately not attempted here: an order-4 attack (D-167 Finding 2).** `docs/DECISIONS.md`
//! D-173 already investigated this directly at the `dstu-core` level (with full internal-crate
//! access, `#[cfg(test)]` module and all) and hit a genuine, currently-unresolved research
//! question: "whether a concrete order-4 point is reachable through `point_from_x`'s own
//! reconstruction formula at all is an open question, not confirmed either way" - existence is
//! proven (Hasse's bound), reachability via the actual public reconstruction path is not. Attacking
//! it from the CLI subprocess boundary, with *less* internal access than that investigation had,
//! cannot responsibly claim to do better - it would need the same analytic answer D-173 left open
//! ("does an order-4 point's `x` ever satisfy `euler_criterion`?"), not more engineering. The order-2
//! case above is the one D-167/D-173 both confirm is real and reachable, so it is the one exercised
//! here.
//!
//! **Wire format** (`crypto_box.rs`'s `seal`/`open`, confirmed by reading both, not assumed):
//! `[kem_ciphertext: 128 bytes][secretstream header: 32][ciphertext: N][auth tag: 16]`. The KEM
//! ciphertext's own first 32 bytes are `r` (`hazmat::dstu9041::encryption::encrypt`'s
//! `ciphertext[..32] = r_bytes`) - the exact field this attack overwrites.

mod support;
use support::{uacrypt, TempDir};

use dstu_core::hazmat::dstu9041::fp256::FieldElement;

/// `crates/dstu-core/tests/vectors/dstu9041/curve-E256-1.json`'s own `"p_hex"` - E256/1's field
/// prime, not attacker-controlled. `p - 1` is computed via the crate's own `FieldElement::sub` at
/// runtime (mirroring `dstu9041_curve.rs`'s own `r_equals_p_minus_1_reconstructs_the_order_2_point`
/// construction) rather than hand-subtracted - this project's own `CLAUDE.md` note on miscounting
/// long same-character hex runs by eye applies exactly as much to hand arithmetic on a 256-bit
/// value as to transcription.
const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE4D";

fn decode_hex_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "expected a zero-padded 32-byte hex string");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .expect("valid hex in this file's own constant");
    }
    out
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_open_rejects_r_equals_p_minus_one_order_two_point() {
    let p = FieldElement::from_be_bytes(&decode_hex_32(P_HEX));
    let p_minus_1 = p.sub(FieldElement::ONE);
    let r_bytes = p_minus_1.to_be_bytes();

    let dir = TempDir::new("box_attack_r_p_minus_1");
    let secret = dir.file("recipient.key");
    let public = dir.file("recipient.pub");
    let msg = dir.file("msg.txt");
    let sealed = dir.file("msg.box");
    let opened = dir.file("opened.txt");

    assert!(uacrypt(["box-keygen", "--out", secret.to_str().unwrap()]).success());
    assert!(uacrypt([
        "box-pubkey",
        "--key",
        secret.to_str().unwrap(),
        "--out",
        public.to_str().unwrap(),
    ])
    .success());
    support::write_bytes(
        &msg,
        b"a message a chosen-ciphertext attacker wants to leak bits of",
    );
    assert!(uacrypt([
        "box-seal",
        "--key",
        public.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sealed.to_str().unwrap(),
    ])
    .success());

    let mut tampered = support::read_bytes(&sealed);
    assert!(
        tampered.len() >= 32,
        "a real sealed file must be at least 32 bytes (the r field alone)"
    );
    tampered[..32].copy_from_slice(&r_bytes);
    support::write_bytes(&sealed, &tampered);

    let r = uacrypt([
        "box-open",
        "--key",
        secret.to_str().unwrap(),
        "--in",
        sealed.to_str().unwrap(),
        "--out",
        opened.to_str().unwrap(),
    ]);
    assert!(
        r.failure(),
        "r=p-1 (a genuine order-2 point outside <P>, D-167 Finding 1) must be rejected, not \
         silently accepted as a real chosen-ciphertext oracle"
    );
    assert!(
        !opened.exists(),
        "no partial/wrong plaintext written on this rejection"
    );
}
