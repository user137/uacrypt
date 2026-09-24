//! T-200 Phase 3/4 (active-attack category): cross-key-type confusion, revisited for typed key
//! files (T-256, D-212). Before 0.5.0, `keygen`, `box-keygen`/`box-pubkey` and
//! `box-keygen512`/`box-pubkey512` wrote same-length raw files with nothing to tell them apart, and
//! only each type's own validity check caught *some* misuse: a box secret key passed to
//! `box-seal` was accepted whenever its 32 bytes happened to decode a curve point, sealing a file
//! nobody could open. Now every key line names its kind, so the confusions this file used to
//! document are rejected by name before any work; `smoke_typed_keys.rs` covers every
//! command-by-kind pairing.
//!
//! The byte patterns below are the ones T-200 picked by running the real binary (not by
//! assumption). Typed with the *right* kind, they still show that each type's own validity check
//! runs behind the key-file layer: a secret key's is magnitude-only (`0 < e < n`), a public key's
//! needs the x-coordinate to decode a curve point.

mod support;
use support::{uacrypt, write_bytes, write_key, TempDir};

const BOX_SECRET: &str = "UACRYPT-SECRET-BOX256";
const BOX_PUBLIC: &str = "uacrypt-box256-public";

fn ok(r: &support::Run) {
    assert!(
        r.success(),
        "code={:?} stdout={} stderr={}",
        r.code,
        r.stdout,
        r.stderr
    );
}

fn run_box(
    dir: &TempDir,
    cmd: &str,
    key: &std::path::Path,
    input: &std::path::Path,
) -> support::Run {
    uacrypt([
        cmd,
        "--key",
        key.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
        "--out",
        dir.file(&format!("{cmd}.out")).to_str().unwrap(),
    ])
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn all_zero_and_all_ff_box_keys_fail_the_validity_check_behind_the_key_layer() {
    let dir = TempDir::new("keyconf_box_zero_ff");
    let msg = dir.file("msg.bin");
    write_bytes(&msg, b"irrelevant");
    for byte in [0x00u8, 0xFF] {
        let secret = dir.file(&format!("secret_{byte:02x}"));
        let public = dir.file(&format!("public_{byte:02x}"));
        write_key(&secret, BOX_SECRET, &[byte; 32]);
        write_key(&public, BOX_PUBLIC, &[byte; 32]);

        let r = run_box(&dir, "box-open", &secret, &msg);
        assert_eq!(r.code, Some(3), "{}", r.stderr);
        assert!(
            r.stderr.contains("not a valid crypto_box key"),
            "{}",
            r.stderr
        );
        let r = run_box(&dir, "box-seal", &public, &msg);
        assert_eq!(r.code, Some(3), "{}", r.stderr);
        assert!(
            r.stderr.contains("not a valid crypto_box key"),
            "{}",
            r.stderr
        );
    }
}

/// `[0x11; 32]` passes a secret key's range check but is not a curve point; `[0x55; 32]` is the
/// mirror image. Same 32 bytes, typed as each kind in turn.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn secret_and_public_validity_checks_differ_for_the_same_bytes() {
    let dir = TempDir::new("keyconf_box_low_mid");
    let msg = dir.file("msg.bin");
    write_bytes(&msg, b"not real box-seal output, just needs to exist");

    let low_secret = dir.file("low_secret");
    let low_public = dir.file("low_public");
    write_key(&low_secret, BOX_SECRET, &[0x11; 32]);
    write_key(&low_public, BOX_PUBLIC, &[0x11; 32]);
    let r = run_box(&dir, "box-open", &low_secret, &msg);
    assert_eq!(
        r.code,
        Some(1),
        "parses, then the input is rejected: {}",
        r.stderr
    );
    let r = run_box(&dir, "box-seal", &low_public, &msg);
    assert!(
        r.stderr.contains("not a valid crypto_box key"),
        "{}",
        r.stderr
    );

    let mid_secret = dir.file("mid_secret");
    let mid_public = dir.file("mid_public");
    write_key(&mid_secret, BOX_SECRET, &[0x55; 32]);
    write_key(&mid_public, BOX_PUBLIC, &[0x55; 32]);
    ok(&run_box(&dir, "box-seal", &mid_public, &msg));
    let r = run_box(&dir, "box-open", &mid_secret, &msg);
    assert!(
        r.stderr.contains("not a valid crypto_box key"),
        "{}",
        r.stderr
    );
}

/// The 0.4 bug, reproduced with real key files: a box *secret* key given to `box-seal`, and a
/// `keygen` symmetric key given to `box-open`. Both used to get past key parsing whenever the
/// bytes happened to be valid; now both are refused by kind, with nothing written.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn same_length_keys_of_another_kind_are_rejected_by_name() {
    let dir = TempDir::new("keyconf_by_name");
    let box_sk = dir.file("box.key");
    let sym = dir.file("sym.key");
    let msg = dir.file("msg.bin");
    ok(&uacrypt(["box-keygen", "--out", box_sk.to_str().unwrap()]));
    ok(&uacrypt(["keygen", "--out", sym.to_str().unwrap()]));
    write_bytes(&msg, b"sealed to nobody");

    let r = run_box(&dir, "box-seal", &box_sk, &msg);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert!(
        r.stderr.contains(
            "is a box secret key (DSTU 9041, l(p)=256), but box-seal needs a box public key"
        ) && r.stderr.contains("`uacrypt box-pubkey`"),
        "{}",
        r.stderr
    );
    assert!(!dir.file("box-seal.out").exists());

    let r = run_box(&dir, "box-open", &sym, &msg);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert!(r.stderr.contains("is a symmetric key"), "{}", r.stderr);
    assert!(!dir.file("box-open.out").exists());
}

/// `[0x02; 64]` is both a valid box-512 secret key and a valid box-512 public key (D-182), so the
/// same bytes used to mean two different things depending only on the flag. Typed, a secret key
/// line is refused where a public key is needed, and the hint names the one command that makes the
/// right key (T-257: `box-pubkey` serves both curves).
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box512_dual_valid_bytes_are_told_apart_by_kind() {
    let dir = TempDir::new("keyconf_box512_dual");
    let secret = dir.file("dual_secret");
    let public = dir.file("dual_public");
    let msg = dir.file("msg.bin");
    write_key(&secret, "UACRYPT-SECRET-BOX512", &[0x02; 64]);
    write_key(&public, "uacrypt-box512-public", &[0x02; 64]);
    write_bytes(&msg, b"irrelevant");

    ok(&run_box(&dir, "box-seal", &public, &msg));
    let r = run_box(&dir, "box-seal", &secret, &msg);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert!(
        r.stderr
            .contains("is a box secret key (DSTU 9041, l(p)=512)"),
        "{}",
        r.stderr
    );

    assert!(
        r.stderr.contains(
            "make the right key with `uacrypt box-pubkey`
"
        ),
        "{}",
        r.stderr
    );
}
