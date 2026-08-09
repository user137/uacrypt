//! T-200 Phase 3/4 (active-attack category, T-183/D-173's precedent extended to the CLI
//! boundary): `verify --key`'s tagged-verifying-key format (D-186 Decision 1, landed T-199) has
//! never been exercised with genuinely attacker-controlled bytes - only one `0xFF` case exists in
//! the in-process suite (`crates/uacrypt/src/lib.rs`). This file drives the full tag/length matrix
//! implied by `read_tagged_verifying_key` (lib.rs:2190-2233) directly: tag `0x00`/`0x03`..`0xFF`
//! must produce the named `SignVerifyUnsupportedCurve` error (not a generic parse failure or a
//! panic - D-186 Decision 3's whole point), and a correctly-tagged-but-wrong-length body must
//! produce `WrongLength` with the *other* curve's expected length, not a crash or silent
//! misinterpretation.

mod support;
use support::{uacrypt, write_bytes, TempDir};

fn setup(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let msg = dir.file("msg.bin");
    let sig = dir.file("sig.bin");
    write_bytes(
        &msg,
        b"irrelevant - key parsing fails before this is ever read",
    );
    write_bytes(&sig, &[0u8; 42]);
    (msg, sig)
}

fn run_verify(dir: &TempDir, key: &std::path::Path) -> support::Run {
    let (msg, sig) = setup(dir);
    uacrypt([
        "verify",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--sig",
        sig.to_str().unwrap(),
    ])
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn empty_key_file_is_wrong_length_not_a_panic() {
    let dir = TempDir::new("verify_tag_empty");
    let key = dir.file("key.bin");
    write_bytes(&key, &[]);
    let r = run_verify(&dir, &key);
    assert!(r.failure());
    assert_eq!(r.code, Some(1));
    assert!(
        r.stderr
            .contains("verifying key must be exactly 43 bytes, got 0"),
        "stderr={}",
        r.stderr
    );
}

/// Every tag byte outside `{0x01, 0x02}` must hit the *named* `SignVerifyUnsupportedCurve` error,
/// not `WrongLength`/`SignKeyInvalid`/a panic - a policy-relevant distinction (D-186 Decision 2/3):
/// a caller must be able to tell "this key names a curve I don't support" from "this key is
/// corrupt". Sweeps a representative set, not all 254 values - the code path is a single `match`
/// arm with no per-value branching, so a representative sweep is exhaustive in practice.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unsupported_tag_bytes_report_the_specific_tag() {
    let dir = TempDir::new("verify_tag_unsupported");
    for tag in [0x00u8, 0x03, 0x04, 0x7F, 0x80, 0xFE, 0xFF] {
        let key = dir.file(&format!("key_{tag:02x}.bin"));
        let mut body = vec![tag];
        body.extend(std::iter::repeat_n(0u8, 66)); // long enough to not also trip WrongLength
        write_bytes(&key, &body);
        let r = run_verify(&dir, &key);
        assert!(r.failure(), "tag=0x{tag:02X} unexpectedly succeeded");
        let expected = format!("curve id {tag} (0x{tag:02X})");
        assert!(
            r.stderr.contains(&expected),
            "tag=0x{tag:02X} stderr={}",
            r.stderr
        );
        assert!(
            r.stderr.contains("does not support"),
            "tag=0x{tag:02X} stderr={}",
            r.stderr
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn m163_tag_with_m257_body_length_is_wrong_length_not_misparsed() {
    let dir = TempDir::new("verify_tag_163_with_257_body");
    let key = dir.file("key.bin");
    let mut body = vec![0x01u8]; // CurveId::M163
    body.extend(std::iter::repeat_n(0u8, 66)); // M257's own body length, not M163's 42
    write_bytes(&key, &body);
    let r = run_verify(&dir, &key);
    assert!(r.failure());
    assert!(
        r.stderr
            .contains("verifying key must be exactly 43 bytes, got 67"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn m257_tag_with_m163_body_length_is_wrong_length_not_misparsed() {
    let dir = TempDir::new("verify_tag_257_with_163_body");
    let key = dir.file("key.bin");
    let mut body = vec![0x02u8]; // CurveId::M257
    body.extend(std::iter::repeat_n(0u8, 42)); // M163's own body length, not M257's 66
    write_bytes(&key, &body);
    let r = run_verify(&dir, &key);
    assert!(r.failure());
    assert!(
        r.stderr
            .contains("verifying key must be exactly 67 bytes, got 43"),
        "stderr={}",
        r.stderr
    );
}

/// A tag byte alone, no body at all - the degenerate 1-byte case `split_first` still handles
/// distinctly from the fully-empty (0-byte) case.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn tag_byte_with_no_body_is_wrong_length() {
    let dir = TempDir::new("verify_tag_no_body");
    let key = dir.file("key.bin");
    write_bytes(&key, &[0x01u8]);
    let r = run_verify(&dir, &key);
    assert!(r.failure());
    assert!(
        r.stderr
            .contains("verifying key must be exactly 43 bytes, got 1"),
        "stderr={}",
        r.stderr
    );
}
