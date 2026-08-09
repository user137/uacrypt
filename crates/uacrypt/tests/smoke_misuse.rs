//! T-200 Phase 2 (misuse/malformed-usage matrix): `--in`==`--out` across the commands that stream
//! to/from disk rather than building the whole result in memory first - the one misuse scenario in
//! this category with real teeth, per this task's own deferred-work note ("D-65 claims no partial
//! output on failure ... only a real subprocess + real filesystem check can confirm"). Everything
//! else in the fuller misuse matrix (missing/unknown flags, directory-as-`--out`, `--iterations 0`)
//! stays deferred (already covered representatively by `smoke_dispatch.rs` and the in-process
//! suite's own per-command coverage) - this file targets the one gap actually worth a real
//! subprocess: does "encrypt this file in place" destroy data or round-trip cleanly?
//!
//! `strumok-crypt`'s streaming path genuinely did destroy data here (confirmed by running the real
//! binary, not assumed) - `--out` was opened via `File::create` (truncating it) before `--in` had
//! finished being read, so `--in`==`--out` silently produced a 0-byte file at exit code 0. Fixed at
//! `crates/uacrypt/src/lib.rs` (`strumok_temp_path`, the same temp-file-then-rename discipline
//! `run_secretstream_command` already used) - this file is the subprocess-level regression test for
//! that fix, plus confirmation that the commands which were never at risk (whole-buffer read-then-
//! write: `encrypt`/`decrypt`, `kupyna-digest`, `hash`, `kalyna-block`) stay safe.

mod support;
use support::{uacrypt, write_bytes, TempDir};

fn ok(r: &support::Run) {
    assert!(
        r.success(),
        "code={:?} stdout={} stderr={}",
        r.code,
        r.stdout,
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn strumok_crypt_in_place_round_trips_without_destroying_data() {
    let dir = TempDir::new("misuse_strumok_inplace");
    let key = dir.file("key.bin");
    let iv = dir.file("iv.bin");
    let data = dir.file("data.bin");
    write_bytes(&key, &[0x11; 32]);
    write_bytes(&iv, &[0x22; 32]);
    // Multi-chunk (STRUMOK_STREAM_CHUNK_BYTES = 8192), deliberately not chunk-aligned.
    let plaintext = vec![b'A'; 8192 * 3 + 17];
    write_bytes(&data, &plaintext);

    let args = [
        "strumok-crypt",
        "--variant",
        "256",
        "--key",
        key.to_str().unwrap(),
        "--iv",
        iv.to_str().unwrap(),
        "--in",
        data.to_str().unwrap(),
        "--out",
        data.to_str().unwrap(),
    ];

    ok(&uacrypt(args));
    let after_first = support::read_bytes(&data);
    assert_eq!(
        after_first.len(),
        plaintext.len(),
        "must not be truncated/destroyed - this is the exact bug this test regresses"
    );
    assert_ne!(after_first, plaintext, "must actually be keystream-applied");

    // Strumok is its own inverse (XOR keystream) - applying again in place must recover plaintext.
    ok(&uacrypt(args));
    assert_eq!(
        support::read_bytes(&data),
        plaintext,
        "applying the keystream twice in place must recover the original plaintext"
    );

    let leftover = dir.file("data.bin.strumok-tmp");
    assert!(!leftover.exists(), "no leftover temp file after success");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn strumok_crypt_in_place_leaves_no_partial_output_on_read_failure() {
    let dir = TempDir::new("misuse_strumok_inplace_fail");
    let key = dir.file("key.bin");
    let iv = dir.file("iv.bin");
    write_bytes(&key, &[0x11; 32]);
    write_bytes(&iv, &[0x22; 32]);
    let missing_in = dir.file("does_not_exist.bin");
    let out = dir.file("out.bin");

    let r = uacrypt([
        "strumok-crypt",
        "--variant",
        "256",
        "--key",
        key.to_str().unwrap(),
        "--iv",
        iv.to_str().unwrap(),
        "--in",
        missing_in.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(r.failure());
    assert!(!out.exists(), "no partial --out on failure (D-65)");
    assert!(
        !dir.file("out.bin.strumok-tmp").exists(),
        "no leftover temp file on failure either"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn secretstream_encrypt_decrypt_in_place_round_trips() {
    let dir = TempDir::new("misuse_secretstream_inplace");
    let key = dir.file("key.bin");
    let data = dir.file("data.bin");
    assert!(uacrypt(["keygen", "--out", key.to_str().unwrap()]).success());
    let plaintext = b"overwrite me in place, subprocess boundary".to_vec();
    write_bytes(&data, &plaintext);

    ok(&uacrypt([
        "encrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        data.to_str().unwrap(),
        "--out",
        data.to_str().unwrap(),
    ]));
    assert_ne!(support::read_bytes(&data), plaintext);

    ok(&uacrypt([
        "decrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        data.to_str().unwrap(),
        "--out",
        data.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&data), plaintext);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kupyna_digest_in_place_does_not_corrupt_before_reading() {
    // Whole-buffer read-then-write path (unlike strumok's old streaming bug) - --in==--out must
    // still work, since the digest is fully computed before --out is ever touched.
    let dir = TempDir::new("misuse_digest_inplace");
    let data = dir.file("data.bin");
    let plaintext = b"hash me, then overwrite me with my own digest".to_vec();
    write_bytes(&data, &plaintext);

    ok(&uacrypt([
        "kupyna-digest",
        "--variant",
        "256",
        "--in",
        data.to_str().unwrap(),
        "--out",
        data.to_str().unwrap(),
    ]));
    let out = support::read_bytes(&data);
    assert_eq!(
        out.len(),
        32,
        "must be a genuine 32-byte digest, not garbage"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_block_in_place_does_not_corrupt_before_reading() {
    let dir = TempDir::new("misuse_kalyna_block_inplace");
    let key = dir.file("key.bin");
    let data = dir.file("data.bin");
    write_bytes(&key, &[0x33; 32]);
    let plaintext = [0x44u8; 32];
    write_bytes(&data, &plaintext);

    ok(&uacrypt([
        "kalyna-block",
        "encrypt",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--in",
        data.to_str().unwrap(),
        "--out",
        data.to_str().unwrap(),
    ]));
    let ct = support::read_bytes(&data);
    assert_eq!(ct.len(), 32);
    assert_ne!(ct, plaintext);

    ok(&uacrypt([
        "kalyna-block",
        "decrypt",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--in",
        data.to_str().unwrap(),
        "--out",
        data.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&data), plaintext);
}
