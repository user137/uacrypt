//! T-200 Phase 3/4: `decrypt`'s on-disk wire format (`crypto_secretstream`, D-68) - length-prefixed
//! chunk framing `[header:32][tag:1][len:4 LE][ciphertext:len][auth_tag:16]...`, terminated by a
//! chunk tagged `Final` - attacked directly at the file layer, mapped to the specific named
//! `CliError` each malformed shape should produce (never just "a nonzero exit code"). Wire offsets
//! taken from `crates/uacrypt/src/lib.rs`'s own `run_secretstream_decrypt` (header then
//! `[tag:1][len_le:4][ciphertext][auth_tag:SECRETSTREAM_TAG_LEN]`, `SECRETSTREAM_TAG_LEN = 16`,
//! `SECRETSTREAM_CHUNK_BYTES = 8192`) - every fixture here is a real `encrypt` output for a message
//! well under the chunk size, so it is exactly one record tagged `Final` (per `run_secretstream_
//! encrypt`'s own one-chunk-ahead buffering doc comment): bytes `[0..32)` header, `[32]` tag byte
//! `0x03`, `[33..37)` little-endian length, `[37..37+len)` ciphertext, then a 16-byte auth tag.

mod support;
use support::{uacrypt, write_bytes, TempDir};

const HEADER_LEN: usize = 32;
const TAG_LEN: usize = 16;
const PREFIX_LEN: usize = 5; // 1 tag byte + 4-byte LE length

struct Fixture {
    key: std::path::PathBuf,
    good: Vec<u8>,
    plaintext_len: usize,
}

fn make_fixture(dir: &TempDir, label: &str, plaintext: &[u8]) -> Fixture {
    let key = dir.file(&format!("{label}_key.bin"));
    let pt = dir.file(&format!("{label}_pt.bin"));
    let ct = dir.file(&format!("{label}_ct.bin"));
    assert!(uacrypt(["keygen", "--out", key.to_str().unwrap()]).success());
    write_bytes(&pt, plaintext);
    let r = uacrypt([
        "encrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
    ]);
    assert!(r.success(), "fixture encrypt failed: {}", r.stderr);
    let good = support::read_bytes(&ct);
    // Single-record sanity check every test in this file relies on: exactly one Final-tagged chunk.
    assert_eq!(
        good[HEADER_LEN], 0x03,
        "fixture is not a single Final-tagged record as assumed"
    );
    let claimed_len = u32::from_le_bytes([good[33], good[34], good[35], good[36]]) as usize;
    assert_eq!(claimed_len, plaintext.len());
    assert_eq!(good.len(), HEADER_LEN + PREFIX_LEN + claimed_len + TAG_LEN);
    Fixture {
        key,
        good,
        plaintext_len: plaintext.len(),
    }
}

fn try_decrypt(dir: &TempDir, key: &std::path::Path, tampered: &[u8], label: &str) -> support::Run {
    let in_path = dir.file(&format!("{label}_tampered.bin"));
    let out_path = dir.file(&format!("{label}_out.bin"));
    write_bytes(&in_path, tampered);
    uacrypt([
        "decrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        in_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ])
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn genuine_round_trip_still_works_sanity_check() {
    let dir = TempDir::new("ss_attack_sanity");
    let f = make_fixture(&dir, "sanity", b"a real message, untampered");
    let r = try_decrypt(&dir, &f.key, &f.good, "sanity");
    assert!(r.success(), "stderr={}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn truncated_mid_header_is_secretstream_truncated() {
    let dir = TempDir::new("ss_attack_trunc_header");
    let f = make_fixture(&dir, "trunc_header", b"whatever");
    let truncated = &f.good[..10];
    let r = try_decrypt(&dir, &f.key, truncated, "trunc_header");
    assert!(r.failure());
    assert!(r.stderr.contains("truncated"), "stderr={}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn truncated_mid_ciphertext_is_secretstream_truncated() {
    let dir = TempDir::new("ss_attack_trunc_chunk");
    let f = make_fixture(
        &dir,
        "trunc_chunk",
        b"a message long enough to have real ciphertext bytes",
    );
    // Keep header + prefix + a few ciphertext bytes, drop the rest (including the whole auth tag).
    let cut = HEADER_LEN + PREFIX_LEN + 3;
    let truncated = &f.good[..cut];
    let r = try_decrypt(&dir, &f.key, truncated, "trunc_chunk");
    assert!(r.failure());
    assert!(
        r.stderr.contains("ends before a Final chunk was ever read")
            || r.stderr.contains("truncated"),
        "stderr={}",
        r.stderr
    );
}

/// The memory-safety property `docs/TASKS.md` T-200 specifically calls out: the oversized-length
/// check (`chunk_len > SECRETSTREAM_CHUNK_BYTES`) happens *before* any allocation or read of that
/// many bytes - an attacker who lies about the chunk length in the 4-byte length field cannot make
/// this command try to allocate/read gigabytes it was never actually given. Real total file size
/// here stays tiny; only the length *field* claims something enormous.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn oversized_chunk_length_field_is_rejected_before_reading_that_much() {
    let dir = TempDir::new("ss_attack_oversized_len");
    let f = make_fixture(&dir, "oversized", b"short");
    let mut tampered = f.good.clone();
    tampered[33..37].copy_from_slice(&u32::MAX.to_le_bytes());
    let r = try_decrypt(&dir, &f.key, &tampered, "oversized");
    assert!(r.failure());
    assert!(
        r.stderr.contains("exceeds this build's maximum chunk size"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unknown_tag_byte_is_secretstream_unknown_tag() {
    let dir = TempDir::new("ss_attack_unknown_tag");
    let f = make_fixture(&dir, "unknown_tag", b"message");
    let mut tampered = f.good.clone();
    tampered[HEADER_LEN] = 0xFF; // not one of Message/Push/Rekey/Final (0x00..0x03)
    let r = try_decrypt(&dir, &f.key, &tampered, "unknown_tag");
    assert!(r.failure());
    assert!(
        r.stderr.contains("unrecognized chunk tag"),
        "stderr={}",
        r.stderr
    );
}

/// The security property this project's own module doc comment claims: flipping the transmitted
/// tag byte to a *different but still-known* value (`Final` 0x03 -> `Message` 0x00) is caught by
/// authentication failure, not silently accepted - `tag_byte` is bound into the chunk's own AEAD
/// associated data, so this is a forgery attempt, not a parse-level error.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn final_tag_flipped_to_message_is_verify_failure_not_silently_accepted() {
    let dir = TempDir::new("ss_attack_flip_final");
    let f = make_fixture(&dir, "flip_final", b"message that should not decrypt");
    let mut tampered = f.good.clone();
    assert_eq!(tampered[HEADER_LEN], 0x03);
    tampered[HEADER_LEN] = 0x00; // Final -> Message, otherwise byte-identical
    let r = try_decrypt(&dir, &f.key, &tampered, "flip_final");
    assert!(
        r.failure(),
        "tag flip was NOT caught - this is a real security gap, not a test bug"
    );
    assert!(
        r.stderr.contains("authentication failed"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn tampered_ciphertext_byte_is_verify_failure() {
    let dir = TempDir::new("ss_attack_tamper_ct");
    let f = make_fixture(&dir, "tamper_ct", b"tamper one ciphertext byte");
    let mut tampered = f.good.clone();
    let ct_start = HEADER_LEN + PREFIX_LEN;
    tampered[ct_start] ^= 0x01;
    let r = try_decrypt(&dir, &f.key, &tampered, "tamper_ct");
    assert!(r.failure());
    assert!(
        r.stderr.contains("authentication failed"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn tampered_auth_tag_byte_is_verify_failure() {
    let dir = TempDir::new("ss_attack_tamper_tag");
    let f = make_fixture(&dir, "tamper_tag", b"tamper the trailing auth tag");
    let mut tampered = f.good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let r = try_decrypt(&dir, &f.key, &tampered, "tamper_tag");
    assert!(r.failure());
    assert!(
        r.stderr.contains("authentication failed"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn tampered_header_byte_is_verify_failure() {
    let dir = TempDir::new("ss_attack_tamper_header");
    let f = make_fixture(&dir, "tamper_header", b"tamper the header");
    let mut tampered = f.good.clone();
    tampered[0] ^= 0x01;
    let r = try_decrypt(&dir, &f.key, &tampered, "tamper_header");
    assert!(r.failure());
    assert!(
        r.stderr.contains("authentication failed"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn trailing_data_after_final_is_rejected() {
    let dir = TempDir::new("ss_attack_trailing");
    let f = make_fixture(&dir, "trailing", b"complete valid message");
    let mut tampered = f.good.clone();
    tampered.push(0x42); // one extra byte after an otherwise-complete, valid stream
    let r = try_decrypt(&dir, &f.key, &tampered, "trailing");
    assert!(r.failure());
    assert!(r.stderr.contains("extra data found"), "stderr={}", r.stderr);
    let _ = f.plaintext_len; // silence unused-field warning if the length isn't asserted above
}
