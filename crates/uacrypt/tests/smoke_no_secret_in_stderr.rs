//! T-214: no key/secret material ever reaches stderr, for every keyed subcommand. Every `--key`
//! flag resolves to a file path (`ArgScanner::path`, never a raw CLI arg - confirmed no
//! `--passphrase`/`--secret` flag exists anywhere in `lib.rs`), so the real risk surface is a
//! future change to `CliError`'s `Display` impl (or a panic) that accidentally formats the key's
//! own bytes into the error message shown on stderr. Each test here writes a distinctive,
//! non-trivial "secret" key, deliberately drives a real error path (wrong length or a tamper that
//! trips authentication), and asserts the raw key bytes and their hex encoding are both absent
//! from stderr - both the raw bytes (checked on the unconverted byte stream, since a lossy UTF-8
//! `String` can silently mangle non-UTF8 bytes into replacement characters and hide a real leak)
//! and the hex encoding (always valid ASCII regardless of key content, so this check is meaningful
//! even for a key that doesn't survive lossy UTF-8 conversion intact).

mod support;
use support::{uacrypt, write_bytes, TempDir};

/// A key value distinctive enough that an accidental leak would be unmistakable, not all-zero or
/// a repeated single byte (which could coincidentally match unrelated output).
const SECRET: [u8; 32] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xCA, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
];

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Spawns the real binary and returns its *raw* (non-lossy) stderr bytes, alongside a [`Run`] via
/// the normal shared helper for exit-code/stdout assertions. Kept local to this file rather than
/// added to `support::mod.rs` - one extra spawn call, not worth growing the shared helper's public
/// surface for a single file's need.
fn raw_stderr<I, S>(args: I) -> Vec<u8>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let exe = env!("CARGO_BIN_EXE_uacrypt");
    std::process::Command::new(exe)
        .args(args)
        .output()
        .expect("spawn the real uacrypt binary")
        .stderr
}

fn assert_no_secret_leak(label: &str, stderr_bytes: &[u8], secret: &[u8]) {
    assert!(
        !stderr_bytes.windows(secret.len()).any(|w| w == secret),
        "{label}: raw secret bytes found in stderr: {:?}",
        String::from_utf8_lossy(stderr_bytes)
    );
    let stderr_text = String::from_utf8_lossy(stderr_bytes);
    let lower = hex_lower(secret);
    let upper = hex_upper(secret);
    assert!(
        !stderr_text.contains(&lower) && !stderr_text.contains(&upper),
        "{label}: hex-encoded secret found in stderr: {stderr_text}"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_block_wrong_key_length_does_not_leak_key() {
    let dir = TempDir::new("nosecret_kalyna_block");
    let key = dir.file("key.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    write_bytes(&key, &SECRET[..17]); // not a valid 128-128/256-256/etc length
    write_bytes(&pt, &[0x22; 32]);

    let args = [
        "kalyna-block",
        "encrypt",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(
        r.failure(),
        "expected a wrong-key-length error, got success"
    );
    assert_no_secret_leak("kalyna-block", &raw_stderr(args), &SECRET[..17]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_ccm_tampered_tag_does_not_leak_key() {
    let dir = TempDir::new("nosecret_kalyna_ccm");
    let key = dir.file("key.bin");
    let nonce = dir.file("nonce.bin");
    let tag = dir.file("tag.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&key, &SECRET[..16]);
    write_bytes(&pt, b"kalyna-ccm no-secret-leak test");

    assert!(uacrypt([
        "kalyna-ccm",
        "encrypt",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--nonce",
        nonce.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
        "--tag",
        tag.to_str().unwrap(),
    ])
    .success());
    // Tamper the tag so decrypt hits CcmVerifyFailed.
    let mut tag_bytes = support::read_bytes(&tag);
    tag_bytes[0] ^= 0xFF;
    write_bytes(&tag, &tag_bytes);

    let args = [
        "kalyna-ccm",
        "decrypt",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--nonce",
        nonce.to_str().unwrap(),
        "--in",
        ct.to_str().unwrap(),
        "--out",
        rt.to_str().unwrap(),
        "--tag",
        tag.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected CcmVerifyFailed, got success");
    assert_no_secret_leak("kalyna-ccm", &raw_stderr(args), &SECRET[..16]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_gcm_tampered_tag_does_not_leak_key() {
    let dir = TempDir::new("nosecret_kalyna_gcm");
    let key = dir.file("key.bin");
    let nonce = dir.file("nonce.bin");
    let tag = dir.file("tag.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&key, &SECRET);
    write_bytes(
        &pt,
        b"kalyna-gcm no-secret-leak test, a little longer than one block",
    );

    assert!(uacrypt([
        "kalyna-gcm",
        "encrypt",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--nonce",
        nonce.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
        "--tag",
        tag.to_str().unwrap(),
    ])
    .success());
    let mut tag_bytes = support::read_bytes(&tag);
    tag_bytes[0] ^= 0xFF;
    write_bytes(&tag, &tag_bytes);

    let args = [
        "kalyna-gcm",
        "decrypt",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--nonce",
        nonce.to_str().unwrap(),
        "--in",
        ct.to_str().unwrap(),
        "--out",
        rt.to_str().unwrap(),
        "--tag",
        tag.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected GcmVerifyFailed, got success");
    assert_no_secret_leak("kalyna-gcm", &raw_stderr(args), &SECRET);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_cmac_tampered_tag_does_not_leak_key() {
    let dir = TempDir::new("nosecret_kalyna_cmac");
    let key = dir.file("key.bin");
    let msg = dir.file("msg.bin");
    let tag = dir.file("tag.bin");
    write_bytes(&key, &SECRET[..16]);
    write_bytes(&msg, b"cmac no-secret-leak test message");

    assert!(uacrypt([
        "kalyna-cmac",
        "compute",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        tag.to_str().unwrap(),
    ])
    .success());
    let mut tag_bytes = support::read_bytes(&tag);
    tag_bytes[0] ^= 0xFF;
    write_bytes(&tag, &tag_bytes);

    let args = [
        "kalyna-cmac",
        "verify",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--tag",
        tag.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected CmacVerifyFailed, got success");
    assert_no_secret_leak("kalyna-cmac", &raw_stderr(args), &SECRET[..16]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_gmac_tampered_tag_does_not_leak_key() {
    let dir = TempDir::new("nosecret_kalyna_gmac");
    let key = dir.file("key.bin");
    let msg = dir.file("msg.bin");
    let tag = dir.file("tag.bin");
    write_bytes(&key, &SECRET[..16]);
    write_bytes(&msg, b"gmac no-secret-leak test message");

    assert!(uacrypt([
        "kalyna-gmac",
        "compute",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        tag.to_str().unwrap(),
    ])
    .success());
    let mut tag_bytes = support::read_bytes(&tag);
    tag_bytes[0] ^= 0xFF;
    write_bytes(&tag, &tag_bytes);

    let args = [
        "kalyna-gmac",
        "verify",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--tag",
        tag.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected GmacVerifyFailed, got success");
    assert_no_secret_leak("kalyna-gmac", &raw_stderr(args), &SECRET[..16]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_kw_corrupted_wrapped_data_does_not_leak_key() {
    let dir = TempDir::new("nosecret_kalyna_kw");
    let key = dir.file("key.bin");
    let material = dir.file("material.bin");
    let wrapped = dir.file("wrapped.bin");
    let unwrapped = dir.file("unwrapped.bin");
    write_bytes(&key, &SECRET);
    write_bytes(&material, &[0x88; 32]);

    assert!(uacrypt([
        "kalyna-kw",
        "wrap",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--in",
        material.to_str().unwrap(),
        "--out",
        wrapped.to_str().unwrap(),
    ])
    .success());
    let mut wrapped_bytes = support::read_bytes(&wrapped);
    let last = wrapped_bytes.len() - 1;
    wrapped_bytes[last] ^= 0xFF;
    write_bytes(&wrapped, &wrapped_bytes);

    let args = [
        "kalyna-kw",
        "unwrap",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--in",
        wrapped.to_str().unwrap(),
        "--out",
        unwrapped.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected KwChecksumMismatch, got success");
    assert_no_secret_leak("kalyna-kw", &raw_stderr(args), &SECRET);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_xts_wrong_key_length_does_not_leak_key() {
    let dir = TempDir::new("nosecret_kalyna_xts");
    let key = dir.file("key.bin");
    let tweak = dir.file("tweak.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    write_bytes(&key, &SECRET[..9]);
    write_bytes(&tweak, &[0x00; 32]);
    write_bytes(&pt, &[0xAA; 32]);

    let args = [
        "kalyna-xts",
        "encrypt",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--tweak",
        tweak.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(
        r.failure(),
        "expected a wrong-key-length error, got success"
    );
    assert_no_secret_leak("kalyna-xts", &raw_stderr(args), &SECRET[..9]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn strumok_crypt_wrong_key_length_does_not_leak_key() {
    let dir = TempDir::new("nosecret_strumok");
    let key = dir.file("key.bin");
    let iv = dir.file("iv.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    write_bytes(&key, &SECRET[..5]);
    write_bytes(&iv, &[0xCC; 32]);
    write_bytes(&pt, b"strumok-crypt no-secret-leak test");

    let args = [
        "strumok-crypt",
        "--variant",
        "256",
        "--key",
        key.to_str().unwrap(),
        "--iv",
        iv.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(
        r.failure(),
        "expected a wrong-key-length error, got success"
    );
    assert_no_secret_leak("strumok-crypt", &raw_stderr(args), &SECRET[..5]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn secretstream_decrypt_tampered_ciphertext_does_not_leak_key() {
    let dir = TempDir::new("nosecret_secretstream");
    let key = dir.file("key.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&key, &SECRET);
    write_bytes(&pt, b"encrypt/decrypt no-secret-leak test plaintext");

    assert!(uacrypt([
        "encrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
    ])
    .success());
    let mut ct_bytes = support::read_bytes(&ct);
    let last = ct_bytes.len() - 1;
    ct_bytes[last] ^= 0xFF;
    write_bytes(&ct, &ct_bytes);

    let args = [
        "decrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        ct.to_str().unwrap(),
        "--out",
        rt.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(
        r.failure(),
        "expected SecretstreamVerifyFailed, got success"
    );
    assert_no_secret_leak("secretstream", &raw_stderr(args), &SECRET);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn sign_wrong_key_length_does_not_leak_key() {
    let dir = TempDir::new("nosecret_sign163");
    let sk = dir.file("sk.bin");
    let msg = dir.file("msg.bin");
    let sig = dir.file("sig.bin");
    write_bytes(&sk, &SECRET[..7]); // not a valid 21-byte m=163 signing key
    write_bytes(&msg, b"sign no-secret-leak test message");

    let args = [
        "sign",
        "--key",
        sk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sig.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected a signing-key error, got success");
    assert_no_secret_leak("sign", &raw_stderr(args), &SECRET[..7]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn sign257_wrong_key_length_does_not_leak_key() {
    let dir = TempDir::new("nosecret_sign257");
    let sk = dir.file("sk.bin");
    let msg = dir.file("msg.bin");
    let sig = dir.file("sig.bin");
    write_bytes(&sk, &SECRET[..11]); // not a valid 33-byte m=257 signing key
    write_bytes(&msg, b"sign257 no-secret-leak test message");

    let args = [
        "sign257",
        "--key",
        sk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sig.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected a signing-key error, got success");
    assert_no_secret_leak("sign257", &raw_stderr(args), &SECRET[..11]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_open_wrong_key_does_not_leak_key() {
    let dir = TempDir::new("nosecret_box");
    let sk_wrong = dir.file("sk_wrong.bin");
    let pk = dir.file("pk.bin");
    let sk_real = dir.file("sk_real.bin");
    let msg = dir.file("msg.bin");
    let sealed = dir.file("sealed.bin");
    let opened = dir.file("opened.bin");
    write_bytes(&msg, b"crypto_box no-secret-leak test message");

    assert!(uacrypt(["box-keygen", "--out", sk_real.to_str().unwrap()]).success());
    assert!(uacrypt([
        "box-pubkey",
        "--key",
        sk_real.to_str().unwrap(),
        "--out",
        pk.to_str().unwrap(),
    ])
    .success());
    assert!(uacrypt([
        "box-seal",
        "--key",
        pk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sealed.to_str().unwrap(),
    ])
    .success());

    // A distinctive, wrong 32-byte secret key - box-open must fail (mismatched keypair) without
    // ever printing this key's bytes.
    write_bytes(&sk_wrong, &SECRET);
    let args = [
        "box-open",
        "--key",
        sk_wrong.to_str().unwrap(),
        "--in",
        sealed.to_str().unwrap(),
        "--out",
        opened.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected BoxOpenFailed, got success");
    assert_no_secret_leak("box-open", &raw_stderr(args), &SECRET);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_open512_wrong_key_does_not_leak_key() {
    let dir = TempDir::new("nosecret_box512");
    let sk_wrong = dir.file("sk_wrong.bin");
    let pk = dir.file("pk.bin");
    let sk_real = dir.file("sk_real.bin");
    let msg = dir.file("msg.bin");
    let sealed = dir.file("sealed.bin");
    let opened = dir.file("opened.bin");
    write_bytes(&msg, b"crypto_box512 no-secret-leak test message");

    assert!(uacrypt(["box-keygen512", "--out", sk_real.to_str().unwrap()]).success());
    assert!(uacrypt([
        "box-pubkey512",
        "--key",
        sk_real.to_str().unwrap(),
        "--out",
        pk.to_str().unwrap(),
    ])
    .success());
    assert!(uacrypt([
        "box-seal512",
        "--key",
        pk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sealed.to_str().unwrap(),
    ])
    .success());

    // 64-byte wrong secret key for box-open512 - reuse SECRET twice for the required length.
    let wrong64: Vec<u8> = SECRET.iter().chain(SECRET.iter()).copied().collect();
    write_bytes(&sk_wrong, &wrong64);
    let args = [
        "box-open512",
        "--key",
        sk_wrong.to_str().unwrap(),
        "--in",
        sealed.to_str().unwrap(),
        "--out",
        opened.to_str().unwrap(),
    ];
    let r = uacrypt(args);
    assert!(r.failure(), "expected Box512OpenFailed, got success");
    assert_no_secret_leak("box-open512", &raw_stderr(args), &wrong64);
}
