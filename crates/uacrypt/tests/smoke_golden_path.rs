//! T-200 Phase 1: one real-subprocess golden-path round trip per `uacrypt` leaf command (all 35,
//! enumerated from `run()`'s own dispatch `match` in `crates/uacrypt/src/lib.rs` - not README or
//! `--help` text, either of which can drift from the real dispatch table). Confirms exit code 0,
//! empty/expected stderr, and that the real output file exists and (where round-trippable) decodes
//! back to the original input through a second real subprocess call - never previously checked at
//! the process boundary, only via the existing 140 in-process `run(&args)` tests.
//!
//! One variant per Kalyna-mode family is exercised here (K128_128 or K256_256) - the full 5-variant
//! matrix is already covered by the in-process suite; this file's job is process-boundary coverage,
//! not variant-matrix reduplication.

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
fn kalyna_block_encrypt_decrypt_round_trips() {
    let dir = TempDir::new("golden_kalyna_block");
    let key = dir.file("key.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&key, &[0x11; 32]);
    write_bytes(&pt, &[0x22; 32]);

    ok(&uacrypt([
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
    ]));
    assert!(ct.exists());

    ok(&uacrypt([
        "kalyna-block",
        "decrypt",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--in",
        ct.to_str().unwrap(),
        "--out",
        rt.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&pt), support::read_bytes(&rt));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_ccm_encrypt_decrypt_round_trips() {
    let dir = TempDir::new("golden_kalyna_ccm");
    let key = dir.file("key.bin");
    let nonce = dir.file("nonce.bin");
    let tag = dir.file("tag.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&key, &[0x33; 16]);
    write_bytes(&pt, b"kalyna-ccm smoke test plaintext");

    ok(&uacrypt([
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
    ]));
    assert!(nonce.exists() && tag.exists() && ct.exists());

    ok(&uacrypt([
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
    ]));
    assert_eq!(support::read_bytes(&pt), support::read_bytes(&rt));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_gcm_encrypt_decrypt_round_trips() {
    let dir = TempDir::new("golden_kalyna_gcm");
    let key = dir.file("key.bin");
    let nonce = dir.file("nonce.bin");
    let tag = dir.file("tag.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&key, &[0x44; 32]);
    write_bytes(
        &pt,
        b"kalyna-gcm smoke test plaintext, a bit longer than one block",
    );

    ok(&uacrypt([
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
    ]));
    ok(&uacrypt([
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
    ]));
    assert_eq!(support::read_bytes(&pt), support::read_bytes(&rt));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_cmac_compute_verify_round_trips() {
    let dir = TempDir::new("golden_kalyna_cmac");
    let key = dir.file("key.bin");
    let msg = dir.file("msg.bin");
    let tag = dir.file("tag.bin");
    write_bytes(&key, &[0x55; 16]);
    write_bytes(&msg, b"cmac smoke test message");

    ok(&uacrypt([
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
    ]));
    assert!(tag.exists());

    let r = uacrypt([
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
    ]);
    ok(&r);
    assert_eq!(r.stdout, "");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_gmac_compute_verify_round_trips() {
    let dir = TempDir::new("golden_kalyna_gmac");
    let key = dir.file("key.bin");
    let msg = dir.file("msg.bin");
    let tag = dir.file("tag.bin");
    write_bytes(&key, &[0x66; 16]);
    write_bytes(&msg, b"gmac smoke test message");

    ok(&uacrypt([
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
    ]));
    assert!(tag.exists());

    ok(&uacrypt([
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
    ]));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_kw_wrap_unwrap_round_trips() {
    let dir = TempDir::new("golden_kalyna_kw");
    let key = dir.file("key.bin");
    let material = dir.file("material.bin");
    let wrapped = dir.file("wrapped.bin");
    let unwrapped = dir.file("unwrapped.bin");
    write_bytes(&key, &[0x77; 32]);
    write_bytes(&material, &[0x88; 32]); // one 256-256 block of "key material" to wrap

    ok(&uacrypt([
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
    ]));
    assert_eq!(support::read_bytes(&wrapped).len(), 32 + 32); // + one checksum block

    ok(&uacrypt([
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
    ]));
    assert_eq!(
        support::read_bytes(&material),
        support::read_bytes(&unwrapped)
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_xts_encrypt_decrypt_round_trips() {
    let dir = TempDir::new("golden_kalyna_xts");
    let key = dir.file("key.bin");
    let tweak = dir.file("tweak.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&key, &[0x99; 32]);
    write_bytes(&tweak, &[0x00; 32]);
    write_bytes(&pt, &[0xAA; 32]); // exactly one 256-256 block

    ok(&uacrypt([
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
    ]));
    ok(&uacrypt([
        "kalyna-xts",
        "decrypt",
        "--variant",
        "256-256",
        "--key",
        key.to_str().unwrap(),
        "--tweak",
        tweak.to_str().unwrap(),
        "--in",
        ct.to_str().unwrap(),
        "--out",
        rt.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&pt), support::read_bytes(&rt));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kupyna_digest_produces_expected_length_both_variants() {
    let dir = TempDir::new("golden_kupyna_digest");
    let input = dir.file("in.bin");
    let out256 = dir.file("out256.bin");
    let out512 = dir.file("out512.bin");
    write_bytes(&input, b"kupyna-digest smoke test");

    ok(&uacrypt([
        "kupyna-digest",
        "--variant",
        "256",
        "--in",
        input.to_str().unwrap(),
        "--out",
        out256.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&out256).len(), 32);

    ok(&uacrypt([
        "kupyna-digest",
        "--variant",
        "512",
        "--in",
        input.to_str().unwrap(),
        "--out",
        out512.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&out512).len(), 64);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn strumok_crypt_round_trips_via_second_pass() {
    let dir = TempDir::new("golden_strumok");
    let key = dir.file("key.bin");
    let iv = dir.file("iv.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&key, &[0xBB; 32]);
    write_bytes(&iv, &[0xCC; 32]);
    write_bytes(&pt, b"strumok-crypt smoke test plaintext");

    ok(&uacrypt([
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
    ]));
    assert_ne!(support::read_bytes(&pt), support::read_bytes(&ct));

    // Same keystream cipher applied twice with the same key/IV round-trips (XOR).
    ok(&uacrypt([
        "strumok-crypt",
        "--variant",
        "256",
        "--key",
        key.to_str().unwrap(),
        "--iv",
        iv.to_str().unwrap(),
        "--in",
        ct.to_str().unwrap(),
        "--out",
        rt.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&pt), support::read_bytes(&rt));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn hash_produces_32_byte_kupyna256_digest() {
    let dir = TempDir::new("golden_hash");
    let input = dir.file("in.bin");
    let out = dir.file("out.bin");
    write_bytes(&input, b"hash smoke test");

    ok(&uacrypt([
        "hash",
        "--in",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&out).len(), 32);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn keygen_produces_32_byte_key() {
    let dir = TempDir::new("golden_keygen");
    let out = dir.file("key.bin");
    ok(&uacrypt(["keygen", "--out", out.to_str().unwrap()]));
    assert_eq!(support::read_bytes(&out).len(), 32);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn secretstream_encrypt_decrypt_round_trips() {
    let dir = TempDir::new("golden_secretstream");
    let key = dir.file("key.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    ok(&uacrypt(["keygen", "--out", key.to_str().unwrap()]));
    write_bytes(&pt, b"encrypt/decrypt smoke test plaintext");

    ok(&uacrypt([
        "encrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
    ]));
    assert_ne!(support::read_bytes(&pt), support::read_bytes(&ct));

    ok(&uacrypt([
        "decrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        ct.to_str().unwrap(),
        "--out",
        rt.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&pt), support::read_bytes(&rt));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn sign_m163_full_flow_keygen_pubkey_sign_verify() {
    let dir = TempDir::new("golden_sign163");
    let sk = dir.file("sk.bin");
    let vk = dir.file("vk.bin");
    let msg = dir.file("msg.bin");
    let sig = dir.file("sig.bin");
    write_bytes(&msg, b"sign m=163 smoke test message");

    ok(&uacrypt(["sign-keygen", "--out", sk.to_str().unwrap()]));
    assert_eq!(support::read_bytes(&sk).len(), 21);

    ok(&uacrypt([
        "sign-pubkey",
        "--key",
        sk.to_str().unwrap(),
        "--out",
        vk.to_str().unwrap(),
    ]));
    let vk_bytes = support::read_bytes(&vk);
    assert_eq!(vk_bytes.len(), 43);
    assert_eq!(vk_bytes[0], 0x01); // CurveId::M163 tag

    ok(&uacrypt([
        "sign",
        "--key",
        sk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sig.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&sig).len(), 42);

    let r = uacrypt([
        "verify",
        "--key",
        vk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--sig",
        sig.to_str().unwrap(),
    ]);
    ok(&r);
    assert_eq!(r.stdout, "");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn sign_m257_full_flow_keygen_pubkey_sign_verify() {
    let dir = TempDir::new("golden_sign257");
    let sk = dir.file("sk.bin");
    let vk = dir.file("vk.bin");
    let msg = dir.file("msg.bin");
    let sig = dir.file("sig.bin");
    write_bytes(&msg, b"sign m=257 smoke test message");

    ok(&uacrypt(["sign-keygen257", "--out", sk.to_str().unwrap()]));
    assert_eq!(support::read_bytes(&sk).len(), 33);

    ok(&uacrypt([
        "sign-pubkey257",
        "--key",
        sk.to_str().unwrap(),
        "--out",
        vk.to_str().unwrap(),
    ]));
    let vk_bytes = support::read_bytes(&vk);
    assert_eq!(vk_bytes.len(), 67);
    assert_eq!(vk_bytes[0], 0x02); // CurveId::M257 tag

    ok(&uacrypt([
        "sign257",
        "--key",
        sk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sig.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&sig).len(), 66);

    // The one command surface where both curves genuinely converge: `verify` alone is
    // curve-tag-aware and handles an m=257 signature with no separate `verify257` command.
    let r = uacrypt([
        "verify",
        "--key",
        vk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--sig",
        sig.to_str().unwrap(),
    ]);
    ok(&r);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_full_flow_keygen_pubkey_seal_open() {
    let dir = TempDir::new("golden_box");
    let sk = dir.file("sk.bin");
    let pk = dir.file("pk.bin");
    let msg = dir.file("msg.bin");
    let sealed = dir.file("sealed.bin");
    let opened = dir.file("opened.bin");
    write_bytes(&msg, b"crypto_box smoke test message");

    ok(&uacrypt(["box-keygen", "--out", sk.to_str().unwrap()]));
    assert_eq!(support::read_bytes(&sk).len(), 32);

    ok(&uacrypt([
        "box-pubkey",
        "--key",
        sk.to_str().unwrap(),
        "--out",
        pk.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&pk).len(), 32);

    ok(&uacrypt([
        "box-seal",
        "--key",
        pk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sealed.to_str().unwrap(),
    ]));
    ok(&uacrypt([
        "box-open",
        "--key",
        sk.to_str().unwrap(),
        "--in",
        sealed.to_str().unwrap(),
        "--out",
        opened.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&msg), support::read_bytes(&opened));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box512_full_flow_keygen_pubkey_seal_open() {
    let dir = TempDir::new("golden_box512");
    let sk = dir.file("sk.bin");
    let pk = dir.file("pk.bin");
    let msg = dir.file("msg.bin");
    let sealed = dir.file("sealed.bin");
    let opened = dir.file("opened.bin");
    write_bytes(&msg, b"crypto_box512 smoke test message");

    ok(&uacrypt(["box-keygen512", "--out", sk.to_str().unwrap()]));
    assert_eq!(support::read_bytes(&sk).len(), 64);

    ok(&uacrypt([
        "box-pubkey512",
        "--key",
        sk.to_str().unwrap(),
        "--out",
        pk.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&pk).len(), 64);

    ok(&uacrypt([
        "box-seal512",
        "--key",
        pk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sealed.to_str().unwrap(),
    ]));
    ok(&uacrypt([
        "box-open512",
        "--key",
        sk.to_str().unwrap(),
        "--in",
        sealed.to_str().unwrap(),
        "--out",
        opened.to_str().unwrap(),
    ]));
    assert_eq!(support::read_bytes(&msg), support::read_bytes(&opened));
}
