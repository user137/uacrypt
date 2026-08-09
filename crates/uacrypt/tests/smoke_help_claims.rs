//! T-200 Phase 4: `--help` text as a pinned claim, not prose - per this task's own note in
//! `docs/TASKS.md`, "the highest-value net-new angle, nothing today covers it." Each command's
//! `--help` (`crates/uacrypt/src/lib.rs`'s `*_HELP` constants) makes testable behavioral assertions
//! ("NOT authenticated", "prints nothing and exits 0", "a failure never leaves partial output",
//! "capped at 255 bytes", "must be at least one block long") that can rot silently if the
//! implementation ever drifts from what the help text still claims. This file picks the claims that
//! are genuinely behavioral (not policy/advice, which nothing enforces) and checks the real binary
//! against its own documented promise - not just that the promise's *words* still appear somewhere.

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

/// `STRUMOK_CRYPT_HELP`: "NOT authenticated. A tampered output file decrypts silently into wrong
/// plaintext instead of an error - there is no tag to detect it."
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn strumok_crypt_help_claims_tampering_is_undetected_not_an_error() {
    let dir = TempDir::new("help_strumok_not_authenticated");
    let key = dir.file("key.bin");
    let iv = dir.file("iv.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let recovered = dir.file("recovered.bin");
    write_bytes(&key, &[0x11; 32]);
    write_bytes(&iv, &[0x22; 32]);
    let plaintext = b"the help text promises this is NOT authenticated".to_vec();
    write_bytes(&pt, &plaintext);

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

    let mut tampered = support::read_bytes(&ct);
    tampered[0] ^= 0x01; // flip one ciphertext byte - no tag exists to catch this
    write_bytes(&ct, &tampered);

    let r = uacrypt([
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
        recovered.to_str().unwrap(),
    ]);
    assert!(
        r.success(),
        "help text claims tampering is silently undetected, not rejected - got failure instead: {}",
        r.stderr
    );
    let recovered_bytes = support::read_bytes(&recovered);
    assert_ne!(
        recovered_bytes, plaintext,
        "tampering must actually corrupt the recovered plaintext for this claim to mean anything"
    );
}

/// `VERIFY_HELP`: "Prints nothing and exits 0 on a valid signature."
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn verify_help_claims_valid_signature_prints_nothing_and_exits_zero() {
    let dir = TempDir::new("help_verify_silent_success");
    let signing_key = dir.file("signing.key");
    let verifying_key = dir.file("verifying.key");
    let msg = dir.file("msg.bin");
    let sig = dir.file("msg.sig");
    write_bytes(&msg, b"a message worth signing");

    ok(&uacrypt([
        "sign-keygen",
        "--out",
        signing_key.to_str().unwrap(),
    ]));
    ok(&uacrypt([
        "sign-pubkey",
        "--key",
        signing_key.to_str().unwrap(),
        "--out",
        verifying_key.to_str().unwrap(),
    ]));
    ok(&uacrypt([
        "sign",
        "--key",
        signing_key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sig.to_str().unwrap(),
    ]));

    let r = uacrypt([
        "verify",
        "--key",
        verifying_key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--sig",
        sig.to_str().unwrap(),
    ]);
    assert!(r.success(), "stderr={}", r.stderr);
    assert_eq!(r.stdout, "", "help text claims 'prints nothing' on success");
}

/// `DECRYPT_HELP`: "Fails loudly (no --out written) on a wrong key, a wrong/tampered file..."
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn decrypt_help_claims_tampered_input_leaves_no_partial_output() {
    let dir = TempDir::new("help_decrypt_no_partial_output");
    let key = dir.file("key.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let out = dir.file("out.bin");
    ok(&uacrypt(["keygen", "--out", key.to_str().unwrap()]));
    write_bytes(
        &pt,
        b"a message that will be tampered before decrypt is attempted",
    );

    ok(&uacrypt([
        "encrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        pt.to_str().unwrap(),
        "--out",
        ct.to_str().unwrap(),
    ]));
    let mut tampered = support::read_bytes(&ct);
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    write_bytes(&ct, &tampered);

    let r = uacrypt([
        "decrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        ct.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(r.failure());
    assert!(
        !out.exists(),
        "help text claims '--out is only replaced after the whole file is written and verified'"
    );
}

/// `KALYNA_CCM_HELP`: "Messages and AAD are capped at 255 bytes each."
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_ccm_help_claims_255_byte_message_cap() {
    let dir = TempDir::new("help_ccm_255_cap");
    let key = dir.file("key.bin");
    let nonce = dir.file("nonce.bin");
    let tag = dir.file("tag.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    write_bytes(&key, &[0x33; 16]);
    write_bytes(&pt, &vec![b'A'; 256]); // one byte over the claimed cap

    let r = uacrypt([
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
    ]);
    assert!(r.failure());
    assert!(r.stderr.contains("255-byte limit"), "stderr={}", r.stderr);
}

/// `KALYNA_XTS_HELP`: "--in must be at least one block long."
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_xts_help_claims_in_must_be_at_least_one_block() {
    let dir = TempDir::new("help_xts_min_block");
    let key = dir.file("key.bin");
    let tweak = dir.file("tweak.bin");
    let short_in = dir.file("short.bin");
    let out = dir.file("out.bin");
    write_bytes(&key, &[0x44; 16]);
    write_bytes(&tweak, &[0x55; 16]);
    write_bytes(&short_in, &[0x66; 8]); // 128-128's block length is 16

    let r = uacrypt([
        "kalyna-xts",
        "encrypt",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--tweak",
        tweak.to_str().unwrap(),
        "--in",
        short_in.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(r.failure());
    assert!(
        r.stderr.contains("must be at least one block long"),
        "stderr={}",
        r.stderr
    );
    assert!(!out.exists());
}

/// `BOX_OPEN_HELP`: "A wrong key or a tampered/truncated file is rejected with an error before
/// anything is written to --out."
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_open_help_claims_wrong_key_leaves_no_partial_output() {
    let dir = TempDir::new("help_box_open_no_partial");
    let recipient_key = dir.file("recipient.key");
    let recipient_pub = dir.file("recipient.pub");
    let wrong_key = dir.file("wrong.key");
    let msg = dir.file("msg.txt");
    let sealed = dir.file("msg.box");
    let out = dir.file("opened.txt");
    write_bytes(&msg, b"a message sealed to one recipient");

    ok(&uacrypt([
        "box-keygen",
        "--out",
        recipient_key.to_str().unwrap(),
    ]));
    ok(&uacrypt([
        "box-keygen",
        "--out",
        wrong_key.to_str().unwrap(),
    ]));
    ok(&uacrypt([
        "box-pubkey",
        "--key",
        recipient_key.to_str().unwrap(),
        "--out",
        recipient_pub.to_str().unwrap(),
    ]));
    ok(&uacrypt([
        "box-seal",
        "--key",
        recipient_pub.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sealed.to_str().unwrap(),
    ]));

    let r = uacrypt([
        "box-open",
        "--key",
        wrong_key.to_str().unwrap(),
        "--in",
        sealed.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(r.failure());
    assert!(!out.exists());
}
