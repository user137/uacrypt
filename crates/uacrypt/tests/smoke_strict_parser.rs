//! T-255: strict parsing, `help`, typo suggestions and the exit-code contract, at the process
//! boundary - exit codes only exist there (`main.rs`), so this cannot be an in-process test.
//!
//! Exit status contract: 0 ok, 1 input rejected, 2 usage error, 3 file or key problem.

mod support;
use support::{uacrypt, write_bytes, TempDir};

fn p(path: &std::path::Path) -> &str {
    path.to_str().unwrap()
}

fn assert_code(r: &support::Run, code: i32) {
    assert_eq!(
        r.code,
        Some(code),
        "stdout={} stderr={}",
        r.stdout,
        r.stderr
    );
}

fn keygen(dir: &TempDir, name: &str) -> std::path::PathBuf {
    let key = dir.file(name);
    assert_code(&uacrypt(["keygen", "--out", p(&key)]), 0);
    key
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn flag_equals_value_form_round_trips() {
    let dir = TempDir::new("strict_equals_form");
    let key = keygen(&dir, "key.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&pt, b"hello");

    let key_arg = format!("--key={}", p(&key));
    let r = uacrypt([
        "encrypt",
        key_arg.as_str(),
        &format!("--in={}", p(&pt)),
        &format!("--out={}", p(&ct)),
    ]);
    assert_code(&r, 0);
    let r = uacrypt(["decrypt", key_arg.as_str(), "--in", p(&ct), "--out", p(&rt)]);
    assert_code(&r, 0);
    assert_eq!(std::fs::read(&rt).unwrap(), b"hello");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn repeated_flag_is_a_usage_error_and_writes_nothing() {
    let dir = TempDir::new("strict_repeated");
    let a = keygen(&dir, "a.bin");
    let b = keygen(&dir, "b.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    write_bytes(&pt, b"hello");

    let r = uacrypt([
        "encrypt",
        "--key",
        p(&a),
        "--key",
        p(&b),
        "--in",
        p(&pt),
        "--out",
        p(&ct),
    ]);
    assert_code(&r, 2);
    assert!(
        r.stderr.contains("--key given more than once"),
        "{}",
        r.stderr
    );
    assert!(!ct.exists());

    let mixed = format!("--key={}", p(&a));
    let r = uacrypt([
        "encrypt",
        mixed.as_str(),
        "--key",
        p(&b),
        "--in",
        p(&pt),
        "--out",
        p(&ct),
    ]);
    assert_code(&r, 2);
    assert!(!ct.exists());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn repeated_bool_flag_is_a_usage_error() {
    let r = uacrypt([
        "kalyna-block",
        "encrypt",
        "--raw-schedule",
        "--raw-schedule",
    ]);
    assert_code(&r, 2);
    assert!(
        r.stderr.contains("--raw-schedule given more than once"),
        "{}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn flag_followed_by_another_flag_is_a_missing_value() {
    let r = uacrypt(["encrypt", "--key", "--in", "x", "--out", "y"]);
    assert_code(&r, 2);
    assert!(r.stderr.contains("--key needs a value"), "{}", r.stderr);

    let r = uacrypt(["encrypt", "--key=", "--in", "x", "--out", "y"]);
    assert_code(&r, 2);
    assert!(r.stderr.contains("--key needs a value"), "{}", r.stderr);

    let r = uacrypt(["encrypt", "--in", "x", "--out", "y", "--key"]);
    assert_code(&r, 2);
    assert!(r.stderr.contains("--key needs a value"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn bool_flag_with_a_value_is_a_usage_error() {
    let r = uacrypt(["kalyna-block", "encrypt", "--raw-schedule=1"]);
    assert_code(&r, 2);
    assert!(
        r.stderr.contains("--raw-schedule takes no value"),
        "{}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn positional_argument_is_a_usage_error_naming_the_flag_form() {
    let r = uacrypt(["encrypt", "msg.txt"]);
    assert_code(&r, 2);
    assert!(
        r.stderr.contains("unexpected argument: msg.txt"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("--in"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unknown_flag_suggests_the_closest_one() {
    let r = uacrypt(["encrypt", "--inn", "x"]);
    assert_code(&r, 2);
    assert!(r.stderr.contains("unknown flag: --inn"), "{}", r.stderr);
    assert!(r.stderr.contains("did you mean `--in`?"), "{}", r.stderr);

    let r = uacrypt(["encrypt", "--kye=x"]);
    assert_code(&r, 2);
    assert!(r.stderr.contains("did you mean `--key`?"), "{}", r.stderr);

    let r = uacrypt(["encrypt", "--zzzzzz", "x"]);
    assert_code(&r, 2);
    assert!(!r.stderr.contains("did you mean"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unknown_command_suggests_the_closest_one() {
    let r = uacrypt(["encrpyt"]);
    assert_code(&r, 2);
    assert!(
        r.stderr.contains("unknown command: encrpyt"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("did you mean `encrypt`?"), "{}", r.stderr);

    let r = uacrypt(["sign-kegyen"]);
    assert!(
        r.stderr.contains("did you mean `sign-keygen`?"),
        "{}",
        r.stderr
    );

    let r = uacrypt(["foo"]);
    assert_code(&r, 2);
    assert!(!r.stderr.contains("did you mean"), "{}", r.stderr);
    assert!(r.stderr.contains("uacrypt help"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unknown_subcommand_suggests_the_closest_one() {
    let r = uacrypt(["kalyna-gcm", "encrpyt"]);
    assert_code(&r, 2);
    assert!(r.stderr.contains("did you mean `encrypt`?"), "{}", r.stderr);

    let r = uacrypt(["kalyna-cmac", "verfy"]);
    assert!(r.stderr.contains("did you mean `verify`?"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn missing_subcommand_names_the_choices_not_a_flag() {
    let r = uacrypt(["kalyna-kw"]);
    assert_code(&r, 2);
    assert!(r.stderr.contains("wrap|unwrap"), "{}", r.stderr);
    assert!(!r.stderr.contains("--wrap"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn help_command_prints_top_level_and_per_command_help() {
    let r = uacrypt(["help"]);
    assert_code(&r, 0);
    assert!(r.stdout.contains("USAGE:"), "{}", r.stdout);
    assert!(r.stdout.contains("EXIT STATUS:"), "{}", r.stdout);

    let r = uacrypt(["help", "encrypt"]);
    assert_code(&r, 0);
    assert!(r.stdout.starts_with("uacrypt encrypt"), "{}", r.stdout);
    assert_eq!(r.stdout, uacrypt(["encrypt", "--help"]).stdout);

    let r = uacrypt(["help", "help"]);
    assert_code(&r, 0);
    assert!(r.stdout.contains("EXIT STATUS:"), "{}", r.stdout);

    let r = uacrypt(["help", "kalyna-gcm"]);
    assert_code(&r, 0);
    assert!(r.stdout.starts_with("uacrypt kalyna-gcm"), "{}", r.stdout);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn help_for_an_unknown_command_is_a_usage_error() {
    let r = uacrypt(["help", "encrpyt"]);
    assert_code(&r, 2);
    assert!(r.stderr.contains("did you mean `encrypt`?"), "{}", r.stderr);
    assert_eq!(r.stdout, "");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn tampered_ciphertext_exits_1() {
    let dir = TempDir::new("strict_exit_tampered");
    let key = keygen(&dir, "key.bin");
    let pt = dir.file("pt.bin");
    let ct = dir.file("ct.bin");
    let rt = dir.file("rt.bin");
    write_bytes(&pt, b"hello");
    assert_code(
        &uacrypt(["encrypt", "--key", p(&key), "--in", p(&pt), "--out", p(&ct)]),
        0,
    );
    let mut bytes = std::fs::read(&ct).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    write_bytes(&ct, &bytes);
    let r = uacrypt(["decrypt", "--key", p(&key), "--in", p(&ct), "--out", p(&rt)]);
    assert_code(&r, 1);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn verify_success_reports_the_curve_on_stderr_and_bad_signature_exits_1() {
    for (keygen_cmd, pubkey_cmd, sign_cmd, curve) in [
        ("sign-keygen", "sign-pubkey", "sign", "m=163"),
        ("sign-keygen257", "sign-pubkey257", "sign257", "m=257"),
    ] {
        let dir = TempDir::new(&format!("strict_verify_{curve}"));
        let sk = dir.file("sk.bin");
        let pk = dir.file("pk.bin");
        let msg = dir.file("msg.bin");
        let sig = dir.file("sig.bin");
        write_bytes(&msg, b"message");
        assert_code(&uacrypt([keygen_cmd, "--out", p(&sk)]), 0);
        assert_code(&uacrypt([pubkey_cmd, "--key", p(&sk), "--out", p(&pk)]), 0);
        assert_code(
            &uacrypt([sign_cmd, "--key", p(&sk), "--in", p(&msg), "--out", p(&sig)]),
            0,
        );

        let r = uacrypt(["verify", "--key", p(&pk), "--in", p(&msg), "--sig", p(&sig)]);
        assert_code(&r, 0);
        assert_eq!(r.stdout, "");
        assert_eq!(
            r.stderr.trim_end(),
            format!("Signature OK (DSTU 4145, {curve})")
        );

        write_bytes(&msg, b"other message");
        let r = uacrypt(["verify", "--key", p(&pk), "--in", p(&msg), "--sig", p(&sig)]);
        assert_code(&r, 1);
        assert!(!r.stderr.contains("Signature OK"), "{}", r.stderr);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn file_and_key_problems_exit_3() {
    let dir = TempDir::new("strict_exit_3");
    let key = keygen(&dir, "key.bin");
    let missing = dir.file("missing.bin");
    let out = dir.file("out.bin");

    let r = uacrypt([
        "encrypt",
        "--key",
        p(&key),
        "--in",
        p(&missing),
        "--out",
        p(&out),
    ]);
    assert_code(&r, 3);

    let short_key = dir.file("short.bin");
    write_bytes(&short_key, &[0u8; 5]);
    let pt = dir.file("pt.bin");
    write_bytes(&pt, b"x");
    let r = uacrypt([
        "encrypt",
        "--key",
        p(&short_key),
        "--in",
        p(&pt),
        "--out",
        p(&out),
    ]);
    assert_code(&r, 3);

    let r = uacrypt(["keygen", "--out", p(&key)]);
    assert_code(&r, 3);
    assert!(!r.stderr.contains("  "), "double space in: {}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn wrong_length_tag_is_a_rejection_not_a_file_problem() {
    let dir = TempDir::new("strict_tag_len");
    let key = dir.file("key.bin");
    let msg = dir.file("msg.bin");
    let tag = dir.file("tag.bin");
    write_bytes(&key, &[0x11; 16]);
    write_bytes(&msg, b"message");
    write_bytes(&tag, &[0u8; 3]);
    let r = uacrypt([
        "kalyna-cmac",
        "verify",
        "--variant",
        "128-128",
        "--key",
        p(&key),
        "--in",
        p(&msg),
        "--tag",
        p(&tag),
    ]);
    assert_code(&r, 1);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unwritable_output_exits_3_and_leaves_nothing() {
    let dir = TempDir::new("strict_exit_3_write");
    let key = keygen(&dir, "key.bin");
    let pt = dir.file("pt.bin");
    write_bytes(&pt, b"hello");
    let out = dir.file("no-such-dir").join("ct.bin");
    let r = uacrypt([
        "encrypt",
        "--key",
        p(&key),
        "--in",
        p(&pt),
        "--out",
        p(&out),
    ]);
    assert_code(&r, 3);
    assert!(!out.exists());
    assert!(!dir.file("no-such-dir").exists());
}
