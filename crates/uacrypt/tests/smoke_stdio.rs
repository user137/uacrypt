//! stdin/stdout via `-` (T-260, `docs/DECISIONS.md` D-217): `--in -` reads stdin, `--out -`
//! writes stdout. `--key` and every other path flag refuse `-`; secret keys never go to stdout
//! (R7). A decrypt to stdout writes only verified chunks and says the output is INCOMPLETE when
//! the stream fails after the first byte. Refusing binary output to a terminal cannot be reached
//! from a piped test; it is a unit test of `refuse_binary_to_terminal` in `src/lib.rs`.

mod support;
use dstu_core::hazmat::kupyna::Kupyna256;
use support::{read_bytes, write_bytes, TempDir};

/// Plaintext bytes per record; must match `SECRETSTREAM_CHUNK_BYTES` in `src/lib.rs` (D-208).
const CHUNK: usize = 8 * 1024;
/// Version byte plus header.
const PREAMBLE: usize = 1 + 32;
/// Tag byte, length, full chunk, auth tag.
const FULL_RECORD: usize = 1 + 4 + CHUNK + 16;

struct RawRun {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

/// Runs the real binary in `cwd` with `stdin` piped in (from a thread, so a large input cannot
/// deadlock against a full stdout pipe) and stdout captured as raw bytes.
fn run(cwd: &std::path::Path, args: &[&str], stdin: &[u8]) -> RawRun {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_uacrypt"))
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the real uacrypt binary");
    let mut pipe = child.stdin.take().expect("stdin is piped");
    let input = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        // The command may exit before reading everything (a usage error): ignore a broken pipe.
        let _ = pipe.write_all(&input);
    });
    let output = child.wait_with_output().expect("wait for uacrypt");
    writer.join().expect("stdin writer thread");
    RawRun {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn ok(r: &RawRun) {
    assert_eq!(r.code, Some(0), "stderr: {}", r.stderr);
}

fn keygen(dir: &TempDir, command: &str, name: &str) {
    ok(&run(&dir.0, &[command, "--out", name], b""));
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn listing(dir: &TempDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn encrypt_and_decrypt_round_trip_through_stdin_and_stdout() {
    let dir = TempDir::new("stdio_roundtrip");
    keygen(&dir, "keygen", "k.key");
    for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 5] {
        let plain = pattern(len);
        let enc = run(
            &dir.0,
            &["encrypt", "--key", "k.key", "--in", "-", "--out", "-"],
            &plain,
        );
        ok(&enc);
        assert_eq!(enc.stderr, "");
        let dec = run(
            &dir.0,
            &["decrypt", "--key", "k.key", "--in", "-", "--out", "-"],
            &enc.stdout,
        );
        ok(&dec);
        assert_eq!(dec.stdout, plain, "len {len}");

        // Same wire format as a file: stdin -> file, file -> stdout.
        write_bytes(&dir.file("p"), &plain);
        let to_file = run(
            &dir.0,
            &[
                "encrypt", "--key", "k.key", "--in", "-", "--out", "c", "--force",
            ],
            &plain,
        );
        ok(&to_file);
        assert!(to_file.stdout.is_empty());
        let from_file = run(
            &dir.0,
            &["decrypt", "--key", "k.key", "--in", "c", "--out", "-"],
            b"",
        );
        ok(&from_file);
        assert_eq!(from_file.stdout, plain, "len {len}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn sign_hash_and_verify_read_stdin_like_a_file() {
    let dir = TempDir::new("stdio_sign");
    let message = pattern(3 * CHUNK + 11);
    write_bytes(&dir.file("m"), &message);
    for keygen_cmd in ["sign-keygen", "sign-keygen257"] {
        let _ = std::fs::remove_file(dir.file("s.key"));
        let _ = std::fs::remove_file(dir.file("v.key"));
        keygen(&dir, keygen_cmd, "s.key");
        ok(&run(
            &dir.0,
            &["sign-pubkey", "--key", "s.key", "--out", "v.key"],
            b"",
        ));

        let from_file = run(
            &dir.0,
            &["sign", "--key", "s.key", "--in", "m", "--out", "-"],
            b"",
        );
        ok(&from_file);
        let from_stdin = run(
            &dir.0,
            &["sign", "--key", "s.key", "--in", "-", "--out", "-"],
            &message,
        );
        ok(&from_stdin);
        assert!(!from_file.stdout.is_empty());
        // The nonce is deterministic (D-46): same message, same signature.
        assert_eq!(from_stdin.stdout, from_file.stdout, "{keygen_cmd}");

        write_bytes(&dir.file("sig"), &from_stdin.stdout);
        let v = run(
            &dir.0,
            &["verify", "--key", "v.key", "--in", "-", "--sig", "sig"],
            &message,
        );
        ok(&v);
        assert!(v.stderr.starts_with("Signature OK"), "{}", v.stderr);
        let mut other = message.clone();
        other[0] ^= 1;
        let bad = run(
            &dir.0,
            &["verify", "--key", "v.key", "--in", "-", "--sig", "sig"],
            &other,
        );
        assert_eq!(bad.code, Some(1), "{}", bad.stderr);
    }

    let h = run(&dir.0, &["hash", "--in", "-"], &message);
    ok(&h);
    assert_eq!(
        String::from_utf8(h.stdout).unwrap(),
        format!("{}  -\n", hex(&Kupyna256::digest(&message)))
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_seal_and_open_and_public_keys_use_stdio() {
    let dir = TempDir::new("stdio_box");
    for (keygen_cmd, prefix) in [
        ("box-keygen", "uacrypt-box256-public:"),
        ("box-keygen512", "uacrypt-box512-public:"),
    ] {
        for name in ["b.key", "b.pub"] {
            let _ = std::fs::remove_file(dir.file(name));
        }
        keygen(&dir, keygen_cmd, "b.key");
        ok(&run(
            &dir.0,
            &["box-pubkey", "--key", "b.key", "--out", "b.pub"],
            b"",
        ));
        let to_stdout = run(&dir.0, &["box-pubkey", "--key", "b.key", "--out", "-"], b"");
        ok(&to_stdout);
        assert_eq!(to_stdout.stdout, read_bytes(&dir.file("b.pub")));
        assert!(to_stdout.stdout.starts_with(prefix.as_bytes()));

        let message = pattern(1000);
        let sealed = run(
            &dir.0,
            &["box-seal", "--key", "b.pub", "--in", "-", "--out", "-"],
            &message,
        );
        ok(&sealed);
        let opened = run(
            &dir.0,
            &["box-open", "--key", "b.key", "--in", "-", "--out", "-"],
            &sealed.stdout,
        );
        ok(&opened);
        assert_eq!(opened.stdout, message);
    }

    keygen(&dir, "sign-keygen", "s.key");
    ok(&run(
        &dir.0,
        &["sign-pubkey", "--key", "s.key", "--out", "v.key"],
        b"",
    ));
    let v = run(
        &dir.0,
        &["sign-pubkey", "--key", "s.key", "--out", "-"],
        b"",
    );
    ok(&v);
    assert_eq!(v.stdout, read_bytes(&dir.file("v.key")));

    // key-import of a public kind may print the line; its note goes to stderr.
    let raw = [&[0x01u8][..], &read_raw_public(&dir.file("v.key"))].concat();
    write_bytes(&dir.file("raw.pub"), &raw);
    let imported = run(
        &dir.0,
        &[
            "key-import",
            "--kind",
            "sign163-public",
            "--in",
            "raw.pub",
            "--out",
            "-",
        ],
        b"",
    );
    ok(&imported);
    assert_eq!(imported.stdout, read_bytes(&dir.file("v.key")));
    assert!(imported.stderr.contains("stdout"), "{}", imported.stderr);
}

/// The key bytes of a typed public key line.
fn read_raw_public(path: &std::path::Path) -> Vec<u8> {
    let text = String::from_utf8(read_bytes(path)).unwrap();
    let hex = text.split(':').nth(1).unwrap();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_failing_decrypt_to_stdout_prints_only_verified_chunks_and_says_incomplete() {
    let dir = TempDir::new("stdio_incomplete");
    keygen(&dir, "keygen", "k.key");
    keygen(&dir, "keygen", "other.key");
    let plain = pattern(3 * CHUNK + 5);
    let enc = run(
        &dir.0,
        &["encrypt", "--key", "k.key", "--in", "-", "--out", "-"],
        &plain,
    );
    ok(&enc);
    let ct = enc.stdout;
    assert_eq!(ct.len(), PREAMBLE + 3 * FULL_RECORD + 1 + 4 + 5 + 16);
    let decrypt = |input: &[u8], key: &str| {
        run(
            &dir.0,
            &["decrypt", "--key", key, "--in", "-", "--out", "-"],
            input,
        )
    };

    // Final record missing: the three full chunks were verified and printed.
    let truncated = decrypt(&ct[..PREAMBLE + 3 * FULL_RECORD], "k.key");
    assert_eq!(truncated.code, Some(1), "{}", truncated.stderr);
    assert_eq!(truncated.stdout, &plain[..3 * CHUNK]);
    assert!(
        truncated.stderr.contains("INCOMPLETE"),
        "{}",
        truncated.stderr
    );

    // Second chunk tampered: only the first one is printed.
    let mut tampered = ct.clone();
    tampered[PREAMBLE + FULL_RECORD + 5 + 100] ^= 1;
    let r = decrypt(&tampered, "k.key");
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert_eq!(r.stdout, &plain[..CHUNK]);
    assert!(r.stderr.contains("INCOMPLETE"), "{}", r.stderr);

    // Trailing bytes after Final: everything was printed, and it still says discard it.
    let mut trailing = ct.clone();
    trailing.push(0);
    let r = decrypt(&trailing, "k.key");
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert_eq!(r.stdout, plain);
    assert!(r.stderr.contains("INCOMPLETE"), "{}", r.stderr);

    // Nothing verifies under the wrong key: empty stdout and no INCOMPLETE.
    let r = decrypt(&ct, "other.key");
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stdout.is_empty());
    assert!(!r.stderr.contains("INCOMPLETE"), "{}", r.stderr);

    // A header-only input: nothing printed either.
    let r = decrypt(&ct[..PREAMBLE], "k.key");
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stdout.is_empty());
    assert!(!r.stderr.contains("INCOMPLETE"), "{}", r.stderr);

    // box-open decrypts whole before printing: a tampered file prints nothing.
    keygen(&dir, "box-keygen", "b.key");
    ok(&run(
        &dir.0,
        &["box-pubkey", "--key", "b.key", "--out", "b.pub"],
        b"",
    ));
    let sealed = run(
        &dir.0,
        &["box-seal", "--key", "b.pub", "--in", "-", "--out", "-"],
        &plain,
    );
    ok(&sealed);
    let mut bad = sealed.stdout.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let r = run(
        &dir.0,
        &["box-open", "--key", "b.key", "--in", "-", "--out", "-"],
        &bad,
    );
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stdout.is_empty());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn dash_is_refused_everywhere_it_is_not_stdio() {
    let dir = TempDir::new("stdio_refused");
    keygen(&dir, "keygen", "k.key");
    keygen(&dir, "sign-keygen", "s.key");
    ok(&run(
        &dir.0,
        &["sign-pubkey", "--key", "s.key", "--out", "v.key"],
        b"",
    ));
    write_bytes(&dir.file("m"), b"message");
    write_bytes(&dir.file("sig"), &[0u8; 42]);
    write_bytes(&dir.file("raw32"), &[7u8; 32]);
    write_bytes(&dir.file("iv"), &[0u8; 32]);
    let before = listing(&dir);

    let refused: &[&[&str]] = &[
        &["encrypt", "--key", "-", "--in", "m", "--out", "o"],
        &["decrypt", "--key", "-", "--in", "m", "--out", "o"],
        &["sign", "--key", "-", "--in", "m", "--out", "o"],
        &["verify", "--key", "-", "--in", "m", "--sig", "sig"],
        &["verify", "--key", "v.key", "--in", "m", "--sig", "-"],
        &["box-seal", "--key", "-", "--in", "m", "--out", "o"],
        &["box-open", "--key", "-", "--in", "m", "--out", "o"],
        &["sign-pubkey", "--key", "-", "--out", "o"],
        &["box-pubkey", "--key", "-", "--out", "o"],
        &[
            "key-import",
            "--kind",
            "symmetric",
            "--in",
            "-",
            "--out",
            "o",
        ],
        &["hash", "--check", "-"],
        &[
            "kupyna-digest",
            "--variant",
            "256",
            "--in",
            "-",
            "--out",
            "o",
        ],
        &[
            "kupyna-digest",
            "--variant",
            "256",
            "--in",
            "m",
            "--out",
            "-",
        ],
        &[
            "strumok-crypt",
            "--variant",
            "256",
            "--key",
            "raw32",
            "--iv",
            "iv",
            "--in",
            "-",
            "--out",
            "o",
        ],
        &[
            "kalyna-block",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "-",
            "--in",
            "m",
            "--out",
            "o",
        ],
        // A flag that would do nothing is a mistake (R4).
        &[
            "encrypt", "--key", "k.key", "--in", "m", "--out", "-", "--force",
        ],
    ];
    for args in refused {
        let r = run(&dir.0, args, b"stdin must not be read");
        assert_eq!(r.code, Some(2), "{args:?}: {}", r.stderr);
        assert!(r.stdout.is_empty(), "{args:?}");
        assert_eq!(listing(&dir), before, "{args:?} created a file");
    }
    let r = run(
        &dir.0,
        &["encrypt", "--key", "-", "--in", "m", "--out", "o"],
        b"",
    );
    assert!(r.stderr.contains("./-"), "{}", r.stderr);

    // Secret keys never go to stdout (R7), with a message that says so.
    let secret_outputs: &[&[&str]] = &[
        &["keygen", "--out", "-"],
        &["sign-keygen", "--out", "-"],
        &["sign-keygen257", "--out", "-"],
        &["box-keygen", "--out", "-"],
        &["box-keygen512", "--out", "-"],
        &[
            "key-import",
            "--kind",
            "symmetric",
            "--in",
            "raw32",
            "--out",
            "-",
        ],
    ];
    for args in secret_outputs {
        let r = run(&dir.0, args, b"");
        assert_eq!(r.code, Some(2), "{args:?}: {}", r.stderr);
        assert!(r.stdout.is_empty(), "{args:?} printed a secret");
        assert!(r.stderr.contains("secret"), "{args:?}: {}", r.stderr);
        assert_eq!(listing(&dir), before, "{args:?} created a file");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_file_named_dash_is_reachable_as_dot_slash_dash() {
    let dir = TempDir::new("stdio_dot_dash");
    keygen(&dir, "keygen", "k.key");
    write_bytes(&dir.file("-"), b"a file called dash");
    ok(&run(
        &dir.0,
        &["encrypt", "--key", "k.key", "--in", "./-", "--out", "c"],
        b"not this",
    ));
    let r = run(
        &dir.0,
        &["decrypt", "--key", "k.key", "--in", "c", "--out", "-"],
        b"",
    );
    ok(&r);
    assert_eq!(r.stdout, b"a file called dash");
}

#[test]
#[cfg(unix)]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_full_stdout_is_an_io_error_and_says_incomplete() {
    use std::process::{Command, Stdio};

    let dir = TempDir::new("stdio_full");
    keygen(&dir, "keygen", "k.key");
    write_bytes(&dir.file("p"), &pattern(3 * CHUNK));
    ok(&run(
        &dir.0,
        &["encrypt", "--key", "k.key", "--in", "p", "--out", "c"],
        b"",
    ));
    for args in [
        ["decrypt", "--key", "k.key", "--in", "c", "--out", "-"],
        ["encrypt", "--key", "k.key", "--in", "p", "--out", "-"],
    ] {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_uacrypt"))
            .args(args)
            .current_dir(&dir.0)
            .stdout(Stdio::from(full))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(3), "{args:?}: {stderr}");
        assert!(stderr.contains("<stdout>"), "{stderr}");
        assert!(stderr.contains("INCOMPLETE"), "{stderr}");
    }
}

/// Windows PowerShell 5.1's `>` stores binary stdout as UTF-16LE with a BOM (measured, D-217):
/// `decrypt` names that cause instead of blaming an old uacrypt version.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_byte_order_mark_is_named_as_text_redirection() {
    let dir = TempDir::new("stdio_bom");
    keygen(&dir, "keygen", "k.key");
    for (head, powershell) in [
        (&[0xff, 0xfe, 0x02, 0x00][..], true),
        (&[0xef, 0xbb, 0xbf, 0x02][..], true),
        (&[0x01, 0x00, 0x00, 0x00][..], false),
    ] {
        let r = run(
            &dir.0,
            &["decrypt", "--key", "k.key", "--in", "-", "--out", "-"],
            head,
        );
        assert_eq!(r.code, Some(1), "{}", r.stderr);
        assert!(r.stdout.is_empty());
        assert_eq!(
            r.stderr.contains("PowerShell 5.1"),
            powershell,
            "{}",
            r.stderr
        );
        assert_eq!(r.stderr.contains("0.3.x"), !powershell, "{}", r.stderr);
    }
}
