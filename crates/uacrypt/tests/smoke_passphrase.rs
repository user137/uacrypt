//! Passphrase encryption (T-262, `docs/DECISIONS.md` D-219): `encrypt --passphrase-file` /
//! `--passphrase`, and `decrypt` telling a passphrase file from a key file by its first byte.
//! Every run here has a captured stderr, so the terminal prompt is never reached: those cases get
//! the "no terminal" usage error instead, and the prompt itself is checked by hand (D-219).
//!
//! The file format is spelled out independently below (`PREFIX`, [`encode_with_core`],
//! [`decode_with_core`]) over `dstu-core` directly, so `uacrypt`'s writer and reader are each
//! checked against a second implementation, not only against each other.

mod support;
use dstu_core::crypto_pwhash::{derive_key, Strength, SALT_BYTES};
use dstu_core::crypto_secretstream::{Key, PullState, PushState, Tag, FORMAT_VERSION};
use support::{read_bytes, uacrypt, write_bytes, write_key, TempDir};

const CHUNK: usize = 8 * 1024;
/// Container type, container version, KDF id (Argon2id v1.3).
const MAGIC: [u8; 3] = [0x50, 0x01, 0x01];
/// Magic, m_cost (u32 LE), t_cost (u32 LE), p_cost (u8).
const PREFIX_LEN: usize = 3 + 4 + 4 + 1;
const HEADER_LEN: usize = PREFIX_LEN + SALT_BYTES;

fn prefix(strength: Strength) -> Vec<u8> {
    let (m, t, p) = strength.cost();
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&m.to_le_bytes());
    out.extend_from_slice(&t.to_le_bytes());
    out.push(u8::try_from(p).expect("p_cost fits a byte"));
    assert_eq!(out.len(), PREFIX_LEN);
    out
}

/// A passphrase file built from the format description, not by `uacrypt`.
fn encode_with_core(passphrase: &[u8], salt: [u8; SALT_BYTES], plaintext: &[u8]) -> Vec<u8> {
    let key = derive_key(passphrase, &salt, Strength::Moderate).expect("derive");
    let key = Key::from_bytes(*key);
    let (mut push, header) = PushState::init(&key).expect("push init");
    let mut out = prefix(Strength::Moderate);
    out.extend_from_slice(&salt);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&header);
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[]]
    } else {
        plaintext.chunks(CHUNK).collect()
    };
    for (i, chunk) in chunks.iter().enumerate() {
        let tag = if i + 1 == chunks.len() {
            Tag::Final
        } else {
            Tag::Message
        };
        let mut ct = vec![0u8; chunk.len()];
        let auth = push.push(tag, chunk, &mut ct).expect("push");
        out.push(tag.to_byte());
        out.extend_from_slice(&u32::try_from(chunk.len()).expect("len").to_le_bytes());
        out.extend_from_slice(&ct);
        out.extend_from_slice(&auth);
    }
    out
}

/// Reads a `uacrypt` passphrase file with `dstu-core` directly.
fn decode_with_core(passphrase: &[u8], file: &[u8]) -> Vec<u8> {
    assert_eq!(&file[..PREFIX_LEN], prefix(Strength::Moderate).as_slice());
    let salt: [u8; SALT_BYTES] = file[PREFIX_LEN..HEADER_LEN].try_into().expect("salt");
    let key = derive_key(passphrase, &salt, Strength::Moderate).expect("derive");
    let key = Key::from_bytes(*key);
    let mut rest = &file[HEADER_LEN..];
    assert_eq!(rest[0], FORMAT_VERSION);
    let header: [u8; 32] = rest[1..33].try_into().expect("header");
    rest = &rest[33..];
    let mut pull = PullState::init(&key, &header);
    let mut plaintext = Vec::new();
    loop {
        let tag = rest[0];
        let len = u32::from_le_bytes(rest[1..5].try_into().expect("len")) as usize;
        let ct = &rest[5..5 + len];
        let auth: [u8; 16] = rest[5 + len..5 + len + 16].try_into().expect("tag");
        let mut pt = vec![0u8; len];
        let got = pull.pull(tag, ct, &auth, &mut pt).expect("authentic chunk");
        plaintext.extend_from_slice(&pt);
        rest = &rest[5 + len + 16..];
        if got == Tag::Final {
            break;
        }
    }
    assert!(rest.is_empty(), "no trailing bytes");
    plaintext
}

fn s(p: &std::path::Path) -> &str {
    p.to_str().expect("utf-8 temp path")
}

fn encrypt(dir: &TempDir, pass: &str, input: &str, out: &str) -> support::Run {
    uacrypt([
        "encrypt",
        "--passphrase-file",
        s(&dir.file(pass)),
        "--in",
        s(&dir.file(input)),
        "--out",
        s(&dir.file(out)),
    ])
}

fn decrypt(dir: &TempDir, pass: &str, input: &str, out: &str) -> support::Run {
    uacrypt([
        "decrypt",
        "--passphrase-file",
        s(&dir.file(pass)),
        "--in",
        s(&dir.file(input)),
        "--out",
        s(&dir.file(out)),
    ])
}

fn assert_code(r: &support::Run, code: i32, needle: &str) {
    assert_eq!(r.code, Some(code), "stderr: {}", r.stderr);
    assert!(
        r.stderr.contains(needle),
        "expected {needle:?} in stderr: {}",
        r.stderr
    );
}

// --- Happy path -------------------------------------------------------------------------------

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn round_trip_empty_one_chunk_and_multi_chunk() {
    let dir = TempDir::new("pp_round_trip");
    write_bytes(&dir.file("pass"), b"correct horse battery staple\n");
    for (name, len) in [("empty", 0), ("small", 100), ("multi", 2 * CHUNK + 7)] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        write_bytes(&dir.file(name), &plaintext);
        let enc = format!("{name}.enc");
        let dec = format!("{name}.dec");
        let r = encrypt(&dir, "pass", name, &enc);
        assert!(r.success(), "encrypt {name}: {}", r.stderr);
        let r = decrypt(&dir, "pass", &enc, &dec);
        assert!(r.success(), "decrypt {name}: {}", r.stderr);
        assert_eq!(read_bytes(&dir.file(&dec)), plaintext);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn uacrypt_output_matches_the_format_description() {
    let dir = TempDir::new("pp_format_out");
    write_bytes(&dir.file("pass"), "пароль їжак".as_bytes());
    let plaintext: Vec<u8> = (0..CHUNK + 3).map(|i| (i % 7) as u8).collect();
    write_bytes(&dir.file("pt"), &plaintext);
    assert!(encrypt(&dir, "pass", "pt", "enc").success());
    let file = read_bytes(&dir.file("enc"));
    assert_eq!(decode_with_core("пароль їжак".as_bytes(), &file), plaintext);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_file_built_from_the_format_description_decrypts() {
    let dir = TempDir::new("pp_format_in");
    write_bytes(&dir.file("pass"), b"hunter2 but longer");
    let plaintext: Vec<u8> = (0..2 * CHUNK).map(|i| (i % 13) as u8).collect();
    write_bytes(
        &dir.file("enc"),
        &encode_with_core(b"hunter2 but longer", [9u8; SALT_BYTES], &plaintext),
    );
    let r = decrypt(&dir, "pass", "enc", "dec");
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(read_bytes(&dir.file("dec")), plaintext);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn two_encryptions_use_different_salts() {
    let dir = TempDir::new("pp_salts");
    write_bytes(&dir.file("pass"), b"same passphrase");
    write_bytes(&dir.file("pt"), b"same message");
    assert!(encrypt(&dir, "pass", "pt", "a").success());
    assert!(encrypt(&dir, "pass", "pt", "b").success());
    let (a, b) = (read_bytes(&dir.file("a")), read_bytes(&dir.file("b")));
    assert_ne!(a[PREFIX_LEN..HEADER_LEN], b[PREFIX_LEN..HEADER_LEN]);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn line_ending_and_bom_do_not_change_the_passphrase() {
    let dir = TempDir::new("pp_line_endings");
    write_bytes(&dir.file("lf"), b"pass phrase\n");
    write_bytes(&dir.file("crlf"), b"pass phrase\r\n");
    write_bytes(&dir.file("bom"), b"\xEF\xBB\xBFpass phrase\r\n");
    write_bytes(&dir.file("bare"), b"pass phrase");
    write_bytes(&dir.file("pt"), b"message");
    assert!(encrypt(&dir, "lf", "pt", "enc").success());
    for pass in ["crlf", "bom", "bare"] {
        let out = format!("{pass}.dec");
        let r = decrypt(&dir, pass, "enc", &out);
        assert!(r.success(), "{pass}: {}", r.stderr);
        assert_eq!(read_bytes(&dir.file(&out)), b"message");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn stdin_to_stdout_round_trip() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let dir = TempDir::new("pp_stdio");
    write_bytes(&dir.file("pass"), b"stdio passphrase");
    let run = |args: &[&str], input: &[u8]| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_uacrypt"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut pipe = child.stdin.take().expect("stdin");
        let input = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = pipe.write_all(&input);
        });
        let out = child.wait_with_output().expect("wait");
        writer.join().expect("writer");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    let pass = dir.file("pass");
    let plaintext: Vec<u8> = (0..CHUNK + 1).map(|i| (i % 5) as u8).collect();
    let enc = run(
        &[
            "encrypt",
            "--passphrase-file",
            s(&pass),
            "--in",
            "-",
            "--out",
            "-",
        ],
        &plaintext,
    );
    let dec = run(
        &[
            "decrypt",
            "--passphrase-file",
            s(&pass),
            "--in",
            "-",
            "--out",
            "-",
        ],
        &enc,
    );
    assert_eq!(dec, plaintext);
}

// --- Security & boundary ----------------------------------------------------------------------

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn wrong_passphrase_is_rejected_by_name_and_writes_nothing() {
    let dir = TempDir::new("pp_wrong");
    write_bytes(&dir.file("pass"), b"right");
    write_bytes(&dir.file("other"), b"wrong");
    write_bytes(&dir.file("pt"), b"secret");
    assert!(encrypt(&dir, "pass", "pt", "enc").success());
    let r = decrypt(&dir, "other", "enc", "dec");
    assert_code(&r, 1, "wrong passphrase");
    assert!(!dir.file("dec").exists());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn every_header_byte_is_checked() {
    let dir = TempDir::new("pp_header_flip");
    write_bytes(&dir.file("pass"), b"passphrase");
    write_bytes(&dir.file("pt"), b"message");
    assert!(encrypt(&dir, "pass", "pt", "enc").success());
    let good = read_bytes(&dir.file("enc"));
    for i in 0..=HEADER_LEN {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        write_bytes(&dir.file("bad"), &bad);
        let r = decrypt(&dir, "pass", "bad", "dec");
        assert_eq!(r.code, Some(1), "byte {i}: {}", r.stderr);
        assert!(!dir.file("dec").exists(), "byte {i}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unsupported_parameters_are_refused_before_any_argon2_work() {
    let dir = TempDir::new("pp_params");
    write_bytes(&dir.file("pass"), b"passphrase");
    write_bytes(&dir.file("pt"), b"message");
    assert!(encrypt(&dir, "pass", "pt", "enc").success());
    let good = read_bytes(&dir.file("enc"));
    let mut cases = Vec::new();
    for (m, t, p) in [
        (u32::MAX, 3, 1),
        (65536, 2, 1),     // Interactive: a real preset, but not the one encrypt writes
        (1_048_576, 4, 1), // Sensitive: 1 GiB, same
        (262_144, 3, 4),
    ] {
        let mut bad = good.clone();
        bad[3..7].copy_from_slice(&u32::to_le_bytes(m));
        bad[7..11].copy_from_slice(&u32::to_le_bytes(t));
        bad[11] = p;
        cases.push(bad);
    }
    for bad in cases {
        write_bytes(&dir.file("bad"), &bad);
        let started = std::time::Instant::now();
        let r = decrypt(&dir, "pass", "bad", "dec");
        assert_code(&r, 1, "unsupported passphrase parameters");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "refused only after Argon2 ran"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn truncated_header_is_rejected() {
    let dir = TempDir::new("pp_truncated");
    write_bytes(&dir.file("pass"), b"passphrase");
    write_bytes(&dir.file("pt"), b"message");
    assert!(encrypt(&dir, "pass", "pt", "enc").success());
    let good = read_bytes(&dir.file("enc"));
    for len in [1, 2, 3, PREFIX_LEN, HEADER_LEN, HEADER_LEN + 1] {
        write_bytes(&dir.file("cut"), &good[..len]);
        let r = decrypt(&dir, "pass", "cut", "dec");
        assert_code(&r, 1, "truncated");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn key_file_and_passphrase_file_are_told_apart_by_name() {
    let dir = TempDir::new("pp_mixup");
    write_bytes(&dir.file("pass"), b"passphrase");
    write_bytes(&dir.file("pt"), b"message");
    write_key(&dir.file("key"), "UACRYPT-SECRET-SYMMETRIC", &[7u8; 32]);
    assert!(encrypt(&dir, "pass", "pt", "pp.enc").success());
    let r = uacrypt([
        "encrypt",
        "--key",
        s(&dir.file("key")),
        "--in",
        s(&dir.file("pt")),
        "--out",
        s(&dir.file("key.enc")),
    ]);
    assert!(r.success(), "{}", r.stderr);

    let r = uacrypt([
        "decrypt",
        "--key",
        s(&dir.file("key")),
        "--in",
        s(&dir.file("pp.enc")),
        "--out",
        s(&dir.file("dec")),
    ]);
    assert_code(&r, 2, "passphrase");
    let r = decrypt(&dir, "pass", "key.enc", "dec");
    assert_code(&r, 2, "--key");
    let r = uacrypt([
        "decrypt",
        "--in",
        s(&dir.file("key.enc")),
        "--out",
        s(&dir.file("dec")),
    ]);
    assert_code(&r, 2, "--key");
    assert!(!dir.file("dec").exists());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn passphrase_never_appears_in_output() {
    let dir = TempDir::new("pp_no_leak");
    write_bytes(&dir.file("pass"), b"Zq9-unique-passphrase");
    write_bytes(&dir.file("other"), b"Xw4-other-passphrase");
    write_bytes(&dir.file("pt"), b"message");
    let r = encrypt(&dir, "pass", "pt", "enc");
    assert!(!r.stderr.contains("Zq9") && !r.stdout.contains("Zq9"));
    let r = decrypt(&dir, "other", "enc", "dec");
    assert!(!r.stderr.contains("Xw4") && !r.stdout.contains("Xw4"));
    assert!(!r.stderr.contains("Zq9"));
}

// --- Misuse -----------------------------------------------------------------------------------

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn flag_combinations_are_usage_errors() {
    let dir = TempDir::new("pp_flags");
    write_bytes(&dir.file("pass"), b"passphrase");
    write_bytes(&dir.file("pt"), b"message");
    write_key(&dir.file("key"), "UACRYPT-SECRET-SYMMETRIC", &[7u8; 32]);
    let (pass, key, pt, out) = (
        dir.file("pass"),
        dir.file("key"),
        dir.file("pt"),
        dir.file("out"),
    );
    let cases: Vec<Vec<&str>> = vec![
        vec!["encrypt", "--in", s(&pt), "--out", s(&out)],
        vec![
            "encrypt",
            "--key",
            s(&key),
            "--passphrase",
            "--in",
            s(&pt),
            "--out",
            s(&out),
        ],
        vec![
            "encrypt",
            "--key",
            s(&key),
            "--passphrase-file",
            s(&pass),
            "--in",
            s(&pt),
            "--out",
            s(&out),
        ],
        vec![
            "encrypt",
            "--passphrase",
            "--passphrase-file",
            s(&pass),
            "--in",
            s(&pt),
            "--out",
            s(&out),
        ],
        vec![
            "encrypt",
            "--passphrase-file",
            "-",
            "--in",
            s(&pt),
            "--out",
            s(&out),
        ],
        vec!["decrypt", "--passphrase", "--in", s(&pt), "--out", s(&out)],
        vec![
            "decrypt",
            "--key",
            s(&key),
            "--passphrase-file",
            s(&pass),
            "--in",
            s(&pt),
            "--out",
            s(&out),
        ],
    ];
    for args in cases {
        let r = uacrypt(&args);
        assert_eq!(r.code, Some(2), "{args:?}: {}", r.stderr);
        assert!(!out.exists(), "{args:?}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn no_terminal_names_passphrase_file() {
    let dir = TempDir::new("pp_no_tty");
    write_bytes(&dir.file("pt"), b"message");
    let r = uacrypt([
        "encrypt",
        "--passphrase",
        "--in",
        s(&dir.file("pt")),
        "--out",
        s(&dir.file("enc")),
    ]);
    assert_code(&r, 2, "--passphrase-file");
    assert!(!dir.file("enc").exists());

    write_bytes(&dir.file("pass"), b"passphrase");
    assert!(encrypt(&dir, "pass", "pt", "enc").success());
    let r = uacrypt([
        "decrypt",
        "--in",
        s(&dir.file("enc")),
        "--out",
        s(&dir.file("dec")),
    ]);
    assert_code(&r, 2, "--passphrase-file");
    assert!(!dir.file("dec").exists());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn bad_passphrase_files_are_refused() {
    let dir = TempDir::new("pp_bad_files");
    write_bytes(&dir.file("pt"), b"message");
    let cases: [(&str, &[u8], &str); 6] = [
        ("empty", b"", "empty"),
        ("newline_only", b"\n", "empty"),
        ("bom_only", b"\xEF\xBB\xBF", "empty"),
        ("two_lines", b"one\ntwo\n", "more than one line"),
        ("blank_second_line", b"one\n\n", "more than one line"),
        ("not_utf8", b"\xFF\xFEp\x00", "UTF-8"),
    ];
    for (name, bytes, needle) in cases {
        write_bytes(&dir.file(name), bytes);
        let r = encrypt(&dir, name, "pt", "enc");
        assert_code(&r, 3, needle);
        assert!(!dir.file("enc").exists(), "{name}");
    }
    write_bytes(&dir.file("huge"), &vec![b'a'; 2000]);
    assert_code(&encrypt(&dir, "huge", "pt", "enc"), 3, "longer than");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn out_may_not_replace_the_passphrase_file() {
    let dir = TempDir::new("pp_out_is_pass");
    write_bytes(&dir.file("pass"), b"passphrase");
    write_bytes(&dir.file("pt"), b"message");
    let r = uacrypt([
        "encrypt",
        "--passphrase-file",
        s(&dir.file("pass")),
        "--in",
        s(&dir.file("pt")),
        "--out",
        s(&dir.file("pass")),
        "--force",
    ]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert_eq!(read_bytes(&dir.file("pass")), b"passphrase");
}

// --- Error path -------------------------------------------------------------------------------

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn missing_passphrase_file_is_an_io_error() {
    let dir = TempDir::new("pp_missing");
    write_bytes(&dir.file("pt"), b"message");
    let r = encrypt(&dir, "no-such-file", "pt", "enc");
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert!(!dir.file("enc").exists());
}
