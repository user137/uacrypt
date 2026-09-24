//! `hash` like `sha256sum` (T-259, `docs/DECISIONS.md` D-215): `--in` prints `<hex>  <path>`,
//! `--check` verifies such lines. The check file is untrusted input: bounded read, strict
//! grammar, whole file validated before anything is hashed.

mod support;
use dstu_core::hazmat::kupyna::Kupyna256;
use support::{uacrypt, write_bytes, TempDir};

/// Must match `HASH_CHECK_LIST_MAX_BYTES` in `src/lib.rs`.
const CHECK_LIST_MAX_BYTES: usize = 16 * 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn line_for(path: &std::path::Path, content: &[u8]) -> String {
    format!("{}  {}\n", hex(&Kupyna256::digest(content)), path.display())
}

fn uacrypt_in(cwd: &std::path::Path, args: &[&str]) -> support::Run {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_uacrypt"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn the real uacrypt binary");
    support::Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn hash_prints_hex_two_spaces_and_the_path_as_given() {
    let dir = TempDir::new("hash_line");
    let input = dir.file("report.pdf");
    write_bytes(&input, b"hash me");
    let r = uacrypt(["hash", "--in", input.to_str().unwrap()]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(r.stdout, line_for(&input, b"hash me"));
    assert_eq!(r.stderr, "");

    write_bytes(&dir.file("empty"), b"");
    let r = uacrypt_in(&dir.0, &["hash", "--in", "empty"]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(
        r.stdout,
        format!("{}  empty\n", hex(&Kupyna256::digest(b"")))
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn hash_output_checks_ok_and_writes_no_file() {
    let dir = TempDir::new("hash_roundtrip");
    write_bytes(&dir.file("a"), b"first");
    write_bytes(&dir.file("b"), b"second");
    let before: Vec<_> = std::fs::read_dir(&dir.0).unwrap().collect();
    let mut sums = String::new();
    for name in ["a", "b"] {
        let r = uacrypt_in(&dir.0, &["hash", "--in", name]);
        assert!(r.success(), "{}", r.stderr);
        sums.push_str(&r.stdout);
    }
    assert_eq!(
        std::fs::read_dir(&dir.0).unwrap().count(),
        before.len(),
        "hash wrote a file"
    );
    write_bytes(&dir.file("SUMS"), sums.as_bytes());

    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS"]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(r.stdout, "a: OK\nb: OK\n");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn check_names_every_changed_or_missing_file_and_exits_1() {
    let dir = TempDir::new("hash_mismatch");
    write_bytes(&dir.file("a"), b"first");
    write_bytes(&dir.file("b"), b"tampered");
    let sums = format!(
        "{}{}{}",
        line_for(std::path::Path::new("a"), b"first"),
        line_for(std::path::Path::new("b"), b"second"),
        line_for(std::path::Path::new("gone"), b"third"),
    );
    write_bytes(&dir.file("SUMS"), sums.as_bytes());

    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS"]);
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines[0], "a: OK");
    assert_eq!(lines[1], "b: FAILED");
    assert!(
        lines[2].starts_with("gone: FAILED (cannot read"),
        "{}",
        r.stdout
    );
    assert_eq!(lines.len(), 3);
    assert!(r.stderr.contains("2 of 3"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn check_resolves_relative_paths_against_the_working_directory() {
    let dir = TempDir::new("hash_relative");
    std::fs::create_dir(dir.file("sub")).unwrap();
    write_bytes(&dir.file("data"), b"top");
    write_bytes(&dir.file("sub").join("data"), b"nested");
    write_bytes(
        &dir.file("sub").join("SUMS"),
        line_for(std::path::Path::new("data"), b"top").as_bytes(),
    );
    let r = uacrypt_in(&dir.0, &["hash", "--check", "sub/SUMS"]);
    assert!(r.success(), "{} {}", r.stdout, r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn check_accepts_crlf_upper_case_hex_and_no_final_newline() {
    let dir = TempDir::new("hash_lenient");
    write_bytes(&dir.file("a"), b"first");
    write_bytes(&dir.file("b"), b"second");
    let a = line_for(std::path::Path::new("a"), b"first");
    let b = line_for(std::path::Path::new("b"), b"second");
    let text = format!(
        "{}\r\n{}",
        a.trim_end().to_uppercase().replace("  A", "  a"),
        b.trim_end()
    );
    write_bytes(&dir.file("SUMS"), text.as_bytes());
    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS"]);
    assert!(r.success(), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "a: OK\nb: OK\n");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_malformed_check_file_is_rejected_with_its_line_before_anything_is_hashed() {
    let dir = TempDir::new("hash_malformed");
    write_bytes(&dir.file("a"), b"first");
    let good = line_for(std::path::Path::new("a"), b"first");
    let digest = &good[..64];
    let bad_lines = [
        format!("{digest} a\n"),            // one space
        format!("{digest} *a\n"),           // GNU binary marker
        format!("{digest}  \n"),            // empty path
        format!("{}  a\n", &digest[..62]),  // short digest
        format!("{digest}00  a\n"),         // long digest
        format!("{}g  a\n", &digest[..63]), // non-hex digit
        "\n".to_string(),                   // blank line
        format!("{digest}  a\tb\n"),        // control character in the path
        format!("{digest}  a\u{1b}[31m\n"), // terminal escape in the path
        "SHA256 (a) = 00\n".to_string(),    // BSD tag format
    ];
    for bad in &bad_lines {
        write_bytes(&dir.file("SUMS"), format!("{good}{bad}").as_bytes());
        let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS"]);
        assert_eq!(r.code, Some(1), "{bad:?}: {}", r.stderr);
        assert_eq!(r.stdout, "", "{bad:?}: partial output");
        assert!(r.stderr.contains("line 2"), "{bad:?}: {}", r.stderr);
    }

    let mut not_utf8 = good.clone().into_bytes();
    not_utf8.extend_from_slice(&good.as_bytes()[..66]);
    not_utf8.extend_from_slice(b"\xff\n");
    write_bytes(&dir.file("SUMS"), &not_utf8);
    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS"]);
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stderr.contains("line 2"), "{}", r.stderr);

    write_bytes(&dir.file("SUMS"), format!("{good}\n{good}").as_bytes());
    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS"]);
    assert_eq!(r.code, Some(1), "blank line in the middle: {}", r.stderr);
    assert!(r.stderr.contains("line 2"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn an_empty_check_file_is_rejected() {
    let dir = TempDir::new("hash_empty_list");
    write_bytes(&dir.file("SUMS"), b"");
    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS"]);
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stderr.contains("no checksum lines"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn the_check_file_read_is_bounded() {
    let dir = TempDir::new("hash_list_cap");
    let at_cap = vec![b'x'; CHECK_LIST_MAX_BYTES];
    write_bytes(&dir.file("at_cap"), &at_cap);
    let r = uacrypt_in(&dir.0, &["hash", "--check", "at_cap"]);
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(
        r.stderr.contains("line 1"),
        "at the cap it is parsed: {}",
        r.stderr
    );

    let mut over = at_cap;
    over.push(b'x');
    write_bytes(&dir.file("over"), &over);
    let r = uacrypt_in(&dir.0, &["hash", "--check", "over"]);
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stderr.contains("larger than"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn usage_errors_exit_2() {
    let dir = TempDir::new("hash_usage");
    write_bytes(&dir.file("a"), b"first");
    let cases: &[&[&str]] = &[
        &["hash"],
        &["hash", "--in", "a", "--check", "a"],
        &["hash", "--in", "a", "--out", "digest"],
        &["hash", "--in", "a", "--force"],
        &["hash", "--in", "a", "--in", "a"],
        &["hash", "--check"],
    ];
    for argv in cases {
        let r = uacrypt_in(&dir.0, argv);
        assert_eq!(r.code, Some(2), "{argv:?}: {}", r.stderr);
        assert_eq!(r.stdout, "", "{argv:?}");
    }
    assert!(!dir.file("digest").exists());
    let r = uacrypt_in(&dir.0, &["hash"]);
    assert!(r.stderr.contains("--in (or --check)"), "{}", r.stderr);
    let r = uacrypt_in(&dir.0, &["hash", "--in", "a", "--check", "a"]);
    assert!(
        r.stderr.contains("--in") && r.stderr.contains("--check"),
        "{}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn file_errors_exit_3() {
    let dir = TempDir::new("hash_io");
    std::fs::create_dir(dir.file("sub")).unwrap();
    for argv in [
        ["hash", "--in", "missing"],
        ["hash", "--in", "sub"],
        ["hash", "--check", "missing"],
        ["hash", "--check", "sub"],
    ] {
        let r = uacrypt_in(&dir.0, &argv);
        assert_eq!(r.code, Some(3), "{argv:?}: {}", r.stderr);
        assert_eq!(r.stdout, "", "{argv:?}");
    }
}

/// A path that cannot be written as one line of a check file is refused instead of printed.
#[cfg(unix)]
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_path_with_a_control_character_is_refused() {
    let dir = TempDir::new("hash_newline_path");
    for name in ["two\nlines", "esc\u{1b}[31m"] {
        write_bytes(&dir.file(name), b"x");
        let r = uacrypt_in(&dir.0, &["hash", "--in", name]);
        assert_eq!(r.code, Some(2), "{name:?}: {}", r.stderr);
        assert_eq!(r.stdout, "");
    }
}

/// A write error on stdout (here: a full device) is exit 3 naming `<stdout>`, never a panic.
#[cfg(unix)]
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_failing_stdout_is_exit_3_not_a_panic() {
    let dir = TempDir::new("hash_full_stdout");
    write_bytes(&dir.file("a"), b"first");
    let full = std::fs::File::create("/dev/full").expect("open /dev/full");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_uacrypt"))
        .args(["hash", "--in", "a"])
        .current_dir(&dir.0)
        .stdout(full)
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("<stdout>"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_cyrillic_path_round_trips() {
    let dir = TempDir::new("hash_cyrillic");
    write_bytes(&dir.file("звіт.pdf"), b"x");
    let r = uacrypt_in(&dir.0, &["hash", "--in", "звіт.pdf"]);
    assert!(r.success(), "{}", r.stderr);
    assert!(r.stdout.ends_with("  звіт.pdf\n"), "{}", r.stdout);
    write_bytes(&dir.file("SUMS"), r.stdout.as_bytes());
    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS"]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(r.stdout, "звіт.pdf: OK\n");
}

/// Windows PowerShell 5.1's `>` writes UTF-16LE with a BOM: named, not "line 1 malformed". A
/// UTF-8 BOM (`Out-File -Encoding utf8`) is accepted.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_utf16_check_file_is_named_and_a_utf8_bom_is_accepted() {
    let dir = TempDir::new("hash_bom");
    write_bytes(&dir.file("a"), b"first");
    let line = line_for(std::path::Path::new("a"), b"first");
    let utf16: Vec<u8> = [0xff, 0xfe]
        .into_iter()
        .chain(line.bytes().flat_map(|b| [b, 0]))
        .collect();
    write_bytes(&dir.file("SUMS16"), &utf16);
    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS16"]);
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stderr.contains("UTF-16"), "{}", r.stderr);
    assert_eq!(r.stdout, "");

    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(line.as_bytes());
    write_bytes(&dir.file("SUMS8"), &bom);
    let r = uacrypt_in(&dir.0, &["hash", "--check", "SUMS8"]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(r.stdout, "a: OK\n");
}
