//! T-256 / D-212: typed key files at the binary boundary. Every command that reads a key accepts
//! only its own kinds and names both the kind it found and the kind it needs; raw 0.4-and-older
//! key files point to `key-import`; malformed or oversized files are refused without a panic and
//! without echoing key material; `key-import` turns each raw layout back into exactly the typed
//! line the generating command writes today.

mod support;
use support::{assert_key_line, typed_key_line, uacrypt, write_bytes, write_key, TempDir};

/// Same key bytes (`00 01 02 ...`) and lines as `keyfile`'s unit tests: the support encoder is an
/// independent second implementation, so both must produce these.
const GOLDEN: [(&str, usize, &str); 9] = [
    ("UACRYPT-SECRET-SYMMETRIC", 32, "02348388"),
    ("UACRYPT-SECRET-SIGN163", 21, "d78b26f3"),
    ("uacrypt-sign163-public", 42, "59ff77a2"),
    ("UACRYPT-SECRET-SIGN257", 33, "4aef7638"),
    ("uacrypt-sign257-public", 66, "1ef4eb6f"),
    ("UACRYPT-SECRET-BOX256", 32, "789b33a5"),
    ("uacrypt-box256-public", 32, "4614d28c"),
    ("UACRYPT-SECRET-BOX512", 64, "52b7ab4d"),
    ("uacrypt-box512-public", 64, "89fd9e66"),
];

/// Every key kind: its prefix, the command that makes it, and the `key-import --kind` name.
struct Kind {
    prefix: &'static str,
    file: &'static str,
    kind_name: &'static str,
    key_len: usize,
}

const KINDS: [Kind; 9] = [
    Kind {
        prefix: "UACRYPT-SECRET-SYMMETRIC",
        file: "sym.key",
        kind_name: "symmetric",
        key_len: 32,
    },
    Kind {
        prefix: "UACRYPT-SECRET-SIGN163",
        file: "sign163.key",
        kind_name: "sign163-secret",
        key_len: 21,
    },
    Kind {
        prefix: "uacrypt-sign163-public",
        file: "sign163.pub",
        kind_name: "sign163-public",
        key_len: 42,
    },
    Kind {
        prefix: "UACRYPT-SECRET-SIGN257",
        file: "sign257.key",
        kind_name: "sign257-secret",
        key_len: 33,
    },
    Kind {
        prefix: "uacrypt-sign257-public",
        file: "sign257.pub",
        kind_name: "sign257-public",
        key_len: 66,
    },
    Kind {
        prefix: "UACRYPT-SECRET-BOX256",
        file: "box256.key",
        kind_name: "box256-secret",
        key_len: 32,
    },
    Kind {
        prefix: "uacrypt-box256-public",
        file: "box256.pub",
        kind_name: "box256-public",
        key_len: 32,
    },
    Kind {
        prefix: "UACRYPT-SECRET-BOX512",
        file: "box512.key",
        kind_name: "box512-secret",
        key_len: 64,
    },
    Kind {
        prefix: "uacrypt-box512-public",
        file: "box512.pub",
        kind_name: "box512-public",
        key_len: 64,
    },
];

fn path(dir: &TempDir, name: &str) -> String {
    dir.file(name).to_str().unwrap().to_string()
}

fn ok(r: &support::Run) {
    assert!(r.success(), "code={:?} stderr={}", r.code, r.stderr);
}

/// Makes one real key of every kind in `dir`, with the real commands.
fn make_all_keys(dir: &TempDir) {
    for (cmd, out) in [
        ("keygen", "sym.key"),
        ("sign-keygen", "sign163.key"),
        ("sign-keygen257", "sign257.key"),
        ("box-keygen", "box256.key"),
        ("box-keygen512", "box512.key"),
    ] {
        ok(&uacrypt([cmd, "--out", &path(dir, out)]));
    }
    for (cmd, key, out) in [
        ("sign-pubkey", "sign163.key", "sign163.pub"),
        ("sign-pubkey", "sign257.key", "sign257.pub"),
        ("box-pubkey", "box256.key", "box256.pub"),
        ("box-pubkey", "box512.key", "box512.pub"),
    ] {
        ok(&uacrypt([
            cmd,
            "--key",
            &path(dir, key),
            "--out",
            &path(dir, out),
        ]));
    }
}

/// Runs `cmd` with `--key key`, filling in whatever other flags it needs; its output (if any) is
/// `out.bin`.
fn run_with_key(dir: &TempDir, cmd: &str, key: &str) -> support::Run {
    let key = path(dir, key);
    let (input, out) = (path(dir, "input.bin"), path(dir, "out.bin"));
    match cmd {
        "sign-pubkey" | "box-pubkey" => uacrypt([cmd, "--key", &key, "--out", &out]),
        "verify" => uacrypt([cmd, "--key", &key, "--in", &input, "--sig", &input]),
        _ => uacrypt([cmd, "--key", &key, "--in", &input, "--out", &out]),
    }
}

/// Every command that reads `--key`, with the key files it accepts.
const CONSUMERS: [(&str, &[&str]); 8] = [
    ("encrypt", &["sym.key"]),
    ("decrypt", &["sym.key"]),
    ("sign", &["sign163.key", "sign257.key"]),
    ("sign-pubkey", &["sign163.key", "sign257.key"]),
    ("verify", &["sign163.pub", "sign257.pub"]),
    ("box-pubkey", &["box256.key", "box512.key"]),
    ("box-seal", &["box256.pub", "box512.pub"]),
    ("box-open", &["box256.key", "box512.key"]),
];

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn support_encoder_matches_the_golden_lines() {
    for (prefix, len, check) in GOLDEN {
        let key: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            typed_key_line(prefix, &key),
            format!("{prefix}:{hex}:{check}\n")
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn every_generated_key_is_a_typed_line_of_its_kind() {
    let dir = TempDir::new("typed_generated");
    make_all_keys(&dir);
    for kind in &KINDS {
        assert_key_line(&dir.file(kind.file), kind.prefix, kind.key_len);
    }
}

/// The full matrix: every key-reading command x every key kind it does not accept is exit 3, names
/// the kind found and what the command needs, writes nothing, and never echoes key material.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn every_command_rejects_every_other_key_kind_by_name() {
    let dir = TempDir::new("typed_matrix");
    make_all_keys(&dir);
    write_bytes(
        &dir.file("input.bin"),
        b"never read: the key is refused first",
    );
    for (cmd, accepted) in CONSUMERS {
        for kind in KINDS.iter().filter(|k| !accepted.contains(&k.file)) {
            let r = run_with_key(&dir, cmd, kind.file);
            let context = format!("{cmd} --key {}: {}", kind.file, r.stderr);
            assert_eq!(r.code, Some(3), "{context}");
            assert!(
                r.stderr.contains(&format!("but {cmd} needs a ")),
                "{context}"
            );
            assert!(r.stderr.contains("uacrypt "), "no hint: {context}");
            assert!(!dir.file("out.bin").exists(), "{context}");
            let key = assert_key_line(&dir.file(kind.file), kind.prefix, kind.key_len);
            let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            assert!(
                !r.stderr.contains(&hex),
                "key material in stderr: {context}"
            );
        }
    }
}

/// T-257: every command takes both curves' keys of its kind - an accepted key never gets a
/// kind error (exit 3) or a usage error (exit 2), whatever the dummy input then does.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn every_consumer_accepts_both_curves_of_its_kind() {
    let dir = TempDir::new("typed_both_curves");
    make_all_keys(&dir);
    write_bytes(&dir.file("input.bin"), b"x");
    for (cmd, accepted) in CONSUMERS {
        for key in accepted {
            let _ = std::fs::remove_file(dir.file("out.bin"));
            let r = run_with_key(&dir, cmd, key);
            let context = format!("{cmd} --key {key}: {}", r.stderr);
            assert!(r.code != Some(2) && r.code != Some(3), "{context}");
            assert!(!r.stderr.contains(" needs a "), "{context}");
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn raw_old_key_files_point_to_key_import() {
    let dir = TempDir::new("typed_raw");
    write_bytes(&dir.file("input.bin"), b"x");
    for (cmd, raw_len) in [
        ("encrypt", 32),
        ("sign", 21),
        ("box-seal", 32),
        ("verify", 43),
    ] {
        write_bytes(&dir.file("raw.key"), &vec![0x01; raw_len]);
        let r = run_with_key(&dir, cmd, "raw.key");
        assert_eq!(r.code, Some(3), "{cmd}: {}", r.stderr);
        assert!(
            r.stderr.contains("is not a uacrypt key file"),
            "{cmd}: {}",
            r.stderr
        );
        assert!(
            r.stderr.contains("uacrypt key-import"),
            "{cmd}: {}",
            r.stderr
        );
    }
}

/// Attacker- or accident-shaped key files: each is refused with exit 3 and a specific message,
/// never a panic, and a big file is not read whole.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn malformed_key_files_are_refused_with_a_specific_message() {
    let dir = TempDir::new("typed_malformed");
    ok(&uacrypt(["keygen", "--out", &path(&dir, "sym.key")]));
    let good = String::from_utf8(support::read_bytes(&dir.file("sym.key"))).unwrap();
    write_bytes(&dir.file("input.bin"), b"x");
    let flipped_key_digit = {
        let mut b = good.clone().into_bytes();
        let i = "UACRYPT-SECRET-SYMMETRIC:".len();
        b[i] = if b[i] == b'0' { b'1' } else { b'0' };
        b
    };
    let cases: [(&str, Vec<u8>, &str); 7] = [
        ("empty", Vec::new(), "is not a uacrypt key file"),
        ("big", vec![b'U'; 1 << 20], "is not a uacrypt key file"),
        (
            "old tagged verifying key",
            [&[0x01][..], &[0x11; 42]].concat(),
            "is not a uacrypt key file",
        ),
        (
            "prefix only",
            b"UACRYPT-SECRET-SYMMETRIC:".to_vec(),
            "is not a well-formed key line",
        ),
        (
            "truncated",
            good.as_bytes()[..good.len() - 10].to_vec(),
            "is not a well-formed key line",
        ),
        (
            "two lines",
            format!("{good}{good}").into_bytes(),
            "is not a well-formed key line",
        ),
        (
            "flipped key digit",
            flipped_key_digit,
            "is damaged: its check value does not match",
        ),
    ];
    for (name, bytes, message) in cases {
        write_bytes(&dir.file("bad.key"), &bytes);
        let r = run_with_key(&dir, "encrypt", "bad.key");
        assert_eq!(r.code, Some(3), "{name}: {}", r.stderr);
        assert!(r.stderr.contains(message), "{name}: {}", r.stderr);
        assert!(!r.stderr.contains("panicked"), "{name}: {}", r.stderr);
        assert!(!dir.file("out.bin").exists(), "{name}");
    }

    // A key file edited on Windows (CRLF) still works.
    write_bytes(&dir.file("crlf.key"), good.replace('\n', "\r\n").as_bytes());
    ok(&run_with_key(&dir, "encrypt", "crlf.key"));
}

/// `key-import` of each kind's raw 0.4 layout gives back exactly the typed line the generating
/// command wrote, and reports the check values.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn key_import_round_trips_every_kind_from_its_raw_layout() {
    let dir = TempDir::new("typed_import");
    make_all_keys(&dir);
    for kind in &KINDS {
        let typed = dir.file(kind.file);
        let key = assert_key_line(&typed, kind.prefix, kind.key_len);
        let raw = match kind.kind_name {
            "sign163-public" => [&[0x01][..], &key].concat(),
            "sign257-public" => [&[0x02][..], &key].concat(),
            _ => key.clone(),
        };
        let raw_path = dir.file(&format!("{}.raw", kind.file));
        let out = format!("{}.imported", kind.file);
        write_bytes(&raw_path, &raw);
        let r = uacrypt([
            "key-import",
            "--kind",
            kind.kind_name,
            "--in",
            raw_path.to_str().unwrap(),
            "--out",
            &path(&dir, &out),
        ]);
        ok(&r);
        assert_eq!(
            support::read_bytes(&dir.file(&out)),
            support::read_bytes(&typed),
            "{}",
            kind.kind_name
        );
        let check = &typed_key_line(kind.prefix, &key)[kind.prefix.len() + 2 + 2 * kind.key_len..];
        assert!(
            r.stderr.contains(&format!("(check {})", check.trim_end())),
            "{}",
            r.stderr
        );
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !r.stderr.contains(&key_hex),
            "key material in stderr: {}",
            r.stderr
        );
    }
}

/// For a secret key, `key-import` also prints its public key's check value - the one in the
/// public key file already shared.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn key_import_of_a_secret_key_reports_its_public_keys_check() {
    let dir = TempDir::new("typed_import_public_check");
    make_all_keys(&dir);
    let key = assert_key_line(&dir.file("box256.key"), "UACRYPT-SECRET-BOX256", 32);
    write_bytes(&dir.file("raw"), &key);
    let r = uacrypt([
        "key-import",
        "--kind",
        "box256-secret",
        "--in",
        &path(&dir, "raw"),
        "--out",
        &path(&dir, "imported.key"),
    ]);
    ok(&r);
    let public = String::from_utf8(support::read_bytes(&dir.file("box256.pub"))).unwrap();
    let public_check = public.trim_end().rsplit(':').next().unwrap();
    assert!(
        r.stderr
            .contains(&format!("its public key has check {public_check}")),
        "{}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn key_import_refuses_bad_input_without_writing() {
    let dir = TempDir::new("typed_import_bad");
    let import = |kind: &str, raw: &[u8]| {
        write_bytes(&dir.file("raw"), raw);
        let _ = std::fs::remove_file(dir.file("typed"));
        uacrypt([
            "key-import",
            "--kind",
            kind,
            "--in",
            &path(&dir, "raw"),
            "--out",
            &path(&dir, "typed"),
        ])
    };
    let cases: [(&str, &[u8], i32, &str); 6] = [
        (
            "symmetric",
            &[0x11; 31],
            3,
            "must be exactly 32 bytes, got 31",
        ),
        ("sign163-secret", &[0x00; 21], 3, "not a valid"),
        (
            "box256-secret",
            &[0x00; 32],
            3,
            "not a valid crypto_box key",
        ),
        (
            "box512-public",
            &[0xFF; 64],
            3,
            "not a valid crypto_box key",
        ),
        (
            "sign163-public",
            &[0x02; 43],
            3,
            "starts with curve byte 0x02",
        ),
        (
            "box256-secert",
            &[0x11; 32],
            2,
            "did you mean `box256-secret`",
        ),
    ];
    for (kind, raw, code, message) in cases {
        let r = import(kind, raw);
        assert_eq!(r.code, Some(code), "{kind}: {}", r.stderr);
        assert!(r.stderr.contains(message), "{kind}: {}", r.stderr);
        assert!(!dir.file("typed").exists(), "{kind}");
    }

    // An already typed file is not a raw key.
    write_key(
        &dir.file("typed_already"),
        "UACRYPT-SECRET-SYMMETRIC",
        &[0x11; 32],
    );
    let r = uacrypt([
        "key-import",
        "--kind",
        "symmetric",
        "--in",
        &path(&dir, "typed_already"),
        "--out",
        &path(&dir, "typed"),
    ]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);

    let r = uacrypt([
        "key-import",
        "--in",
        &path(&dir, "raw"),
        "--out",
        &path(&dir, "typed"),
    ]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(r.stderr.contains("--kind"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn key_import_never_replaces_an_existing_secret_key() {
    let dir = TempDir::new("typed_import_exists");
    write_bytes(&dir.file("raw"), &[0x11; 32]);
    write_bytes(&dir.file("existing.key"), b"an existing key");
    let r = uacrypt([
        "key-import",
        "--kind",
        "symmetric",
        "--in",
        &path(&dir, "raw"),
        "--out",
        &path(&dir, "existing.key"),
    ]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert!(r.stderr.contains("already exists"), "{}", r.stderr);
    assert_eq!(
        support::read_bytes(&dir.file("existing.key")),
        b"an existing key"
    );
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn key_import_writes_a_secret_key_with_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("typed_import_mode");
    write_bytes(&dir.file("raw"), &[0x11; 32]);
    ok(&uacrypt([
        "key-import",
        "--kind",
        "symmetric",
        "--in",
        &path(&dir, "raw"),
        "--out",
        &path(&dir, "typed.key"),
    ]));
    let mode = std::fs::metadata(dir.file("typed.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
