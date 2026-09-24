//! T-258 / D-214: overwrite policy (O1 a, rule R2) at the binary boundary. Every command that writes
//! a non-key output refuses an existing file unless `--force` is given, and leaves neither a
//! placeholder, a temp file nor a changed output behind when it fails. Commands that write a key
//! file (secret or public) never replace one and do not accept `--force` at all.

mod support;
use support::{read_bytes, uacrypt, write_bytes, TempDir};

const EXISTING: &[u8] = b"EXISTING OUTPUT";

/// Input fixtures shared by every case: raw hazmat keys/inputs plus typed keys and real
/// ciphertexts made by the binary itself.
fn fixtures(dir: &TempDir) {
    write_bytes(&dir.file("k16"), &[0x11; 16]);
    write_bytes(&dir.file("k32"), &[0x22; 32]);
    write_bytes(&dir.file("iv32"), &[0x33; 32]);
    write_bytes(&dir.file("t16"), &[0x44; 16]);
    write_bytes(&dir.file("in16"), &[0x55; 16]);
    write_bytes(&dir.file("in32"), &[0x66; 32]);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    for (cmd, out) in [
        ("keygen", "sym.key"),
        ("sign-keygen", "sign.key"),
        ("box-keygen", "box.key"),
    ] {
        assert!(uacrypt([cmd, "--out", &p(out)]).success(), "{cmd}");
    }
    let prep: [&[&str]; 3] = [
        &["box-pubkey", "--key", &p("box.key"), "--out", &p("box.pub")],
        &[
            "encrypt",
            "--key",
            &p("sym.key"),
            "--in",
            &p("in32"),
            "--out",
            &p("ct"),
        ],
        &[
            "box-seal",
            "--key",
            &p("box.pub"),
            "--in",
            &p("in32"),
            "--out",
            &p("sealed"),
        ],
    ];
    for argv in prep {
        let r = uacrypt(argv);
        assert!(r.success(), "{argv:?}: {}", r.stderr);
    }
}

/// One command writing non-key output: its argv with `{name}` placeholders for output paths, and
/// the flags whose values are outputs.
struct Case {
    argv: &'static [&'static str],
    outputs: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        argv: &[
            "encrypt", "--key", "sym.key", "--in", "in32", "--out", "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "decrypt", "--key", "sym.key", "--in", "ct", "--out", "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &["hash", "--in", "in32", "--out", "{out}"],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "sign", "--key", "sign.key", "--in", "in32", "--out", "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "box-seal", "--key", "box.pub", "--in", "in32", "--out", "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "box-open", "--key", "box.key", "--in", "sealed", "--out", "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "kupyna-digest",
            "--variant",
            "256",
            "--in",
            "in32",
            "--out",
            "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "strumok-crypt",
            "--variant",
            "256",
            "--key",
            "k32",
            "--iv",
            "iv32",
            "--in",
            "in32",
            "--out",
            "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "kalyna-block",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k16",
            "--in",
            "in16",
            "--out",
            "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "kalyna-ccm",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k16",
            "--nonce",
            "{nonce}",
            "--in",
            "in32",
            "--out",
            "{out}",
            "--tag",
            "{tag}",
        ],
        outputs: &["--nonce", "--out", "--tag"],
    },
    Case {
        argv: &[
            "kalyna-gcm",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k16",
            "--nonce",
            "{nonce}",
            "--in",
            "in32",
            "--out",
            "{out}",
            "--tag",
            "{tag}",
        ],
        outputs: &["--nonce", "--out", "--tag"],
    },
    Case {
        argv: &[
            "kalyna-cmac",
            "compute",
            "--variant",
            "128-128",
            "--key",
            "k16",
            "--in",
            "in32",
            "--out",
            "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "kalyna-gmac",
            "compute",
            "--variant",
            "128-128",
            "--key",
            "k16",
            "--in",
            "in32",
            "--out",
            "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "kalyna-kw",
            "wrap",
            "--variant",
            "128-128",
            "--key",
            "k16",
            "--in",
            "in32",
            "--out",
            "{out}",
        ],
        outputs: &["--out"],
    },
    Case {
        argv: &[
            "kalyna-xts",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k16",
            "--tweak",
            "t16",
            "--in",
            "in32",
            "--out",
            "{out}",
        ],
        outputs: &["--out"],
    },
];

/// The output file name a `{placeholder}` becomes.
fn output_name(flag: &str) -> String {
    format!("output{flag}")
}

/// `case.argv` with every fixture name and `{placeholder}` turned into a path inside `dir`, plus
/// `extra` appended.
fn build_argv(dir: &TempDir, case: &Case, extra: &[&str]) -> Vec<String> {
    let mut argv = Vec::new();
    let mut prev = "";
    for token in case.argv {
        let value = if token.starts_with('{') {
            dir.file(&output_name(prev)).to_string_lossy().into_owned()
        } else if prev.starts_with("--") && !matches!(prev, "--variant") {
            dir.file(token).to_string_lossy().into_owned()
        } else {
            (*token).to_string()
        };
        argv.push(value);
        prev = token;
    }
    argv.extend(extra.iter().map(|s| (*s).to_string()));
    argv
}

/// Every file name in `dir`, sorted.
fn listing(dir: &TempDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&dir.0)
        .expect("list temp dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn remove_outputs(dir: &TempDir, case: &Case) {
    for flag in case.outputs {
        let _ = std::fs::remove_file(dir.file(&output_name(flag)));
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn fresh_outputs_are_written_without_force() {
    let dir = TempDir::new("overwrite_fresh");
    fixtures(&dir);
    for case in CASES {
        let r = uacrypt(build_argv(&dir, case, &[]));
        assert!(r.success(), "{:?}: {}", case.argv, r.stderr);
        for flag in case.outputs {
            assert!(
                dir.file(&output_name(flag)).exists(),
                "{:?} {flag}",
                case.argv
            );
        }
        remove_outputs(&dir, case);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn an_existing_output_is_refused_without_force_and_left_untouched() {
    let dir = TempDir::new("overwrite_refused");
    fixtures(&dir);
    for case in CASES {
        for existing in case.outputs {
            let path = dir.file(&output_name(existing));
            write_bytes(&path, EXISTING);
            let before = listing(&dir);
            let r = uacrypt(build_argv(&dir, case, &[]));
            assert_eq!(r.code, Some(3), "{:?} {existing}: {}", case.argv, r.stderr);
            assert!(r.stderr.contains("already exists"), "{}", r.stderr);
            assert!(r.stderr.contains("--force"), "{}", r.stderr);
            assert_eq!(read_bytes(&path), EXISTING, "{:?} {existing}", case.argv);
            assert_eq!(
                listing(&dir),
                before,
                "{:?} {existing}: stray files",
                case.argv
            );
            remove_outputs(&dir, case);
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn force_replaces_every_existing_output() {
    let dir = TempDir::new("overwrite_forced");
    fixtures(&dir);
    for case in CASES {
        for flag in case.outputs {
            write_bytes(&dir.file(&output_name(flag)), EXISTING);
        }
        let r = uacrypt(build_argv(&dir, case, &["--force"]));
        assert!(r.success(), "{:?}: {}", case.argv, r.stderr);
        for flag in case.outputs {
            assert_ne!(
                read_bytes(&dir.file(&output_name(flag))),
                EXISTING,
                "{flag}"
            );
        }
        assert!(
            !listing(&dir).iter().any(|n| n.contains(".uacrypt-tmp-")),
            "{:?}: temp file left",
            case.argv
        );
        remove_outputs(&dir, case);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn in_place_needs_force_and_says_it_is_the_input() {
    let dir = TempDir::new("overwrite_in_place");
    fixtures(&dir);
    let key = dir.file("sym.key").to_string_lossy().into_owned();
    let data = dir.file("data").to_string_lossy().into_owned();
    write_bytes(&dir.file("data"), b"in place");
    let r = uacrypt(["encrypt", "--key", &key, "--in", &data, "--out", &data]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert!(r.stderr.contains("same file as --in"), "{}", r.stderr);
    assert!(r.stderr.contains("--force"), "{}", r.stderr);
    assert_eq!(read_bytes(&dir.file("data")), b"in place");

    for cmd in ["encrypt", "decrypt"] {
        let r = uacrypt([cmd, "--key", &key, "--in", &data, "--out", &data, "--force"]);
        assert!(r.success(), "{cmd}: {}", r.stderr);
    }
    assert_eq!(read_bytes(&dir.file("data")), b"in place");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_failed_command_leaves_no_output_placeholder_or_temp_file() {
    let dir = TempDir::new("overwrite_failure");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    let mut tampered = read_bytes(&dir.file("ct"));
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    write_bytes(&dir.file("ct.bad"), &tampered);
    let mut sealed = read_bytes(&dir.file("sealed"));
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    write_bytes(&dir.file("sealed.bad"), &sealed);
    write_bytes(&dir.file("empty"), b"");

    let failing: [(&[&str], i32); 4] = [
        (
            &["decrypt", "--key", &p("sym.key"), "--in", &p("ct.bad")],
            1,
        ),
        (
            &["box-open", "--key", &p("box.key"), "--in", &p("sealed.bad")],
            1,
        ),
        (
            &["decrypt", "--key", &p("sym.key"), "--in", &p("missing")],
            3,
        ),
        (&["hash", "--in", &p("missing")], 3),
    ];
    for (argv, code) in failing {
        let before = listing(&dir);
        let r = uacrypt(argv.iter().copied().chain(["--out", &p("fresh")]));
        assert_eq!(r.code, Some(code), "{argv:?}: {}", r.stderr);
        assert_eq!(listing(&dir), before, "{argv:?} without --force");

        write_bytes(&dir.file("old"), EXISTING);
        let before = listing(&dir);
        let r = uacrypt(argv.iter().copied().chain(["--out", &p("old"), "--force"]));
        assert_eq!(r.code, Some(code), "{argv:?}: {}", r.stderr);
        assert_eq!(read_bytes(&dir.file("old")), EXISTING, "{argv:?}");
        assert_eq!(listing(&dir), before, "{argv:?} with --force");
    }

    // kalyna-ccm encrypt reserves three outputs before it reads --in; an empty --in (outside the
    // mode's domain) must release all three.
    let before = listing(&dir);
    let r = uacrypt([
        "kalyna-ccm",
        "encrypt",
        "--variant",
        "128-128",
        "--key",
        &p("k16"),
        "--nonce",
        &p("n"),
        "--in",
        &p("empty"),
        "--out",
        &p("o"),
        "--tag",
        &p("t"),
    ]);
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert_eq!(listing(&dir), before);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn two_outputs_naming_one_file_is_a_usage_error_even_with_force() {
    let dir = TempDir::new("overwrite_same_output");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    for force in [false, true] {
        let mut argv = vec![
            "kalyna-gcm".to_string(),
            "encrypt".into(),
            "--variant".into(),
            "128-128".into(),
            "--key".into(),
            p("k16"),
            "--nonce".into(),
            p("n"),
            "--in".into(),
            p("in32"),
            "--out".into(),
            p("x"),
            "--tag".into(),
            p("x"),
        ];
        if force {
            argv.push("--force".into());
        }
        let before = listing(&dir);
        let r = uacrypt(&argv);
        assert_eq!(r.code, Some(2), "force={force}: {}", r.stderr);
        assert!(
            r.stderr.contains("--out") && r.stderr.contains("--tag"),
            "{}",
            r.stderr
        );
        assert_eq!(listing(&dir), before);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn decrypt_side_nonce_and_tag_are_inputs_not_outputs() {
    let dir = TempDir::new("overwrite_decrypt_inputs");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    for mode in ["kalyna-ccm", "kalyna-gcm"] {
        let enc = uacrypt([
            mode,
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            &p("k16"),
            "--nonce",
            &p("n"),
            "--in",
            &p("in32"),
            "--out",
            &p("c"),
            "--tag",
            &p("t"),
        ]);
        assert!(enc.success(), "{mode}: {}", enc.stderr);
        let dec = uacrypt([
            mode,
            "decrypt",
            "--variant",
            "128-128",
            "--key",
            &p("k16"),
            "--nonce",
            &p("n"),
            "--in",
            &p("c"),
            "--out",
            &p("plain"),
            "--tag",
            &p("t"),
        ]);
        assert!(dec.success(), "{mode}: {}", dec.stderr);
        assert_eq!(read_bytes(&dir.file("plain")), [0x66; 32]);
        for n in ["n", "c", "t", "plain"] {
            std::fs::remove_file(dir.file(n)).expect("clean up");
        }
    }
    for mode in ["kalyna-cmac", "kalyna-gmac"] {
        let base = [
            mode,
            "--variant",
            "128-128",
            "--key",
            &p("k16"),
            "--in",
            &p("in32"),
        ];
        let tag = uacrypt(
            [mode, "compute"]
                .into_iter()
                .chain(base[1..].iter().copied())
                .chain(["--out", &p("t")]),
        );
        assert!(tag.success(), "{mode}: {}", tag.stderr);
        let verify = uacrypt(
            [mode, "verify"]
                .into_iter()
                .chain(base[1..].iter().copied())
                .chain(["--tag", &p("t")]),
        );
        assert!(verify.success(), "{mode}: {}", verify.stderr);
        std::fs::remove_file(dir.file("t")).expect("clean up");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn key_writing_commands_never_replace_a_file_and_reject_force() {
    let dir = TempDir::new("overwrite_keys");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    let line = String::from_utf8(read_bytes(&dir.file("box.pub"))).expect("utf-8 key line");
    let hex = line.trim_end().split(':').nth(1).expect("hex field");
    let raw: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    write_bytes(&dir.file("raw.pub"), &raw);
    let key_cases: [&[&str]; 8] = [
        &["keygen"],
        &["sign-keygen"],
        &["sign-keygen257"],
        &["box-keygen"],
        &["box-keygen512"],
        &["sign-pubkey", "--key", &p("sign.key")],
        &["box-pubkey", "--key", &p("box.key")],
        &[
            "key-import",
            "--kind",
            "box256-public",
            "--in",
            &p("raw.pub"),
        ],
    ];
    for argv in key_cases {
        write_bytes(&dir.file("taken"), EXISTING);
        let r = uacrypt(argv.iter().copied().chain(["--out", &p("taken")]));
        assert_eq!(r.code, Some(3), "{argv:?}: {}", r.stderr);
        assert!(r.stderr.contains("already exists"), "{}", r.stderr);
        assert!(!r.stderr.contains("--force"), "{argv:?}: {}", r.stderr);
        assert_eq!(read_bytes(&dir.file("taken")), EXISTING, "{argv:?}");

        let r = uacrypt(
            argv.iter()
                .copied()
                .chain(["--out", &p("fresh"), "--force"]),
        );
        assert_eq!(r.code, Some(2), "{argv:?}: {}", r.stderr);
        assert!(!dir.file("fresh").exists(), "{argv:?}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_public_key_command_pointed_at_its_own_secret_key_does_not_destroy_it() {
    let dir = TempDir::new("overwrite_pubkey_onto_secret");
    fixtures(&dir);
    for (cmd, key) in [("sign-pubkey", "sign.key"), ("box-pubkey", "box.key")] {
        let path = dir.file(key);
        let secret = read_bytes(&path);
        let p = path.to_string_lossy().into_owned();
        let r = uacrypt([cmd, "--key", &p, "--out", &p]);
        assert_eq!(r.code, Some(3), "{cmd}: {}", r.stderr);
        assert_eq!(read_bytes(&path), secret, "{cmd}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn force_takes_no_value() {
    let dir = TempDir::new("overwrite_force_value");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    let r = uacrypt(["hash", "--in", &p("in32"), "--out", &p("h"), "--force=yes"]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(!dir.file("h").exists());
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_symlink_output_is_refused_and_force_replaces_the_link_not_its_target() {
    let dir = TempDir::new("overwrite_symlink");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    write_bytes(&dir.file("target"), EXISTING);
    std::os::unix::fs::symlink(dir.file("target"), dir.file("link")).expect("symlink");

    let r = uacrypt(["hash", "--in", &p("in32"), "--out", &p("link")]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert_eq!(read_bytes(&dir.file("target")), EXISTING);

    let r = uacrypt(["hash", "--in", &p("in32"), "--out", &p("link"), "--force"]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(read_bytes(&dir.file("target")), EXISTING);
    let meta = std::fs::symlink_metadata(dir.file("link")).expect("stat link");
    assert!(meta.file_type().is_file(), "the link itself was replaced");
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn every_output_is_owner_only_even_when_force_replaces_a_0644_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("overwrite_mode");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    let r = uacrypt(["hash", "--in", &p("in32"), "--out", &p("fresh")]);
    assert!(r.success(), "{}", r.stderr);
    write_bytes(&dir.file("shared"), EXISTING);
    std::fs::set_permissions(dir.file("shared"), std::fs::Permissions::from_mode(0o644))
        .expect("chmod");
    let r = uacrypt(["hash", "--in", &p("in32"), "--out", &p("shared"), "--force"]);
    assert!(r.success(), "{}", r.stderr);
    for name in ["fresh", "shared"] {
        let mode = std::fs::metadata(dir.file(name))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn help_offers_force_exactly_where_it_is_accepted() {
    let mut commands: Vec<&str> = CASES.iter().map(|c| c.argv[0]).collect();
    commands.dedup();
    for cmd in commands {
        let r = uacrypt([cmd, "--help"]);
        assert!(r.success(), "{cmd}: {}", r.stderr);
        assert!(r.stdout.contains("[--force]"), "{cmd}: {}", r.stdout);
        assert!(r.stdout.contains("    --force "), "{cmd}: {}", r.stdout);
    }
    for cmd in [
        "keygen",
        "sign-keygen",
        "sign-keygen257",
        "box-keygen",
        "box-keygen512",
        "sign-pubkey",
        "box-pubkey",
        "key-import",
    ] {
        let r = uacrypt([cmd, "--help"]);
        assert!(r.success(), "{cmd}: {}", r.stderr);
        assert!(!r.stdout.contains("[--force]"), "{cmd}: {}", r.stdout);
    }
    let r = uacrypt(["--help"]);
    assert!(
        r.stdout.contains("never replaced unless you pass --force"),
        "{}",
        r.stdout
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn an_output_naming_a_key_input_is_refused_even_with_force() {
    let dir = TempDir::new("overwrite_key_as_output");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    let gcm = uacrypt([
        "kalyna-gcm",
        "encrypt",
        "--variant",
        "128-128",
        "--key",
        &p("k16"),
        "--nonce",
        &p("n"),
        "--in",
        &p("in32"),
        "--out",
        &p("c"),
        "--tag",
        &p("t"),
    ]);
    assert!(gcm.success(), "{}", gcm.stderr);
    let cases: [(&[&str], &str, &str); 8] = [
        (
            &["decrypt", "--key", &p("sym.key"), "--in", &p("ct")],
            "sym.key",
            "--key",
        ),
        (
            &["encrypt", "--key", &p("sym.key"), "--in", &p("in32")],
            "sym.key",
            "--key",
        ),
        (
            &["sign", "--key", &p("sign.key"), "--in", &p("in32")],
            "sign.key",
            "--key",
        ),
        (
            &["box-open", "--key", &p("box.key"), "--in", &p("sealed")],
            "box.key",
            "--key",
        ),
        (
            &[
                "kalyna-block",
                "encrypt",
                "--variant",
                "128-128",
                "--key",
                &p("k16"),
                "--in",
                &p("in16"),
            ],
            "k16",
            "--key",
        ),
        (
            &[
                "strumok-crypt",
                "--variant",
                "256",
                "--key",
                &p("k32"),
                "--iv",
                &p("iv32"),
                "--in",
                &p("in32"),
            ],
            "iv32",
            "--iv",
        ),
        (
            &[
                "kalyna-gcm",
                "decrypt",
                "--variant",
                "128-128",
                "--key",
                &p("k16"),
                "--nonce",
                &p("n"),
                "--in",
                &p("c"),
                "--tag",
                &p("t"),
            ],
            "n",
            "--nonce",
        ),
        (
            &[
                "kalyna-cmac",
                "compute",
                "--variant",
                "128-128",
                "--key",
                &p("k16"),
                "--in",
                &p("in32"),
            ],
            "k16",
            "--key",
        ),
    ];
    for (argv, victim, flag) in cases {
        let before = read_bytes(&dir.file(victim));
        let listing_before = listing(&dir);
        for force in [&[][..], &["--force"][..]] {
            let r = uacrypt(
                argv.iter()
                    .copied()
                    .chain(["--out", &p(victim)])
                    .chain(force.iter().copied()),
            );
            assert_eq!(r.code, Some(2), "{argv:?} {force:?}: {}", r.stderr);
            assert!(
                r.stderr.contains(&format!("--out and {flag}")),
                "{}",
                r.stderr
            );
            assert_eq!(read_bytes(&dir.file(victim)), before, "{argv:?} {force:?}");
            assert_eq!(listing(&dir), listing_before, "{argv:?} {force:?}");
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_directory_output_is_refused_and_left_intact_with_or_without_force() {
    let dir = TempDir::new("overwrite_directory");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    std::fs::create_dir(dir.file("sub")).expect("mkdir");
    write_bytes(&dir.file("sub").join("inside"), EXISTING);
    let before = listing(&dir);

    let r = uacrypt(["hash", "--in", &p("in32"), "--out", &p("sub")]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert!(r.stderr.contains("is a directory"), "{}", r.stderr);
    assert!(!r.stderr.contains("--force"), "{}", r.stderr);

    // The rename onto a directory fails after the temp file is written: the commit-failure path.
    let r = uacrypt([
        "encrypt",
        "--key",
        &p("sym.key"),
        "--in",
        &p("in32"),
        "--out",
        &p("sub"),
        "--force",
    ]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert_eq!(read_bytes(&dir.file("sub").join("inside")), EXISTING);
    assert_eq!(listing(&dir), before);
}
