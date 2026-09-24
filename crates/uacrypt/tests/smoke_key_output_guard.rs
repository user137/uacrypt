//! T-268 / D-216: an existing typed key file is never replaced by another command's output, not
//! even with `--force` (rule R2; closes D-214 Decision 3). Detection reads only the key line's
//! `<prefix>:` at offset 0, never the key hex.

mod support;
use support::{read_bytes, uacrypt, write_bytes, write_key, TempDir};

const KINDS: [(&str, usize); 9] = [
    ("UACRYPT-SECRET-SYMMETRIC", 32),
    ("UACRYPT-SECRET-SIGN163", 21),
    ("uacrypt-sign163-public", 42),
    ("UACRYPT-SECRET-SIGN257", 33),
    ("uacrypt-sign257-public", 66),
    ("UACRYPT-SECRET-BOX256", 32),
    ("uacrypt-box256-public", 32),
    ("UACRYPT-SECRET-BOX512", 64),
    ("uacrypt-box512-public", 64),
];

fn fixtures(dir: &TempDir) {
    write_bytes(&dir.file("in32"), &[0x66; 32]);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    for (cmd, out) in [
        ("keygen", "sym.key"),
        ("sign-keygen", "sign.key"),
        ("box-keygen", "box.key"),
    ] {
        assert!(uacrypt([cmd, "--out", &p(out)]).success(), "{cmd}");
    }
    let prep: [&[&str]; 2] = [
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
    ];
    for argv in prep {
        let r = uacrypt(argv);
        assert!(r.success(), "{argv:?}: {}", r.stderr);
    }
}

/// Non-key output commands; the output path is appended as `--out <victim>`.
fn commands(dir: &TempDir) -> Vec<Vec<String>> {
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    [
        vec!["encrypt", "--key", &p("sym.key"), "--in", &p("in32")],
        vec!["decrypt", "--key", &p("sym.key"), "--in", &p("ct")],
        vec!["sign", "--key", &p("sign.key"), "--in", &p("in32")],
        vec!["box-seal", "--key", &p("box.pub"), "--in", &p("in32")],
        vec!["kupyna-digest", "--variant", "256", "--in", &p("in32")],
    ]
    .into_iter()
    .map(|v| v.into_iter().map(str::to_string).collect())
    .collect()
}

fn listing(dir: &TempDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&dir.0)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn no_command_replaces_a_key_file_of_any_kind_even_with_force() {
    let dir = TempDir::new("key_guard_all");
    fixtures(&dir);
    for (prefix, len) in KINDS {
        let victim = dir.file("victim.key");
        write_key(&victim, prefix, &vec![0x5a; len]);
        let before_bytes = read_bytes(&victim);
        for argv in commands(&dir) {
            for force in [false, true] {
                let before = listing(&dir);
                let mut args = argv.clone();
                args.extend(["--out".to_string(), victim.to_string_lossy().into_owned()]);
                if force {
                    args.push("--force".to_string());
                }
                let r = uacrypt(&args);
                assert_eq!(r.code, Some(3), "{prefix} {args:?}: {}", r.stderr);
                assert!(r.stderr.contains("key file"), "{}", r.stderr);
                assert!(!r.stderr.contains("pass --force"), "{}", r.stderr);
                assert_eq!(read_bytes(&victim), before_bytes, "{prefix} {args:?}");
                assert_eq!(listing(&dir), before, "{prefix} {args:?}: temp file left");
            }
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_damaged_key_file_is_still_protected_but_a_look_alike_is_not() {
    let dir = TempDir::new("key_guard_edges");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    let run = |out: &str| {
        uacrypt([
            "kupyna-digest",
            "--variant",
            "256",
            "--in",
            &p("in32"),
            "--out",
            &p(out),
            "--force",
        ])
    };

    write_bytes(&dir.file("damaged"), b"UACRYPT-SECRET-BOX256:zz");
    let r = run("damaged");
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert_eq!(
        read_bytes(&dir.file("damaged")),
        b"UACRYPT-SECRET-BOX256:zz"
    );

    for (name, content) in [
        ("no_colon", &b"UACRYPT-SECRET-BOX256"[..]),
        ("not_at_start", &b" UACRYPT-SECRET-BOX256:00"[..]),
        ("bom", &b"\xef\xbb\xbfuacrypt-box256-public:00"[..]),
        ("case", &b"uacrypt-secret-box256:00"[..]),
        ("empty", &b""[..]),
    ] {
        write_bytes(&dir.file(name), content);
        let r = run(name);
        assert!(r.success(), "{name}: {}", r.stderr);
        assert_eq!(read_bytes(&dir.file(name)).len(), 32, "{name} was replaced");
    }
}

/// `--force` replaces a symlink itself, never its target (D-214), so a link to a key file is fine.
#[cfg(unix)]
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_symlink_to_a_key_file_is_replaced_and_the_key_is_untouched() {
    let dir = TempDir::new("key_guard_symlink");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    let key = read_bytes(&dir.file("sym.key"));
    std::os::unix::fs::symlink(dir.file("sym.key"), dir.file("link")).expect("symlink");
    let r = uacrypt([
        "kupyna-digest",
        "--variant",
        "256",
        "--in",
        &p("in32"),
        "--out",
        &p("link"),
        "--force",
    ]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(read_bytes(&dir.file("sym.key")), key);
    let meta = std::fs::symlink_metadata(dir.file("link")).expect("stat");
    assert!(meta.file_type().is_file());
}

/// An existing output that cannot be read is not replaced: it might be a key file.
#[cfg(unix)]
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn an_unreadable_existing_output_is_not_replaced_with_force() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("key_guard_unreadable");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    write_bytes(&dir.file("locked"), b"whatever");
    std::fs::set_permissions(dir.file("locked"), std::fs::Permissions::from_mode(0o000))
        .expect("chmod");
    if std::fs::read(dir.file("locked")).is_ok() {
        return; // running as root: permissions do not stop the read
    }
    let before = listing(&dir);
    let r = uacrypt([
        "kupyna-digest",
        "--variant",
        "256",
        "--in",
        &p("in32"),
        "--out",
        &p("locked"),
        "--force",
    ]);
    assert_eq!(r.code, Some(3), "{}", r.stderr);
    assert_eq!(listing(&dir), before);
    std::fs::set_permissions(dir.file("locked"), std::fs::Permissions::from_mode(0o600))
        .expect("chmod back");
    assert_eq!(read_bytes(&dir.file("locked")), b"whatever");
}

/// `SameOutputPath` (exit 2) still wins when `--out` is the command's own `--key`.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn naming_the_commands_own_key_stays_a_usage_error() {
    let dir = TempDir::new("key_guard_own_key");
    fixtures(&dir);
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    let r = uacrypt([
        "decrypt",
        "--key",
        &p("sym.key"),
        "--in",
        &p("ct"),
        "--out",
        &p("sym.key"),
        "--force",
    ]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
}
