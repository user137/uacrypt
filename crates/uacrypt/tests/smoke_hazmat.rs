//! T-317: the low-level commands live under `uacrypt hazmat` - reachable only by name, absent from
//! the everyday help, and warning on every run (`docs/DECISIONS.md` D-264).

mod support;
use support::{uacrypt, TempDir};

const HAZMAT: [&str; 8] = [
    "kalyna-block",
    "kalyna-ccm",
    "kalyna-gcm",
    "kalyna-gmac",
    "kalyna-kw",
    "kalyna-xts",
    "kupyna-digest",
    "strumok-crypt",
];

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn old_top_level_names_are_a_usage_error_naming_the_new_command() {
    for name in HAZMAT {
        for args in [vec![name], vec![name, "encrypt", "--variant", "256"]] {
            let r = uacrypt(&args);
            assert_eq!(r.code, Some(2), "{args:?}: {}", r.stderr);
            assert!(
                r.stderr.contains(&format!("`uacrypt hazmat {name}`")),
                "{args:?}: {}",
                r.stderr
            );
            assert_eq!(r.stdout, "", "{args:?}");
        }
        let r = uacrypt(["help", name]);
        assert_eq!(r.code, Some(2), "help {name}: {}", r.stderr);
        assert!(r.stderr.contains(&format!("`uacrypt hazmat {name}`")));
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn a_near_miss_of_an_old_name_suggests_the_hazmat_command() {
    let r = uacrypt(["kalyna-blok"]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(
        r.stderr.contains("(did you mean `hazmat kalyna-block`?)"),
        "{}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn hazmat_alone_and_help_hazmat_list_every_command_without_a_warning() {
    for args in [
        vec!["hazmat"],
        vec!["hazmat", "--help"],
        vec!["hazmat", "-h"],
        vec!["help", "hazmat"],
    ] {
        let r = uacrypt(&args);
        assert!(r.success(), "{args:?}: {}", r.stderr);
        assert_eq!(r.stderr, "", "{args:?}");
        assert!(r.stdout.starts_with("uacrypt hazmat "), "{args:?}");
        assert!(r.stdout.contains("no misuse protection"), "{args:?}");
        for name in HAZMAT {
            assert!(
                r.stdout.contains(&format!("\n    {name} ")),
                "{args:?}: {name}"
            );
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn each_hazmat_command_has_its_own_help_and_help_does_not_warn() {
    for name in HAZMAT {
        let r = uacrypt(["hazmat", name, "--help"]);
        assert!(r.success(), "{name}: {}", r.stderr);
        assert!(
            r.stdout.starts_with(&format!("uacrypt hazmat {name} ")),
            "{name}: {}",
            r.stdout
        );
        assert_eq!(r.stderr, "", "{name}");
    }
    let r = uacrypt(["hazmat", "kalyna-block", "encrypt", "--key", "x", "--help"]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(r.stderr, "");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unknown_words_after_hazmat_are_unknown_commands() {
    let r = uacrypt(["hazmat", "nope"]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(
        r.stderr.contains("unknown command: hazmat nope"),
        "{}",
        r.stderr
    );

    let r = uacrypt(["hazmat", "kalyna-blok"]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(
        r.stderr.contains("(did you mean `kalyna-block`?)"),
        "{}",
        r.stderr
    );

    let r = uacrypt(["hazmat", "encrypt"]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(
        r.stderr.contains("unknown command: hazmat encrypt"),
        "{}",
        r.stderr
    );

    let r = uacrypt(["hazmat", "kalyna-cmac"]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(r.stderr.contains("forged"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn every_hazmat_run_warns_on_stderr_even_when_it_fails() {
    let dir = TempDir::new("hazmat-warn");
    let input = dir.file("in.bin");
    support::write_bytes(&input, b"abc");
    let r = uacrypt([
        "hazmat",
        "kupyna-digest",
        "--variant",
        "256",
        "--in",
        input.to_str().expect("utf-8 path"),
        "--out",
        dir.file("digest.bin").to_str().expect("utf-8 path"),
    ]);
    assert!(r.success(), "{}", r.stderr);
    assert!(
        r.stderr.starts_with(
            "uacrypt: warning: 'hazmat kupyna-digest' is a low-level primitive with no misuse \
             protection"
        ),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("'hash'"), "{}", r.stderr);

    let r = uacrypt(["hazmat", "strumok-crypt", "--variant", "256"]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(
        r.stderr
            .starts_with("uacrypt: warning: 'hazmat strumok-crypt' is a low-level primitive"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("'encrypt'"), "{}", r.stderr);
    assert!(r.stderr.contains("uacrypt: missing"), "{}", r.stderr);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn the_everyday_help_lists_hazmat_but_none_of_its_commands() {
    let r = uacrypt(["--help"]);
    assert!(r.success());
    assert!(r.stdout.contains("\n    hazmat "), "{}", r.stdout);
    for name in HAZMAT {
        assert!(
            !r.stdout.contains(&format!("\n    {name} ")),
            "{name} still listed at the top level"
        );
    }
}
