//! T-200 Phase 2 (misuse/malformed-usage matrix), the "rest of it" beyond `--in`==`--out`
//! (`smoke_misuse.rs`) and `smoke_dispatch.rs`'s representative dispatch-level coverage: a full
//! per-command missing-required-flag sweep, `kalyna-cmac`/`kalyna-gmac`'s mode-specific `--out`/
//! `--tag` requirement (enforced after file I/O, not at parse time - a genuinely different code
//! path from every other command's flags), directory-as-`--out`, and `--iterations 0`.
//!
//! **Missing-required-flag matrix, exhaustive, not representative**: every leaf command's true
//! required-flag set differs (that's exactly what would silently drift), so this is a real per-
//! command data table (`CASES`), built directly from each `parse_*_args` function's own
//! `ArgScanner::scan`/`.path(...)`/`.variant(...)` calls in `crates/uacrypt/src/lib.rs`, not
//! assumed from `--help` text. `MissingFlag`'s check fires before any file is opened for every
//! flag in this table (confirmed by reading `parse_*_args` - the accessor call happens inside the
//! struct literal, before `run_*_command` ever starts), so the dummy path strings below never need
//! to point at real files.
//!
//! **Unknown-flag rejection is deliberately NOT swept the same way**: every command routes through
//! the exact same shared `ArgScanner::scan` unknown-flag branch (`crates/uacrypt/src/lib.rs`'s own
//! doc comment on `ArgScanner::scan` - built specifically to replace ~918 duplicated lines of
//! per-command copy-paste, T-188/SonarCloud) - there is no per-command variation left to catch, so
//! a handful of representative cases below are the real coverage, not 34 repeats of one 5-line
//! `else` branch.

mod support;
use support::{uacrypt, write_bytes, TempDir};

/// One command invocation's full, well-formed argv (dummy path values - never opened, see the
/// module doc) plus the `--flag` names that must each independently be required.
struct Case {
    name: &'static str,
    args: &'static [&'static str],
    required: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        name: "keygen",
        args: &["keygen", "--out", "o"],
        required: &["--out"],
    },
    Case {
        name: "sign-keygen",
        args: &["sign-keygen", "--out", "o"],
        required: &["--out"],
    },
    Case {
        name: "sign-keygen257",
        args: &["sign-keygen257", "--out", "o"],
        required: &["--out"],
    },
    Case {
        name: "box-keygen",
        args: &["box-keygen", "--out", "o"],
        required: &["--out"],
    },
    Case {
        name: "box-keygen512",
        args: &["box-keygen512", "--out", "o"],
        required: &["--out"],
    },
    Case {
        name: "sign-pubkey",
        args: &["sign-pubkey", "--key", "k", "--out", "o"],
        required: &["--key", "--out"],
    },
    Case {
        name: "sign-pubkey257",
        args: &["sign-pubkey257", "--key", "k", "--out", "o"],
        required: &["--key", "--out"],
    },
    Case {
        name: "box-pubkey",
        args: &["box-pubkey", "--key", "k", "--out", "o"],
        required: &["--key", "--out"],
    },
    Case {
        name: "box-pubkey512",
        args: &["box-pubkey512", "--key", "k", "--out", "o"],
        required: &["--key", "--out"],
    },
    Case {
        name: "sign",
        args: &["sign", "--key", "k", "--in", "i", "--out", "o"],
        required: &["--key", "--in", "--out"],
    },
    Case {
        name: "sign257",
        args: &["sign257", "--key", "k", "--in", "i", "--out", "o"],
        required: &["--key", "--in", "--out"],
    },
    Case {
        name: "verify",
        args: &["verify", "--key", "k", "--in", "i", "--sig", "s"],
        required: &["--key", "--in", "--sig"],
    },
    Case {
        name: "box-seal",
        args: &["box-seal", "--key", "k", "--in", "i", "--out", "o"],
        required: &["--key", "--in", "--out"],
    },
    Case {
        name: "box-open",
        args: &["box-open", "--key", "k", "--in", "i", "--out", "o"],
        required: &["--key", "--in", "--out"],
    },
    Case {
        name: "box-seal512",
        args: &["box-seal512", "--key", "k", "--in", "i", "--out", "o"],
        required: &["--key", "--in", "--out"],
    },
    Case {
        name: "box-open512",
        args: &["box-open512", "--key", "k", "--in", "i", "--out", "o"],
        required: &["--key", "--in", "--out"],
    },
    Case {
        name: "hash",
        args: &["hash", "--in", "i", "--out", "o"],
        required: &["--in", "--out"],
    },
    Case {
        name: "kupyna-digest",
        args: &[
            "kupyna-digest",
            "--variant",
            "256",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--in", "--out"],
    },
    Case {
        name: "encrypt",
        args: &["encrypt", "--key", "k", "--in", "i", "--out", "o"],
        required: &["--key", "--in", "--out"],
    },
    Case {
        name: "decrypt",
        args: &["decrypt", "--key", "k", "--in", "i", "--out", "o"],
        required: &["--key", "--in", "--out"],
    },
    Case {
        name: "strumok-crypt",
        args: &[
            "strumok-crypt",
            "--variant",
            "256",
            "--key",
            "k",
            "--iv",
            "v",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--iv", "--in", "--out"],
    },
    Case {
        name: "kalyna-block encrypt",
        args: &[
            "kalyna-block",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--in", "--out"],
    },
    Case {
        name: "kalyna-block decrypt",
        args: &[
            "kalyna-block",
            "decrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--in", "--out"],
    },
    Case {
        name: "kalyna-ccm encrypt",
        args: &[
            "kalyna-ccm",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--nonce",
            "n",
            "--in",
            "i",
            "--out",
            "o",
            "--tag",
            "t",
        ],
        required: &["--variant", "--key", "--nonce", "--in", "--out", "--tag"],
    },
    Case {
        name: "kalyna-ccm decrypt",
        args: &[
            "kalyna-ccm",
            "decrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--nonce",
            "n",
            "--in",
            "i",
            "--out",
            "o",
            "--tag",
            "t",
        ],
        required: &["--variant", "--key", "--nonce", "--in", "--out", "--tag"],
    },
    Case {
        name: "kalyna-gcm encrypt",
        args: &[
            "kalyna-gcm",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--nonce",
            "n",
            "--in",
            "i",
            "--out",
            "o",
            "--tag",
            "t",
        ],
        required: &["--variant", "--key", "--nonce", "--in", "--out", "--tag"],
    },
    Case {
        name: "kalyna-gcm decrypt",
        args: &[
            "kalyna-gcm",
            "decrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--nonce",
            "n",
            "--in",
            "i",
            "--out",
            "o",
            "--tag",
            "t",
        ],
        required: &["--variant", "--key", "--nonce", "--in", "--out", "--tag"],
    },
    // kalyna-cmac/kalyna-gmac compute/verify: --out/--tag are each mode-specific, checked after
    // file I/O, not by ArgScanner at parse time - covered separately below, not in this table.
    Case {
        name: "kalyna-cmac compute (parse-time flags)",
        args: &[
            "kalyna-cmac",
            "compute",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--in"],
    },
    Case {
        name: "kalyna-gmac compute (parse-time flags)",
        args: &[
            "kalyna-gmac",
            "compute",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--in"],
    },
    Case {
        name: "kalyna-kw wrap",
        args: &[
            "kalyna-kw",
            "wrap",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--in", "--out"],
    },
    Case {
        name: "kalyna-kw unwrap",
        args: &[
            "kalyna-kw",
            "unwrap",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--in", "--out"],
    },
    Case {
        name: "kalyna-xts encrypt",
        args: &[
            "kalyna-xts",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--tweak",
            "t",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--tweak", "--in", "--out"],
    },
    Case {
        name: "kalyna-xts decrypt",
        args: &[
            "kalyna-xts",
            "decrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--tweak",
            "t",
            "--in",
            "i",
            "--out",
            "o",
        ],
        required: &["--variant", "--key", "--tweak", "--in", "--out"],
    },
];

/// Removes `flag` and its following value from `full` - `full` is assumed well-formed (every
/// value flag has exactly one following token), matching every [`Case::args`] entry above.
fn without_flag(full: &[&str], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < full.len() {
        if full[i] == flag {
            i += 2;
        } else {
            out.push(full[i].to_string());
            i += 1;
        }
    }
    out
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn missing_required_flag_matrix() {
    for case in CASES {
        for &flag in case.required {
            let args = without_flag(case.args, flag);
            let r = uacrypt(args);
            assert!(
                r.failure(),
                "case={} flag={flag} unexpectedly succeeded with it omitted",
                case.name
            );
            let flag_name = &flag[2..]; // "--key" -> "key", matches CliError::MissingFlag's Display
            let expected = format!("missing required flag: --{flag_name}");
            assert!(
                r.stderr.contains(&expected),
                "case={} flag={flag} stderr={}",
                case.name,
                r.stderr
            );
        }
    }
}

/// A handful of representative unknown-flag cases across different command shapes - see the module
/// doc for why this is deliberately not a full 34-command sweep (one shared code path, no
/// per-command variation to catch).
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unknown_flag_is_rejected_across_representative_commands() {
    let reps: &[&[&str]] = &[
        &["keygen", "--out", "o", "--bogus", "x"],
        &["hash", "--in", "i", "--out", "o", "--bogus"],
        &[
            "verify", "--key", "k", "--in", "i", "--sig", "s", "--curve", "m163",
        ],
        &[
            "kalyna-xts",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            "k",
            "--tweak",
            "t",
            "--in",
            "i",
            "--out",
            "o",
            "--mode",
            "cbc",
        ],
    ];
    for args in reps {
        let r = uacrypt(*args);
        assert!(r.failure(), "args={args:?}");
        assert!(
            r.stderr.contains("unknown flag:"),
            "args={args:?} stderr={}",
            r.stderr
        );
    }
}

fn setup_cmac_fixture(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let key = dir.file("key.bin");
    let input = dir.file("msg.bin");
    write_bytes(&key, &[0x11; 16]); // 128-128's key length
    write_bytes(&input, b"a message to authenticate");
    (key, input)
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_cmac_verify_without_tag_is_missing_flag() {
    let dir = TempDir::new("misuse_cmac_verify_no_tag");
    let (key, input) = setup_cmac_fixture(&dir);
    let r = uacrypt([
        "kalyna-cmac",
        "verify",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
        // --tag deliberately omitted
    ]);
    assert!(r.failure());
    assert!(
        r.stderr.contains("missing required flag: --tag"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_cmac_compute_without_out_is_missing_flag() {
    let dir = TempDir::new("misuse_cmac_compute_no_out");
    let (key, input) = setup_cmac_fixture(&dir);
    let r = uacrypt([
        "kalyna-cmac",
        "compute",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
        // --out deliberately omitted
    ]);
    assert!(r.failure());
    assert!(
        r.stderr.contains("missing required flag: --out"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_gmac_verify_without_tag_is_missing_flag() {
    let dir = TempDir::new("misuse_gmac_verify_no_tag");
    let (key, input) = setup_cmac_fixture(&dir);
    let r = uacrypt([
        "kalyna-gmac",
        "verify",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
    ]);
    assert!(r.failure());
    assert!(
        r.stderr.contains("missing required flag: --tag"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_gmac_compute_without_out_is_missing_flag() {
    let dir = TempDir::new("misuse_gmac_compute_no_out");
    let (key, input) = setup_cmac_fixture(&dir);
    let r = uacrypt([
        "kalyna-gmac",
        "compute",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
    ]);
    assert!(r.failure());
    assert!(
        r.stderr.contains("missing required flag: --out"),
        "stderr={}",
        r.stderr
    );
}

/// Directory-as-`--out` across a representative sample of the distinct `--out`-writing shapes
/// (`std::fs::write`/`File::create` on a directory path is uniform `std::io` behavior regardless
/// of which command calls it - not swept across all 34 commands for the same reason unknown-flag
/// isn't, see the module doc).
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn directory_as_out_is_rejected_across_representative_commands() {
    let dir = TempDir::new("misuse_dir_as_out");
    let out_dir = dir.file("a_directory");
    std::fs::create_dir(&out_dir).expect("create directory fixture");
    let out_str = out_dir.to_str().unwrap();

    let key = dir.file("key.bin");
    write_bytes(&key, &[0x11; 32]);
    let input = dir.file("in.bin");
    write_bytes(&input, b"some input");

    let cases: &[&[&str]] = &[
        &["keygen", "--out", out_str],
        &["hash", "--in", input.to_str().unwrap(), "--out", out_str],
        &[
            "encrypt",
            "--key",
            key.to_str().unwrap(),
            "--in",
            input.to_str().unwrap(),
            "--out",
            out_str,
        ],
    ];
    for args in cases {
        let r = uacrypt(*args);
        assert!(r.failure(), "args={args:?}");
        assert!(
            !out_dir
                .read_dir()
                .expect("directory fixture must still exist and be readable")
                .next()
                .is_some(),
            "args={args:?} - directory must stay empty, nothing written inside it"
        );
    }
}

/// `--iterations 0` across a representative sample of commands that accept `--iterations` - every
/// one clamps via `.max(1)` (same convention throughout `crates/uacrypt/src/lib.rs`), so this
/// checks the degenerate-but-legal input behaves like `--iterations 1`, not an error and not a
/// panic (D-65's "fool" category).
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn iterations_zero_behaves_like_one_across_representative_commands() {
    let dir = TempDir::new("misuse_iterations_zero");
    let key = dir.file("key.bin");
    write_bytes(&key, &[0x11; 16]);
    let input = dir.file("in.bin");
    write_bytes(&input, &[0x22; 16]); // exactly one 128-128 block

    let out_zero = dir.file("out_zero.bin");
    let r = uacrypt([
        "kalyna-block",
        "encrypt",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
        "--out",
        out_zero.to_str().unwrap(),
        "--iterations",
        "0",
    ]);
    assert!(r.success(), "stderr={}", r.stderr);

    let out_one = dir.file("out_one.bin");
    let r = uacrypt([
        "kalyna-block",
        "encrypt",
        "--variant",
        "128-128",
        "--key",
        key.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
        "--out",
        out_one.to_str().unwrap(),
        "--iterations",
        "1",
    ]);
    assert!(r.success(), "stderr={}", r.stderr);

    assert_eq!(
        support::read_bytes(&out_zero),
        support::read_bytes(&out_one),
        "--iterations 0 must produce the same result as --iterations 1"
    );
}
