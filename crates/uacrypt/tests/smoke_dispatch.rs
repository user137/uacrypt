//! T-200 Phase 1: top-level dispatch smoke tests - exit codes, stdout/stderr routing, and the
//! `uacrypt: ` error prefix `main.rs` adds (17 lines, previously exercised by *zero* tests - every
//! existing `#[test]` in `crates/uacrypt/src/lib.rs` calls `run()` in-process and only ever
//! asserts on the library's own `Result`, never on what a real process exit code/stderr consumer
//! actually sees).

mod support;
use support::uacrypt;

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn no_args_prints_top_level_help_and_exits_success() {
    let r = uacrypt(Vec::<&str>::new());
    assert!(r.success(), "code={:?} stderr={}", r.code, r.stderr);
    assert!(r.stdout.contains("uacrypt - a CLI over dstu-core"));
    assert!(r.stdout.contains("USAGE:"));
    assert_eq!(r.stderr, "");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn help_long_flag_prints_top_level_help() {
    let r = uacrypt(["--help"]);
    assert!(r.success());
    assert!(r.stdout.contains("USAGE:"));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn help_short_flag_prints_top_level_help() {
    let r = uacrypt(["-h"]);
    assert!(r.success());
    assert!(r.stdout.contains("USAGE:"));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn version_long_flag_prints_version_and_exits_success() {
    let r = uacrypt(["--version"]);
    assert!(r.success());
    assert!(r.stdout.starts_with("uacrypt "));
    assert_eq!(r.stderr, "");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn version_short_flag_matches_long_flag() {
    let long = uacrypt(["--version"]);
    let short = uacrypt(["-V"]);
    assert_eq!(long.stdout, short.stdout);
    assert!(short.success());
}

/// The one thing genuinely new here vs. the in-process suite: `main.rs`'s own `ExitCode::FAILURE`
/// mapping and its `"uacrypt: {e}"` stderr prefix, exercised by a real process for the first time.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unknown_command_exits_failure_with_prefixed_stderr() {
    let r = uacrypt(["nonexistent-command"]);
    assert!(r.failure(), "code={:?} stdout={}", r.code, r.stdout);
    assert_eq!(r.code, Some(1));
    assert!(
        r.stderr
            .contains("uacrypt: unknown command: nonexistent-command"),
        "stderr={}",
        r.stderr
    );
    assert_eq!(r.stdout, "");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_block_with_no_subcommand_reports_missing_flag() {
    let r = uacrypt(["kalyna-block"]);
    assert!(r.failure());
    assert!(
        r.stderr
            .contains("uacrypt: missing required flag: --encrypt|decrypt"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_block_with_unknown_subcommand_is_unknown_command() {
    let r = uacrypt(["kalyna-block", "frobnicate"]);
    assert!(r.failure());
    assert!(
        r.stderr
            .contains("uacrypt: unknown command: kalyna-block frobnicate"),
        "stderr={}",
        r.stderr
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn kalyna_block_help_shows_command_specific_text_not_top_level() {
    let r = uacrypt(["kalyna-block", "--help"]);
    assert!(r.success());
    assert!(r.stdout.contains("kalyna-block"));
    assert!(!r.stdout.contains("USAGE:\n    uacrypt <command> [flags]"));
}

/// `is_help_flag` is checked against *every* remaining token, not just the first - a `--help`
/// buried after other flags must still short-circuit before a missing-flag error, per the
/// project's own doc comment on `is_help_flag`.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn help_flag_takes_priority_over_missing_required_flags() {
    let r = uacrypt([
        "kalyna-block",
        "encrypt",
        "--key",
        "nonexistent.bin",
        "--help",
    ]);
    assert!(r.success(), "code={:?} stderr={}", r.code, r.stderr);
    assert!(r.stdout.contains("kalyna-block"));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn unknown_top_level_flag_before_any_command_is_unknown_command() {
    let r = uacrypt(["--frobnicate"]);
    assert!(r.failure());
    assert!(
        r.stderr.contains("uacrypt: unknown command: --frobnicate"),
        "stderr={}",
        r.stderr
    );
}
