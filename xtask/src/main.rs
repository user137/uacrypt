//! Thin cross-platform build/QA runner, invoked as `cargo xtask <command>` (see the alias in
//! `.cargo/config.toml`). Exists so a developer on Linux/Windows/macOS runs the *same* command
//! instead of three different shell dialects. Deliberately zero dependencies and deliberately
//! thin: every subcommand just shells out to a tool that's already documented in README.md /
//! SECURITY.md, and checks the tool is present first so a missing optional tool (miri, cargo-fuzz,
//! cargo-audit, cargo-deny, Maven, the .NET SDK) prints an install hint instead of a raw OS error.
//! Kept out of the main Cargo workspace (own `[workspace]` table above) so this dev-only tool never
//! shows up in `dstu-core`'s dependency graph that `deny.toml`/`SECURITY.md` are policing.

use std::env;
use std::path::Path;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage();
        return ExitCode::FAILURE;
    };

    let ok = match cmd.as_str() {
        "build" => build(),
        "test" => test(),
        "fmt" => fmt(args.any(|a| a == "--check")),
        "clippy" => clippy(),
        "miri" => miri(),
        "fuzz" => fuzz(),
        "audit" => audit(),
        "deny" => deny(),
        "oracle-java" => oracle_java(),
        "oracle-dotnet" => oracle_dotnet(),
        "ci" => ci(),
        "help" | "-h" | "--help" => {
            print_usage();
            true
        }
        other => {
            eprintln!("xtask: unknown command '{other}'\n");
            print_usage();
            false
        }
    };

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_usage() {
    eprintln!(
        "cargo xtask <command>\n\n\
         Always available (only need cargo/rustup, see README.md \"Building from source\"):\n\
         \x20 build          cargo build --workspace, both --all-features and --no-default-features (no_std check)\n\
         \x20 test           cargo test --workspace --all-features\n\
         \x20 fmt [--check]  cargo fmt --all, or --check to verify without writing\n\
         \x20 clippy         cargo clippy --workspace --all-features -- -D warnings\n\
         \x20 ci             fmt --check + build + test + clippy, then best-effort for the optional tools below\n\n\
         Optional (each checks its tool is installed first and prints an install hint if not):\n\
         \x20 miri           cargo +nightly miri test --workspace\n\
         \x20 fuzz           short cargo-fuzz smoke run against the kupyna target\n\
         \x20 audit          cargo audit (RustSec advisories)\n\
         \x20 deny           cargo deny check (licenses, bans, sources)\n\
         \x20 oracle-java    run the Java/Bouncy Castle oracle harness via Maven\n\
         \x20 oracle-dotnet  run the .NET/Bouncy Castle oracle harness via dotnet run"
    );
}

/// Windows Maven ships `mvn.cmd`, not `mvn` - `Command::new` doesn't resolve batch-script
/// extensions the way a shell does, so this is the one real per-OS branch in this whole file.
fn command_for(base: &str) -> String {
    if cfg!(windows) && base == "mvn" {
        format!("{base}.cmd")
    } else {
        base.to_string()
    }
}

fn tool_available(base: &str) -> bool {
    Command::new(command_for(base))
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn run(base: &str, args: &[&str], dir: Option<&Path>) -> bool {
    let mut command = Command::new(command_for(base));
    command.args(args);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    println!("+ {base} {}", args.join(" "));
    command.status().is_ok_and(|s| s.success())
}

fn require(tool: &str, install_hint: &str) -> bool {
    if tool_available(tool) {
        return true;
    }
    eprintln!("xtask: '{tool}' not found on PATH - skipping.\n  install with: {install_hint}");
    false
}

fn build() -> bool {
    run("cargo", &["build", "--workspace", "--all-features"], None)
        && run(
            "cargo",
            &["build", "--workspace", "--no-default-features"],
            None,
        )
}

fn test() -> bool {
    run("cargo", &["test", "--workspace", "--all-features"], None)
}

fn fmt(check: bool) -> bool {
    let mut args = vec!["fmt", "--all"];
    if check {
        args.extend(["--", "--check"]);
    }
    run("cargo", &args, None)
}

fn clippy() -> bool {
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        None,
    )
}

fn miri() -> bool {
    if !require(
        "cargo-miri",
        "rustup component add miri --toolchain nightly",
    ) {
        return false;
    }
    run("cargo", &["+nightly", "miri", "test", "--workspace"], None)
}

fn fuzz() -> bool {
    if !require("cargo-fuzz", "cargo install cargo-fuzz --locked") {
        return false;
    }
    run(
        "cargo",
        &[
            "+nightly",
            "fuzz",
            "run",
            "kupyna",
            "--",
            "-max_total_time=60",
        ],
        Some(Path::new("crates/dstu-core")),
    )
}

fn audit() -> bool {
    if !require("cargo-audit", "cargo install cargo-audit --locked") {
        return false;
    }
    run("cargo", &["audit"], None)
}

fn deny() -> bool {
    if !require("cargo-deny", "cargo install cargo-deny --locked") {
        return false;
    }
    run("cargo", &["deny", "check"], None)
}

fn oracle_java() -> bool {
    if !require("mvn", "see README.md \"Building from source\" (Maven)") {
        return false;
    }
    run(
        "mvn",
        &[
            "-f",
            "tests/oracle-harness/java/pom.xml",
            "-q",
            "compile",
            "exec:java",
        ],
        None,
    )
}

fn oracle_dotnet() -> bool {
    if !require("dotnet", "https://dotnet.microsoft.com/download") {
        return false;
    }
    run(
        "dotnet",
        &[
            "run",
            "--project",
            "tests/oracle-harness/dotnet/oracle-harness.csproj",
        ],
        None,
    )
}

/// Mirrors `.github/workflows/rust.yml`'s mandatory `test` job exactly, then best-effort runs the
/// optional layers (miri/fuzz/audit/deny/oracle harnesses) - missing tools are reported, not fatal,
/// so this is useful on a fresh machine that only has `cargo` so far, not just full CI runners.
fn ci() -> bool {
    let mandatory = fmt(true) && build() && test() && clippy();
    if !mandatory {
        return false;
    }

    println!("\nMandatory checks passed. Running optional layers best-effort:\n");
    for optional in [miri, fuzz, audit, deny, oracle_java, oracle_dotnet] {
        optional();
    }
    true
}
