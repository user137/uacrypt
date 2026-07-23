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
         \x20 fuzz           short cargo-fuzz smoke run against the kupyna/kalyna/kalyna_ccm/strumok targets\n\
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
    // Note (see TASKS.md "Testing & hardening", DECISIONS.md D-32): libFuzzer-on-Windows only
    // works with the MSVC target, not this project's default GNU host toolchain - a real, confirmed
    // upstream limitation, not a bug here. On Linux/macOS the native toolchain already supports
    // ASan, so this runs directly; on Windows it additionally needs a nightly-x86_64-pc-windows-msvc
    // rustup toolchain plus a Visual Studio C++ toolset (for `link.exe` and the ASan runtime DLL,
    // both only on PATH once `vcvars64.bat` is sourced) - genuinely separate tools, not just a cargo
    // target add, so this is the one other real per-OS branch in this file (see the `mvn`/`mvn.cmd`
    // one in `command_for`).
    #[cfg(windows)]
    {
        fuzz_windows_msvc()
    }
    #[cfg(not(windows))]
    {
        fuzz_targets(&["cargo", "+nightly", "fuzz", "run"])
    }
}

#[cfg(not(windows))]
fn fuzz_targets(prefix: &[&str]) -> bool {
    for target in ["kupyna", "kalyna", "kalyna_ccm", "strumok"] {
        let mut args = prefix.to_vec();
        args.push(target);
        args.extend(["--", "-max_total_time=60"]);
        let ok = run(args[0], &args[1..], Some(Path::new("crates/dstu-core")));
        if !ok {
            return false;
        }
    }
    true
}

/// Finds `vcvars64.bat` via `vswhere.exe`'s fixed, well-known install path (itself not on PATH,
/// same reason `command_for` special-cases `mvn.cmd` - a Windows tool that isn't just `cargo`).
#[cfg(windows)]
fn find_vcvars64() -> Option<String> {
    let vswhere = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe";
    if !Path::new(vswhere).exists() {
        return None;
    }
    let output = Command::new(vswhere)
        .args(["-latest", "-property", "installationPath"])
        .output()
        .ok()?;
    let install_path = String::from_utf8(output.stdout).ok()?;
    let install_path = install_path.trim();
    if install_path.is_empty() {
        return None;
    }
    let vcvars = format!(r"{install_path}\VC\Auxiliary\Build\vcvars64.bat");
    Path::new(&vcvars).exists().then_some(vcvars)
}

#[cfg(windows)]
fn rustup_toolchain_installed(name: &str) -> bool {
    Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|line| line.starts_with(name))
        })
}

#[cfg(windows)]
fn fuzz_windows_msvc() -> bool {
    use std::os::windows::process::CommandExt;

    let Some(vcvars) = find_vcvars64() else {
        eprintln!(
            "xtask: no Visual Studio C++ toolset found (vswhere.exe absent or reported nothing) \
             - skipping fuzz.\n  install: Visual Studio Build Tools, \"Desktop development with \
             C++\" workload"
        );
        return false;
    };
    const MSVC_TOOLCHAIN: &str = "nightly-x86_64-pc-windows-msvc";
    if !rustup_toolchain_installed(MSVC_TOOLCHAIN) {
        eprintln!(
            "xtask: rustup toolchain '{MSVC_TOOLCHAIN}' not installed - skipping fuzz.\n  install \
             with: rustup toolchain install {MSVC_TOOLCHAIN}"
        );
        return false;
    }
    for target in ["kupyna", "kalyna", "kalyna_ccm", "strumok"] {
        let inner = format!(
            "cargo +{MSVC_TOOLCHAIN} fuzz run --target x86_64-pc-windows-msvc {target} -- \
             -max_total_time=60"
        );
        let full = format!("call \"{vcvars}\" >nul && {inner}");
        println!("+ cmd /C {full}");
        // `raw_arg` (not `arg`/`args`) is load-bearing here: `full` already contains its own
        // `"..."` quoting for cmd.exe's parser (around the vcvars path, which has spaces).
        // Rust's normal Windows argument quoting would re-escape those embedded quotes and
        // corrupt the command line - confirmed by hitting exactly that ("is not recognized as an
        // internal or external command") before switching to `raw_arg`.
        let mut command = Command::new("cmd");
        command.arg("/C");
        command.raw_arg(&full);
        command.current_dir("crates/dstu-core");
        let ok = command.status().is_ok_and(|s| s.success());
        if !ok {
            return false;
        }
    }
    true
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
    // `OracleHarness.findVectorsDir()` resolves a relative `../../../crates/...` path assuming
    // its cwd is this project directory - true for a plain `mvn` invocation from inside it, but
    // NOT for `mvn -f tests/oracle-harness/java/pom.xml ...` run from the repo root: `-f` only
    // selects which POM to build, it doesn't relocate exec:java's forked JVM's working directory.
    // Confirmed the hard way: `-f` from the repo root resolved the vectors path to a
    // nonexistent location outside the repo (`NoSuchFileException`), while `cd`-ing into the
    // project directory first and running plain `mvn -q compile exec:java` worked. Passing this
    // as `dir` (not `-f`) fixes it for both invocation shapes.
    run(
        "mvn",
        &["-q", "compile", "exec:java"],
        Some(Path::new("tests/oracle-harness/java")),
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
