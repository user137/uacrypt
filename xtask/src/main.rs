//! Thin cross-platform build/QA runner, invoked as `cargo xtask <command>` (see the alias in
//! `.cargo/config.toml`). Exists so a developer on Linux/Windows/macOS runs the *same* command
//! instead of three different shell dialects. Deliberately zero dependencies and deliberately
//! thin: every subcommand just shells out to a tool that's already documented in README.md /
//! docs/SECURITY.md, and checks the tool is present first so a missing optional tool (miri, kani,
//! cargo-fuzz, cargo-audit, cargo-deny, Maven, the .NET SDK, maturin/pytest) prints an install hint
//! instead of a raw OS error.
//! Kept out of the main Cargo workspace (own `[workspace]` table above) so this dev-only tool never
//! shows up in `dstu-core`'s dependency graph that `deny.toml`/`docs/SECURITY.md` are policing.

use std::env;
use std::path::{Path, PathBuf};
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
        "kani" => kani(),
        "fuzz" => fuzz(),
        "audit" => audit(),
        "deny" => deny(),
        "oracle-java" => oracle_java(),
        "oracle-dotnet" => oracle_dotnet(),
        "python" => python(),
        "nodejs" => nodejs(),
        "ruby" => ruby(),
        "php" => php(),
        "capi" => capi(),
        "dotnet" => dotnet(),
        "java" => java(),
        "go" => go(),
        "qemu-stm32" => qemu_stm32(),
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
         \x20 build          cargo build --workspace, --all-features + --no-default-features (no_std check) + dstu-core's no_std/getrandom combo (D-74)\n\
         \x20 test           cargo test --workspace --all-features\n\
         \x20 fmt [--check]  cargo fmt --all, or --check to verify without writing\n\
         \x20 clippy         cargo clippy --workspace --all-features -- -D warnings\n\
         \x20 ci             fmt --check + build + test + clippy, then best-effort for the optional tools below\n\n\
         Optional (each checks its tool is installed first and prints an install hint if not):\n\
         \x20 miri           cargo +nightly miri test --workspace\n\
         \x20 kani           cargo kani -p dstu-core (bounded model checking, see gf2m163.rs's kani_proofs, D-102) - Linux/macOS only, not Windows\n\
         \x20 fuzz           short cargo-fuzz smoke run against every target (see FUZZ_TARGETS)\n\
         \x20 audit          cargo audit (RustSec advisories)\n\
         \x20 deny           cargo deny check (licenses, bans, sources)\n\
         \x20 oracle-java    run the Java/Bouncy Castle oracle harness via Maven\n\
         \x20 oracle-dotnet  run the .NET/Bouncy Castle oracle harness via dotnet run\n\
         \x20 python         build+lint bindings/python, maturin develop, pytest (T-49)\n\
         \x20 nodejs         build+lint bindings/nodejs, napi build, node --test (T-50)\n\
         \x20 ruby           build+lint bindings/ruby, rake compile, rspec (T-160)\n\
         \x20 php            build+lint bindings/php, cargo build, phpunit (T-159)\n\
         \x20 capi           regenerate+diff include/dstu_core.h, compile+run the C test harness and examples (T-158)\n\
         \x20 dotnet         dotnet format --verify-no-changes, dotnet test bindings/dotnet (T-52)\n\
         \x20 java           build+lint bindings/java/native, mvn test bindings/java (T-51) - needs a JDK 11+ (17 recommended, D-153)\n\
         \x20 go             build dstu-core-capi, gofmt -l + go vet + go test bindings/go (T-163)\n\
         \x20 qemu-stm32     run firmware/qemu-stm32-smoketest under QEMU's netduinoplus2 (Cortex-M4F), no real hardware needed (T-170)"
    );
}

/// Windows Maven/npm ship `mvn.cmd`/`npm.cmd`, RubyGems' `bundle` ships `bundle.bat` - none of them
/// `mvn`/`npm`/`bundle` bare, and `Command::new` doesn't resolve batch-script extensions the way a
/// shell does, so this is the one real per-OS branch in this whole file (confirmed for `npm`/
/// `bundle` the same way `mvn` was: a bare `Command::new(...)` reports "not found on PATH" despite
/// the plain command working fine directly in a real shell).
fn command_for(base: &str) -> String {
    if cfg!(windows) && (base == "mvn" || base == "npm") {
        format!("{base}.cmd")
    } else if cfg!(windows) && base == "bundle" {
        format!("{base}.bat")
    } else {
        base.to_string()
    }
}

fn tool_available(base: &str) -> bool {
    // `go` has no `--version` flag (only the `version` subcommand) and exits nonzero on an
    // unrecognized flag, unlike every other tool this checks - confirmed the hard way running
    // `cargo xtask go` for the first time (T-163): `go --version` printed the top-level help text
    // and returned exit code 2.
    let version_arg = if base == "go" { "version" } else { "--version" };
    Command::new(command_for(base))
        .arg(version_arg)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `dir` is only ever a binding subdirectory that may carry its own `rustup override` (Node's
/// MSVC pin, PHP's nightly-MSVC pin, D-130/D-146) distinct from the repo root's own toolchain.
/// `RUSTUP_TOOLCHAIN` is removed from the child's environment in that case - confirmed the hard
/// way (D-146): `cargo xtask php` itself runs under a rustup-resolved `cargo`, which sets
/// `RUSTUP_TOOLCHAIN` for its own process before this xtask binary ever starts; that env var is
/// inherited by every child process spawned here and - per the same precedence rule CLAUDE.md
/// already documents for a `rust-toolchain.toml` (D-141) - overrides a directory-based `rustup
/// override set` outright. Without this, a nested `cargo build`/`clippy` inside `bindings/php`
/// silently used the repo root's own default GNU-host toolchain instead of the directory's pinned
/// `nightly-x86_64-pc-windows-msvc`, producing a real build failure (ext-php-rs's `wrapper.c`
/// compiled with `gcc` against PHP's MSVC-only devel-pack headers - `__forceinline`/
/// `_InterlockedExchange8`/`pid_t` conflicts) that a direct manual `cd bindings/php && cargo
/// build` never reproduced, since a plain shell invocation has no inherited `RUSTUP_TOOLCHAIN` to
/// begin with.
fn run(base: &str, args: &[&str], dir: Option<&Path>) -> bool {
    let mut command = Command::new(command_for(base));
    command.args(args);
    if let Some(dir) = dir {
        command.current_dir(dir);
        command.env_remove("RUSTUP_TOOLCHAIN");
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
        // `getrandom` feature (docs/DECISIONS.md D-74, docs/TASKS.md T-123): `--all-features` above already
        // covers it combined with `std`, but this is the one combination that proves `randombytes`
        // reaches a bare `no_std` build without `std`/`alloc` at all - not covered by either call
        // above.
        && run(
            "cargo",
            &[
                "build",
                "-p",
                "dstu-core",
                "--no-default-features",
                "--features",
                "getrandom",
            ],
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

/// Bounded model checking (`kani_proofs` mod in `gf2m163.rs`, `docs/DECISIONS.md` D-102) - unlike
/// every other optional tool in this file, Kani genuinely cannot run on Windows at all: confirmed
/// by trying `cargo install kani-verifier` here, whose own source calls Unix-only std APIs
/// (`std::os::unix::fs::symlink`, `Command::arg0`) that don't exist on this platform - not a
/// missing-install-step case `require`'s generic message would describe accurately.
fn kani() -> bool {
    #[cfg(windows)]
    {
        eprintln!(
            "xtask: 'cargo kani' does not support Windows - kani-verifier's own source requires \
             Unix-only std APIs, confirmed by trying to install it here (docs/DECISIONS.md D-102). \
             CI (Linux) is the actual, unconditional venue for this - see the `kani` job in \
             rust.yml."
        );
        false
    }
    #[cfg(not(windows))]
    {
        if !require("cargo-kani", "cargo install kani-verifier && cargo kani setup") {
            return false;
        }
        run("cargo", &["kani", "-p", "dstu-core"], None)
    }
}

fn fuzz() -> bool {
    if !require("cargo-fuzz", "cargo install cargo-fuzz --locked") {
        return false;
    }
    // Note (see docs/TASKS.md "Testing & hardening", docs/DECISIONS.md D-32): libFuzzer-on-Windows only
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

/// Kept in sync by hand with `crates/dstu-core/fuzz/Cargo.toml`'s `[[bin]]` entries and
/// `.github/workflows/rust.yml`'s `fuzz-smoke` matrix (T-98) - no single source of truth cargo
/// exposes for "every fuzz target name" short of parsing that file. Used on both platforms
/// (`fuzz_targets` below and `fuzz_windows_msvc` further down).
const FUZZ_TARGETS: [&str; 10] = [
    "kupyna",
    "kalyna",
    "kalyna_ccm",
    "strumok",
    "kalyna_cmac",
    "kalyna_kw",
    "kalyna_gcm",
    "kalyna_gmac",
    "kalyna_cfb",
    "crypto_secretstream",
];

#[cfg(not(windows))]
fn fuzz_targets(prefix: &[&str]) -> bool {
    for target in FUZZ_TARGETS {
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
    for target in FUZZ_TARGETS {
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
        && run("cargo", &["audit"], Some(Path::new("bindings/python")))
        && run("cargo", &["audit"], Some(Path::new("bindings/nodejs")))
        && run("cargo", &["audit"], Some(Path::new("bindings/ruby")))
        && run("cargo", &["audit"], Some(Path::new("bindings/php")))
}

/// `bindings/python`/`bindings/nodejs` are separate Cargo workspaces (D-119), but deliberately
/// share the root `deny.toml` rather than duplicating one - cargo-deny walks up from its cwd
/// looking for the config file, so running with either as cwd finds the same root policy and
/// checks that workspace's own dependency tree against it. Confirmed by running it, not assumed -
/// it also caught a real wildcard-dependency bug (missing `version =` on the `dstu-core` path
/// dependency, the exact T-75/D-11 failure mode) the first time this was tried for Python.
fn deny() -> bool {
    if !require("cargo-deny", "cargo install cargo-deny --locked") {
        return false;
    }
    run("cargo", &["deny", "check"], None)
        && run(
            "cargo",
            &["deny", "check"],
            Some(Path::new("bindings/python")),
        )
        && run(
            "cargo",
            &["deny", "check"],
            Some(Path::new("bindings/nodejs")),
        )
        && run(
            "cargo",
            &["deny", "check"],
            Some(Path::new("bindings/ruby")),
        )
        && run("cargo", &["deny", "check"], Some(Path::new("bindings/php")))
}

/// Best-effort like miri/fuzz/audit (D-12) - `bindings/python`'s own separate Cargo workspace
/// (D-119) isn't reached by `build`/`test`/`clippy`/`fmt` above. Builds `uacrypt` first (release,
/// from the repo root) since `tests/test_secretstream.py`'s interop test silently *skips* rather
/// than fails when the binary isn't found - skipping that check here would be a green-but-vacuous
/// run of exactly the wire-format coverage that justifies the binding existing.
fn python() -> bool {
    if !require(
        "maturin",
        "pip install maturin (see bindings/python/pyproject.toml's dev group)",
    ) {
        return false;
    }
    if !require(
        "pytest",
        "pip install pytest (see bindings/python/pyproject.toml's dev group)",
    ) {
        return false;
    }
    let dir = Path::new("bindings/python");
    run("cargo", &["build", "-p", "uacrypt", "--release"], None)
        && run("cargo", &["fmt", "--all", "--", "--check"], Some(dir))
        && run(
            "cargo",
            &["clippy", "--all-targets", "--", "-D", "warnings"],
            Some(dir),
        )
        && run("maturin", &["develop", "--release"], Some(dir))
        && run("pytest", &["-ra"], Some(dir))
}

/// Best-effort like python() above - bindings/nodejs's own separate Cargo workspace (D-119) isn't
/// reached by build/test/clippy/fmt. Builds uacrypt first (release, from the repo root) for
/// test/secretstream.test.js's real interop check, same D-124 reasoning as python()'s own step.
/// The MSVC-toolchain quirk this crate needs on some Windows dev machines (D-125/D-130) is a
/// machine-local `rustup override`, not anything this function or CI needs to special-case.
fn nodejs() -> bool {
    if !require("npm", "https://nodejs.org (npm ships with Node.js)") {
        return false;
    }
    let dir = Path::new("bindings/nodejs");
    run("cargo", &["build", "-p", "uacrypt", "--release"], None)
        && run("npm", &["install"], Some(dir))
        && run("cargo", &["fmt", "--all", "--", "--check"], Some(dir))
        && run(
            "cargo",
            &["clippy", "--all-targets", "--", "-D", "warnings"],
            Some(dir),
        )
        && run("npm", &["run", "build"], Some(dir))
        && run("npm", &["test"], Some(dir))
}

/// Best-effort like python()/nodejs() above - bindings/ruby's own separate Cargo workspace
/// (D-119, split across two Cargo.toml files rather than one, D-133) isn't reached by
/// build/test/clippy/fmt. Builds uacrypt first (release, from the repo root) for the real
/// `uacrypt.exe` interop check inside the RSpec suite. This machine's own `LIBCLANG_PATH`
/// mingw/bindgen requirement (D-133) is a machine-local environment variable - see
/// `.claude.local.md` - not anything this function or CI needs to special-case.
fn ruby() -> bool {
    if !require("ruby", "https://www.ruby-lang.org (or RubyInstaller with DevKit on Windows)") {
        return false;
    }
    if !require("bundle", "gem install bundler") {
        return false;
    }
    let dir = Path::new("bindings/ruby");
    run("cargo", &["build", "-p", "uacrypt", "--release"], None)
        && run("bundle", &["install"], Some(dir))
        && run("cargo", &["fmt", "--all", "--", "--check"], Some(dir))
        && run(
            "cargo",
            &["clippy", "--all-targets", "--", "-D", "warnings"],
            Some(dir),
        )
        && run("bundle", &["exec", "rake", "compile"], Some(dir))
        && run("bundle", &["exec", "rubocop"], Some(dir))
        && run("bundle", &["exec", "rspec"], Some(dir))
}

/// Best-effort like python()/nodejs()/ruby() above - bindings/php's own separate Cargo workspace
/// (D-119) isn't reached by build/test/clippy/fmt. Builds uacrypt first (release, from the repo
/// root) for the real `uacrypt.exe` interop check inside the PHPUnit suite. PHPUnit itself ships
/// as a standalone PHAR (`bindings/php/phpunit.phar`, gitignored) rather than a Composer
/// dependency - this binding has no other Composer-managed dependency to justify adding Composer
/// as a second PHP toolchain requirement just for a test runner (docs/DECISIONS.md D-145).
fn php() -> bool {
    if !require(
        "php",
        "https://windows.php.net or your OS package manager (PHP 8.1+, ext-php-rs's own floor)",
    ) {
        return false;
    }
    let dir = Path::new("bindings/php");
    let phpunit = dir.join("phpunit.phar");
    if !phpunit.is_file() {
        eprintln!(
            "xtask: '{}' not found - install with: curl -sL https://phar.phpunit.de/phpunit-11.phar -o {}",
            phpunit.display(),
            phpunit.display()
        );
        return false;
    }

    let build_ok = run("cargo", &["build", "-p", "uacrypt", "--release"], None)
        && run("cargo", &["fmt", "--all", "--", "--check"], Some(dir))
        && run(
            "cargo",
            &["clippy", "--all-targets", "--", "-D", "warnings"],
            Some(dir),
        )
        && run("cargo", &["build"], Some(dir));
    if !build_ok {
        return false;
    }

    let Some(ext_path) = php_extension_path(dir) else {
        eprintln!(
            "xtask: could not find the built dstu_core_php extension under {}/target/debug",
            dir.display()
        );
        return false;
    };
    // Absolute-ify manually rather than via `Path::canonicalize()` - `run`'s own `php` invocation
    // sets its cwd to `dir` itself, so a path already prefixed with `dir` (as `php_extension_path`
    // returns) would otherwise be resolved a second time relative to that same `dir`, doubling the
    // prefix and failing to load (confirmed by a real "Unable to load dynamic library" failure,
    // not assumed). `canonicalize()` was tried first and rejected: on Windows it prepends the
    // `\\?\` extended-length-path prefix, which this exact PHP build's own library loader doesn't
    // accept (a second real failure, not assumed) - prepending the current directory manually
    // avoids that prefix entirely.
    let Ok(cwd) = env::current_dir() else {
        eprintln!("xtask: could not determine the current directory");
        return false;
    };
    let ext_path = cwd.join(ext_path);
    run(
        "php",
        &[&format!("-dextension={}", ext_path.display()), "phpunit.phar"],
        Some(dir),
    )
}

/// Locates the compiled extension's platform-specific filename under `target/debug` -
/// `dstu_core_php.dll` (Windows), `libdstu_core_php.so` (Linux). macOS's own Cargo `cdylib`
/// default produces `libdstu_core_php.dylib`, but PHP's `extension=` loader conventionally expects
/// a `.so` suffix even on macOS - a real, documented quirk in the Rust-PHP-extension ecosystem
/// (`cargo-php`/`ext-php-rs`'s own install tooling renames it). Checks both suffixes on macOS since
/// this dev machine is Windows-only and the rename step is not yet confirmed here - see
/// `docs/DECISIONS.md` D-145, `bindings-php.yml`'s own macOS step handles the rename explicitly.
fn php_extension_path(dir: &Path) -> Option<std::path::PathBuf> {
    let debug = dir.join("target").join("debug");
    let candidates: &[&str] = if cfg!(windows) {
        &["dstu_core_php.dll"]
    } else if cfg!(target_os = "macos") {
        &["libdstu_core_php.so", "libdstu_core_php.dylib"]
    } else {
        &["libdstu_core_php.so"]
    };
    candidates
        .iter()
        .map(|name| debug.join(name))
        .find(|p| p.is_file())
}

/// `crates/dstu-core-capi` IS a real root-workspace member (D-119/D-148 point 6, unlike Python/
/// Node/Ruby/PHP) - `build`/`test`/`clippy`/`fmt` above already cover its Rust-side correctness
/// for free via their existing `--workspace` flags. This function only needs the C-toolchain-
/// dependent part `--workspace` can't reach: (1) regenerate the header via `cbindgen` into a temp
/// path and diff it against the committed copy (same drift-detection shape as the T-120/D-75
/// README-vs-doctest check), failing loudly on drift; (2) compile and run the plain-C test
/// harness against the just-built cdylib; (3) compile and run the C examples (deterministic,
/// side-effect-free, safe to run here rather than just compile).
fn capi() -> bool {
    if !require("cbindgen", "cargo install cbindgen --locked") {
        return false;
    }
    if !capi_header_up_to_date() {
        return false;
    }
    if !run(
        "cargo",
        &["build", "-p", "dstu-core-capi", "--release"],
        None,
    ) {
        return false;
    }

    let harness = Path::new("crates/dstu-core-capi/c-tests/test_capi.c");
    if !capi_run_c_program(harness, "capi_test_capi") {
        return false;
    }
    for name in CAPI_EXAMPLES {
        let src = PathBuf::from(format!("crates/dstu-core-capi/examples/{name}.c"));
        if !capi_run_c_program(&src, &format!("capi_example_{name}")) {
            return false;
        }
    }
    true
}

/// Kept in sync by hand with `crates/dstu-core-capi/examples/*.c` - no single source of truth for
/// "every example name" short of listing the directory, same manual-sync tradeoff `FUZZ_TARGETS`
/// already accepts.
const CAPI_EXAMPLES: [&str; 4] = ["secretbox", "secretstream_file", "sign", "misc"];

/// Regenerates `include/dstu_core.h` into a temp path and diffs it byte-for-byte against the
/// committed copy - fails loudly (not silently) on drift, the same shape T-120/D-75 already uses
/// for the Python README-vs-doctest check.
fn capi_header_up_to_date() -> bool {
    let dir = Path::new("crates/dstu-core-capi");
    let committed = dir.join("include/dstu_core.h");
    let tmp = env::temp_dir().join("dstu_core_capi_header_check.h");
    let tmp_str = tmp.display().to_string();
    if !run(
        "cbindgen",
        &["--config", "cbindgen.toml", "--output", &tmp_str],
        Some(dir),
    ) {
        return false;
    }

    let generated = match std::fs::read_to_string(&tmp) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "xtask: could not read cbindgen's generated header at {}: {e}",
                tmp.display()
            );
            return false;
        }
    };
    let _ = std::fs::remove_file(&tmp);
    let committed_contents = match std::fs::read_to_string(&committed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "xtask: could not read committed header {}: {e}",
                committed.display()
            );
            return false;
        }
    };
    // Normalize CRLF -> LF before comparing: a Windows/macOS CI checkout applies git's own
    // core.autocrlf translation to the *committed* file's line endings (the same false-positive
    // rust.yml's own fmt job already documents), while cbindgen always writes LF (its own default,
    // confirmed in its source) regardless of host OS - an unnormalized comparison would report
    // drift on every CI Windows/macOS run even with a byte-identical header.
    let generated_normalized = generated.replace("\r\n", "\n");
    let committed_normalized = committed_contents.replace("\r\n", "\n");
    if generated_normalized != committed_normalized {
        eprintln!(
            "xtask: {} is out of date relative to the crate's own extern \"C\" surface - \
             regenerate with `cbindgen --config cbindgen.toml --output include/dstu_core.h` (run \
             from crates/dstu-core-capi) and commit the diff",
            committed.display()
        );
        return false;
    }
    true
}

/// The just-built shared library's platform-specific filename under `target/release` - matches
/// `php_extension_path`'s own per-OS convention above (macOS `cdylib` default is `.dylib`, no
/// PHP-style `.so` rename needed here since this is a plain C consumer, not PHP's `extension=`
/// loader).
fn capi_shared_lib_name() -> &'static str {
    if cfg!(windows) {
        "dstu_core_capi.dll"
    } else if cfg!(target_os = "macos") {
        "libdstu_core_capi.dylib"
    } else {
        "libdstu_core_capi.so"
    }
}

/// Compiles `src` against the just-built `dstu-core-capi` cdylib and runs the result, returning
/// whether both steps succeeded. Copies the shared library next to the compiled binary so the OS
/// loader finds it without a PATH/`LD_LIBRARY_PATH` change - simpler than relying on `-rpath`
/// alone (kept anyway on non-Windows as a second, redundant safety net).
fn capi_run_c_program(src: &Path, exe_stem: &str) -> bool {
    let target_dir = Path::new("target/release");
    let include_dir = Path::new("crates/dstu-core-capi/include");
    let out_dir = Path::new("target/capi-c");
    if std::fs::create_dir_all(out_dir).is_err() {
        eprintln!("xtask: could not create {}", out_dir.display());
        return false;
    }

    let compiled = if cfg!(windows) && cfg!(target_env = "msvc") {
        capi_compile_msvc(src, exe_stem, include_dir, target_dir, out_dir)
    } else {
        let compiler = if cfg!(windows) { "gcc" } else { "cc" };
        capi_compile_unixlike(compiler, src, exe_stem, include_dir, target_dir, out_dir)
    };
    if !compiled {
        return false;
    }

    let exe_name = if cfg!(windows) {
        format!("{exe_stem}.exe")
    } else {
        exe_stem.to_string()
    };
    let exe_path = out_dir.join(&exe_name);

    let lib_name = capi_shared_lib_name();
    if std::fs::copy(target_dir.join(lib_name), out_dir.join(lib_name)).is_err() {
        eprintln!(
            "xtask: could not copy {lib_name} from {} into {}",
            target_dir.display(),
            out_dir.display()
        );
        return false;
    }

    println!("+ {}", exe_path.display());
    Command::new(&exe_path).status().is_ok_and(|s| s.success())
}

/// GCC (mingw, Windows GNU host - this dev machine's own default, confirmed via `rustc -vV`) or
/// `cc` (Linux/macOS, always present alongside a real Rust toolchain there) - both accept the same
/// flag shape, unlike MSVC's `cl.exe` below. Links against the cdylib's import library
/// (`libdstu_core_capi.dll.a` on Windows-GNU, `.so`/`.dylib` directly via `-l` elsewhere), not the
/// staticlib - avoids re-declaring Rust std's own transitive system-library dependencies at the C
/// link step.
fn capi_compile_unixlike(
    compiler: &str,
    src: &Path,
    exe_stem: &str,
    include_dir: &Path,
    target_dir: &Path,
    out_dir: &Path,
) -> bool {
    let exe_name = if cfg!(windows) {
        format!("{exe_stem}.exe")
    } else {
        exe_stem.to_string()
    };
    let out_path = out_dir.join(&exe_name);
    let mut args: Vec<String> = vec![
        "-std=c11".into(),
        "-Wall".into(),
        "-I".into(),
        include_dir.display().to_string(),
        src.display().to_string(),
        "-o".into(),
        out_path.display().to_string(),
        "-L".into(),
        target_dir.display().to_string(),
        "-ldstu_core_capi".into(),
    ];
    if !cfg!(windows) {
        // rpath so the produced binary finds the .so/.dylib without LD_LIBRARY_PATH/DYLD_LIBRARY_PATH
        // - redundant with the copy-next-to-exe step in capi_run_c_program, kept as a second net.
        args.push(format!("-Wl,-rpath,{}", target_dir.display()));
    }
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run(compiler, &args_ref, None)
}

/// MSVC (`cl.exe`), for a real CI Windows runner whose default Rust host is
/// `x86_64-pc-windows-msvc` (unlike this dev machine's own GNU-hosted default, confirmed via
/// `rustc -vV` - `target_env = "msvc"` reflects xtask's own compiled-in host, since xtask itself
/// is always built with the same toolchain as the rest of the workspace). Mirrors
/// `fuzz_windows_msvc`'s own `vcvars64.bat`-sourcing pattern above - `cl.exe`/`link.exe` are not
/// on PATH without it.
#[cfg(windows)]
fn capi_compile_msvc(
    src: &Path,
    exe_stem: &str,
    include_dir: &Path,
    target_dir: &Path,
    out_dir: &Path,
) -> bool {
    use std::os::windows::process::CommandExt;

    let Some(vcvars) = find_vcvars64() else {
        eprintln!(
            "xtask: no Visual Studio C++ toolset found (vswhere.exe absent or reported nothing) \
             - skipping capi C harness/examples.\n  install: Visual Studio Build Tools, \"Desktop \
             development with C++\" workload"
        );
        return false;
    };
    let exe_path = out_dir.join(format!("{exe_stem}.exe"));
    let inner = format!(
        "cl.exe /nologo /W3 /std:c11 /I\"{}\" \"{}\" /Fe\"{}\" /link /LIBPATH:\"{}\" dstu_core_capi.dll.lib",
        include_dir.display(),
        src.display(),
        exe_path.display(),
        target_dir.display()
    );
    let full = format!("call \"{vcvars}\" >nul && {inner}");
    println!("+ cmd /C {full}");
    let mut command = Command::new("cmd");
    command.arg("/C");
    command.raw_arg(&full);
    command.status().is_ok_and(|s| s.success())
}

#[cfg(not(windows))]
fn capi_compile_msvc(
    _src: &Path,
    _exe_stem: &str,
    _include_dir: &Path,
    _target_dir: &Path,
    _out_dir: &Path,
) -> bool {
    unreachable!("only called when cfg!(windows) && cfg!(target_env = \"msvc\")")
}

/// Unlike Python/Node/Ruby/PHP, `bindings/dotnet` has no Cargo workspace of its own at all - it
/// consumes `crates/dstu-core-capi` (T-158, a real root-workspace member) purely via P/Invoke, so
/// `build()`/`test()`/`clippy()`/`fmt()` above already cover 100% of this binding's Rust-side
/// surface for free (unlike PHP/Node/Ruby, there is no `cargo fmt`/`clippy` to run *inside*
/// `bindings/dotnet` - it has no `Cargo.toml`). This function only needs the .NET-toolchain-
/// dependent part those can't reach: build the two native pieces first (`dstu_core_capi` for
/// `Directory.Build.props` to copy next to the test output, `uacrypt` for the real secretstream
/// interop test), `dotnet format --verify-no-changes` (this project's own "formatting is done by
/// the language's own tool" convention, cross-language-style-guide.md principle 9), then
/// `dotnet test`.
fn dotnet() -> bool {
    if !require("dotnet", "https://dotnet.microsoft.com/download (.NET 8 SDK)") {
        return false;
    }
    if !run(
        "cargo",
        &["build", "-p", "dstu-core-capi", "--release"],
        None,
    ) {
        return false;
    }
    if !run("cargo", &["build", "-p", "uacrypt", "--release"], None) {
        return false;
    }

    let dir = Path::new("bindings/dotnet");
    run(
        "dotnet",
        &["format", "DstuCore/DstuCore.csproj", "--verify-no-changes"],
        Some(dir),
    ) && run(
        "dotnet",
        &[
            "format",
            "DstuCore.Tests/DstuCore.Tests.csproj",
            "--verify-no-changes",
        ],
        Some(dir),
    ) && run("dotnet", &["test"], Some(&dir.join("DstuCore.Tests")))
}

/// Best-effort like python()/nodejs()/ruby()/php() above - bindings/java/native's own separate
/// Cargo workspace (D-119, split into its own `native/` subdirectory rather than living at
/// `bindings/java` directly, since a root-level `Cargo.toml` there would collide with Maven's own
/// `src/main/java` layout) isn't reached by build/test/clippy/fmt. Builds uacrypt first (release,
/// from the repo root) for the real `uacrypt.exe` interop check inside the JUnit suite. Needs a
/// JDK new enough for Maven's own `os-maven-plugin` extension and the `--release 8` cross-compile
/// target (11+; this project's own dev/CI machines and the Raspberry Pi rig standardize on 17,
/// D-153) - the *published* artifact still targets Java 8 bytecode via `maven.compiler.release` in
/// `bindings/java/pom.xml`, independent of whichever JDK actually runs this build.
fn java() -> bool {
    if !require("mvn", "https://maven.apache.org (or your OS package manager)") {
        return false;
    }
    if !run("cargo", &["build", "-p", "uacrypt", "--release"], None) {
        return false;
    }

    let native_dir = Path::new("bindings/java/native");
    if !run("cargo", &["build", "--release"], Some(native_dir))
        || !run("cargo", &["fmt", "--all", "--", "--check"], Some(native_dir))
        || !run(
            "cargo",
            &["clippy", "--all-targets", "--", "-D", "warnings"],
            Some(native_dir),
        )
    {
        return false;
    }

    run("mvn", &["-q", "test"], Some(Path::new("bindings/java")))
}

/// `bindings/go` (T-163) goes through the C ABI crate (`cgo` over `dstu_core.h`, D-155), same
/// group as .NET/Java. No `go` subcommand exists to check a directory is already `gofmt`-clean the
/// way `cargo fmt --check` does - `gofmt -l` instead *lists* unformatted files on stdout and still
/// exits 0, so this needs its own output-capturing check (`go_fmt_check` below) rather than `run`'s
/// plain exit-status check.
fn go() -> bool {
    if !require("go", "https://go.dev/dl/ (Go 1.21+)") {
        return false;
    }
    if !run(
        "cargo",
        &["build", "-p", "dstu-core-capi", "--release"],
        None,
    ) {
        return false;
    }

    let dir = Path::new("bindings/go");
    go_fmt_check(dir)
        && run("go", &["vet", "./..."], Some(dir))
        && run("go", &["test", "./..."], Some(dir))
}

fn go_fmt_check(dir: &Path) -> bool {
    let output = Command::new(command_for("gofmt"))
        .args(["-l", "."])
        .current_dir(dir)
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.trim().is_empty() {
                true
            } else {
                eprintln!("xtask: gofmt found unformatted file(s), run `gofmt -w .` in {}:\n{stdout}", dir.display());
                false
            }
        }
        _ => {
            eprintln!("xtask: 'gofmt' failed to run in {}", dir.display());
            false
        }
    }
}

/// `firmware/qemu-stm32-smoketest` is its own Cargo workspace (own `.cargo/config.toml` pinning
/// `target = thumbv7em-none-eabihf` and a QEMU runner) - T-170, docs/TASKS.md. `cargo run
/// --release`'s exit code IS the check: the firmware calls ARM semihosting's `SYS_EXIT` with
/// `EXIT_SUCCESS`/`EXIT_FAILURE`, which QEMU translates into its own process exit code, which
/// `cargo run` propagates as the runner's exit status - no output-parsing needed.
fn qemu_stm32() -> bool {
    if !require(
        "qemu-system-arm",
        "apt install qemu-system-arm qemu-system-misc (Debian/Ubuntu) - see firmware/qemu-stm32-smoketest/README.md",
    ) {
        return false;
    }
    run(
        "cargo",
        &["run", "--release"],
        Some(Path::new("firmware/qemu-stm32-smoketest")),
    )
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
/// optional layers (miri/kani/fuzz/audit/deny/oracle harnesses) - missing tools are reported, not fatal,
/// so this is useful on a fresh machine that only has `cargo` so far, not just full CI runners.
fn ci() -> bool {
    let mandatory = fmt(true) && build() && test() && clippy();
    if !mandatory {
        return false;
    }

    println!("\nMandatory checks passed. Running optional layers best-effort:\n");
    for optional in [
        miri,
        kani,
        fuzz,
        audit,
        deny,
        oracle_java,
        oracle_dotnet,
        python,
        nodejs,
        ruby,
        php,
        capi,
        qemu_stm32,
    ] {
        optional();
    }
    true
}
