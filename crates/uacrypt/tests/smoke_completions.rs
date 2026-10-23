//! `uacrypt completions` and `uacrypt man` (T-264, `docs/DECISIONS.md` D-257) against real shells:
//! each script is loaded and its completer actually run (zsh: parsed only). A shell that is not
//! installed (or, on Windows, a `bash` that is not Git Bash) is skipped with a `SKIPPED` line on
//! stderr (shown with `--nocapture`); an installed shell that fails or hangs fails the test.

mod support;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use support::{uacrypt, write_bytes, TempDir};

/// Runs a shell that is known to be installed, with a deadline. It failing or hanging fails the
/// test (only a missing shell is a skip). Output is drained on threads, so a large one cannot fill
/// the pipe and stall the child.
fn run_shell(mut cmd: Command, cwd: &Path, what: &str) -> String {
    use std::io::Read;

    let mut child = cmd
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{what}: cannot start: {e}"));
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    };
    let stdout = drain(Box::new(child.stdout.take().expect("piped stdout")));
    let stderr = drain(Box::new(child.stderr.take().expect("piped stderr")));
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the shell") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: still running after 60 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = stdout.join().expect("stdout reader");
    let stderr = stderr.join().expect("stderr reader");
    assert!(
        status.success(),
        "{what}: {status}: {}",
        String::from_utf8_lossy(&stderr)
    );
    String::from_utf8_lossy(&stdout).replace('\r', "")
}

/// `true` if `exe args` starts and exits 0 - only then is that shell tested.
fn installed(exe: &Path, args: &[&str]) -> bool {
    Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A missing tool is a skip, except where `UACRYPT_REQUIRE_SHELLS` is set (CI's Linux `test`
/// job installs them all), so a broken install cannot pass as a skip there.
fn skip(what: &str) {
    assert!(
        std::env::var_os("UACRYPT_REQUIRE_SHELLS").is_none(),
        "{what} not available, but UACRYPT_REQUIRE_SHELLS is set"
    );
    eprintln!("SKIPPED: {what} not available - not exercised on this machine");
}

/// Git Bash on Windows (a bare `bash` there may be WSL's `System32\bash.exe`), `bash` elsewhere.
fn bash_path() -> Option<PathBuf> {
    if cfg!(windows) {
        let out = Command::new("git").arg("--exec-path").output().ok()?;
        let exec = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        let root = exec.ancestors().nth(3)?;
        ["bin/bash.exe", "usr/bin/bash.exe"]
            .iter()
            .map(|p| root.join(p))
            .find(|p| p.is_file())
    } else {
        Some(PathBuf::from("bash"))
    }
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn write_script(dir: &TempDir, shell: &str, ext: &str) -> PathBuf {
    let r = uacrypt(["completions", shell]);
    assert!(r.success(), "{}", r.stderr);
    assert_eq!(r.stderr, "");
    let path = dir.file(&format!("uacrypt.{ext}"));
    write_bytes(&path, r.stdout.as_bytes());
    path
}

/// The completion cases every shell runs: the command line typed so far, words that must be
/// offered, words that must not.
const CASES: &[(&str, &[&str], &[&str])] = &[
    ("uacrypt kal", &["kalyna-block", "kalyna-xts"], &["keygen"]),
    ("uacrypt kalyna-block ", &["encrypt", "decrypt"], &["--key"]),
    ("uacrypt kalyna-block encrypt --it", &["--iterations"], &[]),
    (
        "uacrypt sign --",
        &["--key", "--force", "--help"],
        &["--iterations"],
    ),
    (
        "uacrypt decrypt --pass",
        &["--passphrase-file"],
        &["--passphrase"],
    ),
    (
        "uacrypt key-import --kind box5",
        &["box512-secret", "box512-public"],
        &["symmetric"],
    ),
    ("uacrypt kupyna-digest --variant ", &["256", "512"], &[]),
    ("uacrypt help ver", &["verify"], &[]),
    ("uacrypt completions p", &["powershell"], &[]),
    ("uacrypt encrypt --in secret-", &["secret-input.bin"], &[]),
];

fn check(shell: &str, results: &[Vec<String>]) {
    assert_eq!(results.len(), CASES.len(), "{shell}: {results:?}");
    for ((line, want, never), got) in CASES.iter().zip(results) {
        for w in *want {
            assert!(
                got.iter().any(|g| g == w),
                "{shell}: `{line}` -> {got:?} lacks {w}"
            );
        }
        for n in *never {
            assert!(
                !got.iter().any(|g| g == n),
                "{shell}: `{line}` -> {got:?} offers {n}"
            );
        }
    }
}

fn split_cases(stdout: &str) -> Vec<Vec<String>> {
    stdout
        .split("@@\n")
        .skip(1)
        .map(|block| {
            block
                .lines()
                .map(|l| l.split('\t').next().unwrap_or_default().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .collect()
}

fn workdir(label: &str) -> TempDir {
    let dir = TempDir::new(label);
    write_bytes(&dir.file("secret-input.bin"), b"x");
    dir
}

#[test]
#[cfg_attr(miri, ignore = "spawns shells and the real uacrypt binary")]
fn bash_completion_runs_and_offers_the_table() {
    let Some(bash) = bash_path().filter(|b| installed(b, &["--version"])) else {
        return skip("bash (Git Bash on Windows)");
    };
    let dir = workdir("compl_bash");
    let script = write_script(&dir, "bash", "bash");
    let mut driver = format!("source '{}'\n", slash(&script));
    for (line, _, _) in CASES {
        let mut words: Vec<String> = line.split(' ').map(|w| format!("'{w}'")).collect();
        if line.ends_with(' ') {
            words.pop();
            words.push("''".to_string());
        }
        driver.push_str(&format!(
            "COMP_WORDS=({}); COMP_CWORD={}; _uacrypt; echo @@; printf '%s\\n' \"${{COMPREPLY[@]}}\"\n",
            words.join(" "),
            words.len() - 1
        ));
    }
    let driver_path = dir.file("driver.bash");
    write_bytes(&driver_path, driver.as_bytes());
    let mut cmd = Command::new(bash);
    cmd.arg("--noprofile")
        .arg("--norc")
        .arg(slash(&driver_path));
    check("bash", &split_cases(&run_shell(cmd, &dir.0, "bash")));
}

#[test]
#[cfg_attr(miri, ignore = "spawns shells and the real uacrypt binary")]
fn powershell_completion_runs_and_offers_the_table() {
    let exe = ["pwsh", "powershell"]
        .into_iter()
        .find(|exe| installed(Path::new(exe), &["-NoProfile", "-Command", "exit 0"]));
    let Some(exe) = exe else {
        return skip("PowerShell");
    };
    let dir = workdir("compl_pwsh");
    let script = write_script(&dir, "powershell", "ps1");
    let mut driver = format!(". '{}'\n", slash(&script));
    for (line, _, _) in CASES {
        driver.push_str(&format!(
            "'@@'; (TabExpansion2 -inputScript '{line}' -cursorColumn {}).CompletionMatches | ForEach-Object {{ $_.CompletionText }}\n",
            line.len()
        ));
    }
    let driver_path = dir.file("driver.ps1");
    write_bytes(&driver_path, driver.as_bytes());
    let mut cmd = Command::new(exe);
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ])
    .arg(&driver_path);
    let out = run_shell(cmd, &dir.0, exe);
    // A path completion comes back as `.\x` on Windows and `./x` elsewhere; the name matters.
    let results: Vec<Vec<String>> = split_cases(&out)
        .into_iter()
        .map(|v| {
            v.into_iter()
                .map(|w| {
                    w.strip_prefix(".\\")
                        .or_else(|| w.strip_prefix("./"))
                        .unwrap_or(&w)
                        .to_string()
                })
                .collect()
        })
        .collect();
    check("powershell", &results);
}

#[test]
#[cfg_attr(miri, ignore = "spawns shells and the real uacrypt binary")]
fn fish_completion_runs_and_offers_the_table() {
    if !installed(Path::new("fish"), &["--version"]) {
        return skip("fish");
    }
    let dir = workdir("compl_fish");
    let script = write_script(&dir, "fish", "fish");
    let mut driver = format!("source '{}'\n", slash(&script));
    for (line, _, _) in CASES {
        driver.push_str(&format!("echo @@; complete -C '{line}'\n"));
    }
    let driver_path = dir.file("driver.fish");
    write_bytes(&driver_path, driver.as_bytes());
    let mut cmd = Command::new("fish");
    cmd.arg("--no-config").arg(&driver_path);
    check("fish", &split_cases(&run_shell(cmd, &dir.0, "fish")));
}

#[test]
#[cfg_attr(miri, ignore = "spawns shells and the real uacrypt binary")]
fn zsh_completion_parses() {
    if !installed(Path::new("zsh"), &["--version"]) {
        return skip("zsh");
    }
    let dir = TempDir::new("compl_zsh");
    let script = write_script(&dir, "zsh", "zsh");
    let mut cmd = Command::new("zsh");
    cmd.arg("-n").arg(&script);
    run_shell(cmd, &dir.0, "zsh -n");
}

#[test]
#[cfg_attr(miri, ignore = "spawns the real uacrypt binary")]
fn man_page_renders_cleanly_where_a_formatter_exists() {
    let r = uacrypt(["man"]);
    assert!(r.success(), "{}", r.stderr);
    assert!(r.stdout.starts_with(".TH UACRYPT 1 "));
    assert!(r.stdout.contains("\n.SS completions\n"));
    let dir = TempDir::new("man_lint");
    let page = dir.file("uacrypt.1");
    write_bytes(&page, r.stdout.as_bytes());
    for (tool, args) in [
        // Errors only: mandoc warns about the empty date, left out on purpose (deterministic
        // output, D-257); groff below is the strict check.
        ("mandoc", &["-Tlint", "-Werror"][..]),
        // The device `man` uses in a UTF-8 locale; the default (PostScript) lacks Cyrillic glyphs.
        ("groff", &["-man", "-Tutf8", "-z", "-ww"][..]),
    ] {
        let Ok(out) = Command::new(tool).args(args).arg(&page).output() else {
            skip(tool);
            continue;
        };
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stderr.trim().is_empty(),
            "{tool}: {stderr}"
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "spawns the real uacrypt binary")]
fn misuse_is_a_usage_error_with_nothing_on_stdout() {
    for args in [
        &["completions"][..],
        &["completions", "tcsh"],
        &["completions", "bash", "extra"],
        &["man", "extra"],
    ] {
        let r = uacrypt(args);
        assert_eq!(r.code, Some(2), "{args:?}: {}", r.stderr);
        assert_eq!(r.stdout, "", "{args:?}");
        assert!(!r.stderr.is_empty(), "{args:?}");
    }
    let r = uacrypt(["completions", "tcsh"]);
    assert!(r.stderr.contains("completions tcsh"), "{}", r.stderr);
}
