//! Shared harness for `uacrypt`'s binary-level (subprocess) smoke tests - `docs/TASKS.md` T-200.
//!
//! Deliberately hand-rolled `std::process::Command`, not `assert_cmd`: `crates/uacrypt/Cargo.toml`
//! has zero `[dev-dependencies]` today, and this project's own `xtask` is documented as
//! "deliberately zero dependencies" for exactly this kind of harness code (T-200's own harness
//! decision). `env!("CARGO_BIN_EXE_uacrypt")` gives the exact built-binary path with no
//! `target/debug`-vs-`release`/`.exe`-suffix guessing - confirmed populated for this crate's own
//! integration tests before this module was written, not assumed.
//!
//! Every test that uses [`uacrypt`] spawns a real OS process - Miri cannot do that at all
//! (confirmed empirically: even a plain `Path::exists()` call in a throwaway probe test aborted
//! under Miri's isolation). Every `#[test]` in every file that calls [`uacrypt`] must carry
//! `#[cfg_attr(miri, ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess")]`.

#![allow(dead_code)] // shared across many test binaries; not every file uses every helper.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

/// A per-test scratch directory under the OS temp dir, cleaned up on drop. Mirrors
/// `crates/uacrypt/src/lib.rs`'s own `#[cfg(test)] mod tests::TempDir` exactly (same naming
/// scheme, same "unique label per test, not a real uniqueness guarantee" discipline) - avoids
/// collisions between tests running in parallel within one test-binary process without pulling in
/// a `tempfile`-style dependency.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("uacrypt_smoke_{label}_{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir for smoke test");
        Self(path)
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The result of one real `uacrypt` subprocess invocation - exit code plus captured
/// stdout/stderr, exactly what a shell/CI consumer actually sees (never covered by the existing
/// 140 in-process `#[test]` fns in `crates/uacrypt/src/lib.rs`, which only ever assert on the
/// library's own `Result`).
pub struct Run {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub fn failure(&self) -> bool {
        self.code.is_some_and(|c| c != 0)
    }
}

/// Spawns the real, compiled `uacrypt` binary with `args`, waits for it to exit, and captures its
/// exit code plus stdout/stderr as UTF-8 (lossy - this project's own file paths/messages are
/// always valid UTF-8 per `CLAUDE.md`'s "UTF-8 everywhere" rule, so lossy conversion never hides a
/// real mismatch in practice).
pub fn uacrypt<I, S>(args: I) -> Run
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let exe = env!("CARGO_BIN_EXE_uacrypt");
    let output = Command::new(exe)
        .args(args)
        .output()
        .expect("spawn the real uacrypt binary");
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

pub fn write_bytes(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write test fixture");
}

pub fn read_bytes(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).expect("read test output")
}

/// Writes `len` bytes to `path` via a small repeated chunk, streamed through a normal `File`
/// rather than materializing the whole fixture as one `Vec<u8>` in the *test* process (T-200's
/// streaming-boundedness proof needs a genuinely large file, and there is no reason the test
/// harness itself should buffer it all just to create it).
pub fn write_large_file(path: &std::path::Path, len: usize) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).expect("create large fixture file");
    let chunk = vec![0xABu8; 1024 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        file.write_all(&chunk[..n])
            .expect("write large fixture chunk");
        remaining -= n;
    }
}

/// Spawns the real `uacrypt` binary the same way [`uacrypt`] does, but keeps sampling the child
/// process's real OS-reported resident memory while it runs, returning the peak observed value in
/// bytes alongside the normal [`Run`] result. `None` means no sample landed before the process
/// exited - callers must treat that as "not measured", never as "measured zero" (a command that
/// finishes faster than the first sample interval is not evidence of anything).
///
/// All three platforms read live OS-reported state, not `--in`'s size - this is a real measurement,
/// not a proxy:
/// - Linux: a background thread re-reads `/proc/<pid>/status`'s `VmRSS:` line directly (cheap
///   enough, no subprocess spawn per sample, to sample every 5ms).
/// - Windows/macOS: a helper watcher process polls the target's memory in a loop and streams one
///   sample per stdout line, read by a background thread; the watcher notices the target process
///   is gone on its own (`Get-Process`/`kill -0` failing) and exits, which closes the pipe and ends
///   the reader thread naturally - no explicit stop signal needed. Windows uses the same
///   `Get-Process`-based liveness idiom this project's own `CLAUDE.md` already documents for
///   watching a long-running process (there: CPU time; here: `WorkingSet64`).
///
/// Only the Windows path is empirically verified on this project's own dev machine (T-200) - the
/// Linux/macOS paths rely on well-established, stable OS text conventions (`/proc/PID/status`'s
/// field names, `ps -o rss=`'s output format) but were not run locally; CI
/// (`.github/workflows/rust.yml`'s `ubuntu-latest`/`macos-latest` legs) is the first real
/// confirmation for those two.
pub fn uacrypt_with_peak_rss<I, S>(args: I) -> (Run, Option<u64>)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    use std::process::Stdio;

    let exe = env!("CARGO_BIN_EXE_uacrypt");
    let child = Command::new(exe)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the real uacrypt binary");
    let pid = child.id();

    let peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sampler = spawn_rss_sampler(pid, std::sync::Arc::clone(&peak));

    let output = child
        .wait_with_output()
        .expect("wait for uacrypt subprocess");
    let _ = sampler.join();

    let peak_bytes = peak.load(std::sync::atomic::Ordering::Relaxed);
    let run = Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    (run, (peak_bytes != 0).then_some(peak_bytes))
}

#[cfg(target_os = "linux")]
fn spawn_rss_sampler(
    pid: u32,
    peak: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> std::thread::JoinHandle<()> {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    std::thread::spawn(move || {
        let path = format!("/proc/{pid}/status");
        // Stops on its own once /proc/<pid> is gone (the process exited and was reaped) - no
        // separate stop signal needed, same self-terminating shape as the Windows/macOS watcher.
        while let Ok(text) = std::fs::read_to_string(&path) {
            if let Some(kb) = parse_proc_status_vm_rss_kb(&text) {
                peak.fetch_max(kb.saturating_mul(1024), Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })
}

#[cfg(target_os = "linux")]
fn parse_proc_status_vm_rss_kb(status_text: &str) -> Option<u64> {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.trim().split_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn spawn_rss_sampler(
    pid: u32,
    peak: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> std::thread::JoinHandle<()> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::atomic::Ordering;

    #[cfg(target_os = "windows")]
    let mut watcher = {
        let script = format!(
            "while ($true) {{ try {{ (Get-Process -Id {pid} -ErrorAction Stop).WorkingSet64 }} catch {{ break }}; Start-Sleep -Milliseconds 15 }}"
        );
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn powershell RSS watcher")
    };
    #[cfg(target_os = "macos")]
    let mut watcher = {
        let script = format!(
            "while kill -0 {pid} 2>/dev/null; do ps -o rss= -p {pid} 2>/dev/null; sleep 0.02; done"
        );
        Command::new("sh")
            .args(["-c", &script])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn ps RSS watcher")
    };

    let stdout = watcher.stdout.take().expect("watcher stdout is piped");
    std::thread::spawn(move || {
        let lines = BufReader::new(stdout).lines();
        for line in lines.map_while(Result::ok) {
            if let Ok(value) = line.trim().parse::<u64>() {
                #[cfg(target_os = "windows")]
                let bytes = value; // WorkingSet64 is already bytes
                #[cfg(target_os = "macos")]
                let bytes = value.saturating_mul(1024); // `ps -o rss=` reports KB
                peak.fetch_max(bytes, Ordering::Relaxed);
            }
        }
        // The watcher self-terminates once the target process is gone (Get-Process/kill -0
        // failing), which is what closed its stdout and ended the loop above - this is a safety
        // net for the rare case it didn't, not the expected path.
        let _ = watcher.kill();
        let _ = watcher.wait();
    })
}
