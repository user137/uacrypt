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
