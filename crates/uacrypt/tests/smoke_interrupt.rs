//! T-301 (`docs/DECISIONS.md` D-252): an interrupted `decrypt` removes its temp file (which holds
//! verified plaintext) and its `--out` placeholder, so nothing is left behind and a re-run is not
//! refused with "already exists". The child is stopped while it waits for more stdin, after it
//! has created both files: SIGINT on Unix, Ctrl-Break to its own process group on Windows.

mod support;
use std::io::Write;
use support::{uacrypt, write_bytes, TempDir};

fn listing(dir: &TempDir) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&dir.0)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "timed out waiting: {what}");
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// Sends the interruption; `false` if this platform or environment cannot deliver it.
fn interrupt(child: &std::process::Child) -> bool {
    #[cfg(unix)]
    {
        let pid = libc::pid_t::try_from(child.id()).expect("pid fits");
        // SAFETY: sending a signal to our own child has no memory-safety preconditions.
        unsafe { libc::kill(pid, libc::SIGINT) == 0 }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
        // SAFETY: the child was started as its own process group, whose id is its pid.
        unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) != 0 }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = child;
        false
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn an_interrupted_decrypt_leaves_no_temp_file_and_no_placeholder() {
    let dir = TempDir::new("interrupt_decrypt");
    let p = |n: &str| dir.file(n).to_string_lossy().into_owned();
    write_bytes(&dir.file("msg"), &vec![0x5A; 64 * 1024]);
    assert!(uacrypt(["keygen", "--out", &p("k.key")]).success());
    let r = uacrypt(["encrypt", "--key", &p("k.key"), "--in", &p("msg"), "--out", &p("ct")]);
    assert!(r.success(), "{}", r.stderr);
    let ct = std::fs::read(dir.file("ct")).expect("read ct");

    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_uacrypt"));
    command
        .args(["decrypt", "--key", "k.key", "--in", "-", "--out", "out"])
        .current_dir(&dir.0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = command.spawn().expect("spawn the real uacrypt binary");
    // Part of the first record: decrypt reserves its output, then waits for the rest.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(&ct[..4096]).expect("feed stdin");
    stdin.flush().expect("flush stdin");
    wait_until("decrypt to create its output", || {
        let names = listing(&dir);
        names.iter().any(|n| n == "out") && names.iter().any(|n| n.starts_with("out.uacrypt-tmp-"))
    });

    if !interrupt(&child) {
        // Windows without a console shared with this test (some CI hosts): cannot send Ctrl-Break.
        child.kill().expect("kill");
        let _ = child.wait();
        eprintln!("SKIPPED: could not deliver the interruption on this host");
        return;
    }
    let mut status = None;
    wait_until("decrypt to exit after the interruption", || {
        status = child.try_wait().expect("poll");
        status.is_some()
    });
    drop(stdin);
    let status = status.expect("exited");
    assert!(!status.success(), "{status:?}");
    let names = listing(&dir);
    assert!(
        !names.iter().any(|n| n == "out" || n.starts_with("out.uacrypt-tmp-")),
        "left behind: {names:?}"
    );
}
