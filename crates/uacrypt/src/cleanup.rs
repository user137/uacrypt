//! Removes an unfinished output when the process is interrupted (T-301, `docs/DECISIONS.md` D-252).
//! [`crate::OutputFile`] cleans up in `Drop`, which Ctrl-C skips: before this, an interrupted
//! `decrypt` left `<out>.uacrypt-tmp-<hex>` holding verified plaintext plus the empty placeholder,
//! and the re-run refused with "already exists". While a [`Guard`] lives its path is in a fixed
//! table that a signal handler (Unix: SIGINT, SIGTERM, SIGHUP) or a console control handler
//! (Windows: Ctrl-C, Ctrl-Break, close) deletes before the process ends as it otherwise would.
//!
//! The table holds raw pointers to NUL-terminated paths in atomics, because a signal handler may
//! only do async-signal-safe work - no lock, no allocation. A released entry's string is leaked,
//! not freed: a handler running on another thread may still be reading it. That is at most a few
//! short paths per process. A path registered after the table is full is simply not covered (the
//! old behaviour). `kill -9` and power loss still leave the files; `docs/CLI.md` says so.

#[cfg(any(unix, windows))]
use std::sync::atomic::{AtomicPtr, Ordering};

#[cfg(unix)]
type Unit = libc::c_char;
#[cfg(windows)]
type Unit = u16;

/// Two per output (placeholder and temp file), so four concurrent outputs - more than any command
/// writes (`kalyna-ccm`/`kalyna-gcm` write three).
#[cfg(any(unix, windows))]
const SLOTS: usize = 8;

#[cfg(any(unix, windows))]
static PATHS: [AtomicPtr<Unit>; SLOTS] = [const { AtomicPtr::new(std::ptr::null_mut()) }; SLOTS];

#[cfg(any(unix, windows))]
static INSTALL: std::sync::Once = std::sync::Once::new();

/// A registered path; dropping it takes the path out of the table again.
pub(crate) struct Guard {
    #[cfg(any(unix, windows))]
    slot: usize,
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(any(unix, windows))]
        PATHS[self.slot].store(std::ptr::null_mut(), Ordering::SeqCst);
    }
}

/// Puts `path` in the table and installs the handlers on first use. `None` if the path cannot be
/// encoded or the table is full - then the path is not removed on interruption.
pub(crate) fn register(path: &std::path::Path) -> Option<Guard> {
    #[cfg(any(unix, windows))]
    {
        // Under Miri nothing is registered: it cannot install the handlers, and it reports the
        // deliberately leaked strings; the lib tests it runs never interrupt anyway.
        if cfg!(miri) {
            return None;
        }
        INSTALL.call_once(install);
        let raw = encode(path)?;
        for (slot, entry) in PATHS.iter().enumerate() {
            if entry
                .compare_exchange(
                    std::ptr::null_mut(),
                    raw,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                return Some(Guard { slot });
            }
        }
        // SAFETY: `raw` came from `encode` and was never stored, so nothing else can see it.
        unsafe { free(raw) };
        None
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        None
    }
}

/// Runs `f` (taking a path out of the table and renaming the finished output onto it) so that the
/// cleanup cannot run in the middle: between the two steps it would leave the placeholder, and
/// on Windows, where the console handler is another thread, it could read the placeholder entry
/// before `f` and delete the finished output after. An interruption arriving meanwhile is handled
/// once `f` returns. Unix blocks the three signals for this thread (the only one that writes an
/// output); Windows holds the lock the console handler takes.
pub(crate) fn hold_off<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(unix)]
    {
        if cfg!(miri) {
            return f();
        }
        // SAFETY: `sigemptyset`/`sigaddset` initialise a local set; `pthread_sigmask` reads it and
        // writes the previous mask into a local, both valid for the calls.
        unsafe {
            let mut block: libc::sigset_t = core::mem::zeroed();
            let mut previous: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&raw mut block);
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::sigaddset(&raw mut block, signal);
            }
            // Best effort: if the mask cannot be set, `f` runs unprotected - the window is then
            // the few instructions it was before this function existed.
            let blocked =
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const block, &raw mut previous) == 0;
            let result = f();
            if blocked {
                libc::pthread_sigmask(libc::SIG_SETMASK, &raw const previous, std::ptr::null_mut());
            }
            result
        }
    }
    #[cfg(windows)]
    {
        let _held = HANDLER_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f()
    }
    #[cfg(not(any(unix, windows)))]
    {
        f()
    }
}

/// Taken by the console handler around its deletions and by [`hold_off`] around a commit.
#[cfg(windows)]
static HANDLER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(unix)]
fn encode(path: &std::path::Path) -> Option<*mut Unit> {
    use std::os::unix::ffi::OsStrExt;
    Some(
        std::ffi::CString::new(path.as_os_str().as_bytes())
            .ok()?
            .into_raw(),
    )
}

#[cfg(windows)]
fn encode(path: &std::path::Path) -> Option<*mut Unit> {
    let wide = crate::private_file::wide_path(path).ok()?;
    Some(Box::into_raw(wide.into_boxed_slice()).cast::<Unit>())
}

/// Frees a string from [`encode`] that was never stored in the table.
#[cfg(unix)]
unsafe fn free(raw: *mut Unit) {
    // SAFETY: the caller passes a pointer from `CString::into_raw`, once.
    drop(unsafe { std::ffi::CString::from_raw(raw) });
}

#[cfg(windows)]
unsafe fn free(raw: *mut Unit) {
    // SAFETY: the caller passes a pointer from `Box::into_raw` of a slice ending in its only NUL,
    // once; the length is recovered by finding that NUL.
    unsafe {
        let mut len = 0;
        while *raw.add(len) != 0 {
            len += 1;
        }
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            raw,
            len + 1,
        )));
    }
}

#[cfg(unix)]
fn install() {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: `on_signal` is an `extern "C" fn(c_int)` doing only async-signal-safe calls.
        let previous =
            unsafe { libc::signal(signal, on_signal as *const () as libc::sighandler_t) };
        // `SIG_ERR` (cannot happen for these three) leaves the default disposition: the files are
        // then left on interruption, as before T-301 - best effort, not a reason to refuse to run.
        if previous == libc::SIG_IGN {
            // Ignored by whoever started us (`nohup`, a background job): keep it ignored.
            // SAFETY: restores the disposition `signal` just returned.
            unsafe { libc::signal(signal, libc::SIG_IGN) };
        }
    }
}

/// Unlinks every registered path, then ends the process by the same signal with the default
/// disposition, so the parent sees the usual status (130 for SIGINT in a shell).
#[cfg(unix)]
extern "C" fn on_signal(signal: libc::c_int) {
    for entry in &PATHS {
        let path = entry.load(Ordering::SeqCst);
        if !path.is_null() {
            // SAFETY: a non-null entry is a NUL-terminated string that is never freed.
            unsafe { libc::unlink(path) };
        }
    }
    // SAFETY: `signal` and `raise` are async-signal-safe.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

#[cfg(windows)]
fn install() {
    // A failure (no console attached, for one) leaves the files on interruption, as before T-301 -
    // best effort, not a reason to refuse to run.
    // SAFETY: `on_console_event` has the PHANDLER_ROUTINE signature and lives for the whole
    // process.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_console_event), 1);
    }
}

/// Deletes every registered path, then returns FALSE so the default handler still ends the
/// process. An open temp file is only marked for deletion (it was opened with
/// `FILE_SHARE_DELETE`); it disappears when the process exits and closes its handle. It runs on
/// its own thread, so unlike a Unix signal handler it may block on [`HANDLER_LOCK`].
#[cfg(windows)]
unsafe extern "system" fn on_console_event(_event: u32) -> windows_sys::core::BOOL {
    let _held = HANDLER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for entry in &PATHS {
        let path = entry.load(Ordering::SeqCst);
        if !path.is_null() {
            // SAFETY: a non-null entry is a NUL-terminated UTF-16 path that is never freed.
            unsafe { windows_sys::Win32::Storage::FileSystem::DeleteFileW(path) };
        }
    }
    0
}
