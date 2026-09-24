//! Ctrl-C around the passphrase prompt (T-262/T-271, `docs/DECISIONS.md` D-219). `rpassword` 7.5.4
//! reads with the terminal's echo off and, on Ctrl-C, raises SIGINT before its `Drop` restores the
//! terminal - under the default disposition the process dies with echo still off. While a
//! [`Ignored`] guard lives, SIGINT is ignored, so `rpassword` returns `Interrupted` and restores
//! the terminal itself; [`reraise`] then ends the process by SIGINT as usual. On Windows the Ctrl-C
//! event cannot be ignored that way, so the guard saves the console input mode and registers a
//! Ctrl handler that puts it back before the default exit follows (T-271).

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleCtrlHandler, SetConsoleMode};

/// The console input mode saved by [`Ignored::new`], or [`NO_MODE`] while no guard lives. One
/// atomic, so the handler thread never sees a half-set state.
#[cfg(windows)]
static SAVED_MODE: AtomicU64 = AtomicU64::new(NO_MODE);
#[cfg(windows)]
const NO_MODE: u64 = u64::MAX;

/// Ignores SIGINT until dropped, then puts back the previous disposition. On Windows: restores the
/// console input mode on Ctrl-C/Break/Close until dropped.
pub(crate) struct Ignored {
    #[cfg(unix)]
    previous: libc::sighandler_t,
    #[cfg(windows)]
    registered: bool,
}

impl Ignored {
    pub(crate) fn new() -> Self {
        #[cfg(unix)]
        {
            // SAFETY: SIG_IGN installs no handler code, it only changes SIGINT's disposition; the
            // previous one is kept and restored in `Drop`. uacrypt installs no handler of its own.
            let previous = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
            Self { previous }
        }
        #[cfg(windows)]
        {
            let Some(conin) = open_conin() else {
                return Self { registered: false };
            };
            let mut mode = 0;
            // SAFETY: `conin` is a live console handle; `mode` is a valid out-pointer.
            if unsafe { GetConsoleMode(conin.as_raw_handle(), &raw mut mode) } == 0 {
                return Self { registered: false };
            }
            SAVED_MODE.store(u64::from(mode), Ordering::SeqCst);
            // SAFETY: `restore_console` is a `extern "system"` fn with the PHANDLER_ROUTINE
            // signature and lives for the whole process.
            let registered = unsafe { SetConsoleCtrlHandler(Some(restore_console), 1) } != 0;
            if !registered {
                SAVED_MODE.store(NO_MODE, Ordering::SeqCst);
            }
            Self { registered }
        }
        #[cfg(not(any(unix, windows)))]
        Self {}
    }
}

impl Drop for Ignored {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.previous != libc::SIG_ERR {
            // SAFETY: restores the disposition `signal` returned in `new`.
            unsafe {
                libc::signal(libc::SIGINT, self.previous);
            }
        }
        #[cfg(windows)]
        if self.registered {
            // SAFETY: removes the handler `new` added; no memory is involved.
            unsafe {
                SetConsoleCtrlHandler(Some(restore_console), 0);
            }
            SAVED_MODE.store(NO_MODE, Ordering::SeqCst);
        }
    }
}

/// `CONIN$`, the console input itself - never the std input handle, which may be a file.
#[cfg(windows)]
fn open_conin() -> Option<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let name: Vec<u16> = "CONIN$".encode_utf16().chain(Some(0)).collect();
    // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call; null security attributes and
    // a null template handle are allowed.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: a fresh handle from `CreateFileW`, owned by nobody else.
    Some(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Puts back the saved console input mode, exactly as it was, then returns FALSE for every event
/// so the next handler - the default one, ending the process with `0xC000013A` - still runs.
#[cfg(windows)]
unsafe extern "system" fn restore_console(_event: u32) -> windows_sys::core::BOOL {
    let saved = SAVED_MODE.load(Ordering::SeqCst);
    if let (Ok(mode), Some(conin)) = (u32::try_from(saved), open_conin()) {
        // SAFETY: `conin` is a live console handle.
        unsafe {
            SetConsoleMode(conin.as_raw_handle(), mode);
        }
    }
    0
}

/// Ends the process by SIGINT, as a Ctrl-C would have (the shell reports status 130). The prompt
/// had the terminal in raw mode, so the shell itself got no SIGINT: a shell loop runs on. Returns
/// only where the signal cannot end the process (off Unix, or SIGINT ignored by the parent).
pub(crate) fn reraise() {
    #[cfg(unix)]
    // SAFETY: raising a signal has no memory-safety preconditions.
    unsafe {
        libc::raise(libc::SIGINT);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT};

    #[test]
    fn handler_lets_the_default_exit_follow() {
        for event in [CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT] {
            // SAFETY: no guard lives, so the handler touches no console mode.
            assert_eq!(unsafe { restore_console(event) }, 0, "event {event}");
        }
    }
}
