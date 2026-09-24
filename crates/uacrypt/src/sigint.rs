//! SIGINT around the passphrase prompt (T-262, `docs/DECISIONS.md` D-219). `rpassword` 7.5.4 reads
//! with the terminal's echo off and, on Ctrl-C, raises SIGINT before its `Drop` restores the
//! terminal - under the default disposition the process dies with echo still off. While a
//! [`Ignored`] guard lives, SIGINT is ignored, so `rpassword` returns `Interrupted` and restores
//! the terminal itself; [`reraise`] then ends the process by SIGINT as usual. A no-op off Unix:
//! Windows `rpassword` sends a console Ctrl-C event instead, not checked by hand (D-219).

/// Ignores SIGINT until dropped, then puts back the previous disposition.
pub(crate) struct Ignored {
    #[cfg(unix)]
    previous: libc::sighandler_t,
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
        #[cfg(not(unix))]
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
    }
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
