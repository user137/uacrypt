//! `uacrypt` - a CLI over `dstu-core`.
//!
//! **Pre-release and provisional - not independently audited.** See `uacrypt`'s library-crate
//! docs (`lib.rs`) or `docs/SECURITY.md`/`docs/DECISIONS.md` in the project repository for the full
//! per-construction provisional status and threat model.

#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // T-305: `env::args()` panics on an argument that is not valid Unicode; refuse it as a usage
    // error instead (exit 2, the same as any other bad command line).
    let mut args = Vec::new();
    for (position, arg) in std::env::args_os().skip(1).enumerate() {
        match arg.into_string() {
            Ok(arg) => args.push(arg),
            Err(arg) => {
                eprintln!(
                    "uacrypt: argument {} is not valid Unicode ({}) - uacrypt takes paths and \
                     flags as Unicode text only",
                    position + 1,
                    arg.to_string_lossy()
                );
                return ExitCode::from(2);
            }
        }
    }
    match uacrypt::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("uacrypt: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
