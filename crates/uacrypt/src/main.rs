//! `uacrypt` - a CLI over `dstu-core`.
//!
//! **Pre-release and provisional - not independently audited.** See `uacrypt`'s library-crate
//! docs (`lib.rs`) or `docs/SECURITY.md`/`docs/DECISIONS.md` in the project repository for the full
//! per-construction provisional status and threat model.

#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match uacrypt::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("uacrypt: {e}");
            ExitCode::FAILURE
        }
    }
}
