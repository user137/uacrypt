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
