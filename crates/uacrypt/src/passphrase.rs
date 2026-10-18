//! Passphrase encryption for `encrypt`/`decrypt` (T-262, `docs/DECISIONS.md` D-219): the
//! `--passphrase-file` rules and the terminal prompt. The file format itself (the header in front
//! of an ordinary stream file) lives in `dstu_core::crypto_pwhash::passphrase_file` since T-269.

use crate::CliError;
use dstu_core::crypto_pwhash::passphrase_file::PassphraseFileError;
use dstu_core::crypto_pwhash::PwHashError;
use zeroize::Zeroizing;

/// A passphrase file longer than this is refused: it is more likely the wrong file.
pub(crate) const MAX_FILE_BYTES: usize = 1024;

/// The CLI error for a core passphrase-file error, with the messages and exit codes `uacrypt`
/// had before the format moved into the core.
pub(crate) fn cli_error(e: PassphraseFileError) -> CliError {
    match e {
        PassphraseFileError::UnsupportedFormat { version, kdf } => {
            CliError::PassphraseFormatUnsupported { version, kdf }
        }
        PassphraseFileError::UnsupportedParams {
            m_cost,
            t_cost,
            p_cost,
        } => CliError::PassphraseParamsUnsupported {
            m_cost,
            t_cost,
            p_cost,
        },
        PassphraseFileError::EmptyPassphrase => CliError::PassphraseEmpty,
        PassphraseFileError::PwHash(PwHashError::Random(e)) => CliError::Random(e.to_string()),
        PassphraseFileError::PwHash(e) => CliError::PassphraseDerive(e.to_string()),
        // `decrypt` dispatches on byte 0 before parsing, so the header it parses starts with the
        // container type; reported like any other unknown first byte if that ever changes.
        PassphraseFileError::NotPassphraseFile => CliError::SecretstreamUnsupportedVersion(
            dstu_core::crypto_pwhash::passphrase_file::CONTAINER_TYPE,
        ),
    }
}

/// Why a `--passphrase-file` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileProblem {
    Empty,
    TooLong,
    MoreThanOneLine,
    NotUtf8,
}

/// The passphrase in a passphrase file's bytes: a leading UTF-8 BOM and one trailing `\n` or
/// `\r\n` are dropped, nothing else (spaces are part of the passphrase; no Unicode normalisation).
///
/// # Errors
///
/// A [`FileProblem`].
pub(crate) fn parse_file(bytes: &[u8]) -> Result<&[u8], FileProblem> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(FileProblem::TooLong);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| FileProblem::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if text.contains(['\n', '\r']) {
        return Err(FileProblem::MoreThanOneLine);
    }
    if text.is_empty() {
        return Err(FileProblem::Empty);
    }
    Ok(text.as_bytes())
}

/// Reads and checks a `--passphrase-file`.
///
/// # Errors
///
/// [`CliError::Io`] if it cannot be read, [`CliError::PassphraseFileInvalid`] per [`parse_file`].
pub(crate) fn read_file(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    use std::io::Read;
    let io_err = |e: &std::io::Error| CliError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    };
    // Capacity up front, so the buffer never reallocates and leaves an unzeroized copy behind.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_FILE_BYTES + 1));
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_FILE_BYTES as u64 + 1).read_to_end(&mut bytes))
        .map_err(|e| io_err(&e))?;
    match parse_file(&bytes) {
        Ok(passphrase) => Ok(Zeroizing::new(passphrase.to_vec())),
        Err(problem) => Err(CliError::PassphraseFileInvalid {
            path: path.to_path_buf(),
            problem,
        }),
    }
}

/// Asks on the terminal with echo off (`rpassword`: /dev/tty, or the Windows console), twice when
/// `confirm`. Only when stderr is a terminal - a script with a captured stderr gets a usage error
/// naming `--passphrase-file` instead of a prompt nobody sees.
///
/// # Errors
///
/// [`CliError::PassphraseNoTerminal`], [`CliError::PassphraseEmpty`],
/// [`CliError::PassphraseMismatch`], or [`CliError::Io`] for the terminal itself.
pub(crate) fn from_terminal(confirm: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
    use std::io::IsTerminal;
    use subtle::ConstantTimeEq;
    can_prompt(
        std::io::stderr().is_terminal(),
        cfg!(windows),
        std::env::var_os("TERM_PROGRAM").as_deref(),
    )?;
    let ask = |prompt: &str| {
        let ignored = crate::sigint::Ignored::new();
        let answer = rpassword::prompt_password(prompt);
        drop(ignored);
        match answer {
            Ok(answer) => Ok(Zeroizing::new(answer)),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    crate::sigint::reraise();
                }
                Err(CliError::Io {
                    path: std::path::PathBuf::from("<terminal>"),
                    message: e.to_string(),
                })
            }
        }
    };
    let first = ask("Passphrase: ")?;
    if first.is_empty() {
        return Err(CliError::PassphraseEmpty);
    }
    if confirm {
        let second = ask("Repeat passphrase: ")?;
        if !bool::from(first.as_bytes().ct_eq(second.as_bytes())) {
            return Err(CliError::PassphraseMismatch);
        }
    }
    Ok(Zeroizing::new(first.as_bytes().to_vec()))
}

/// Whether the terminal can be asked. mintty (Git Bash's default window) gives a Windows program
/// pipes plus a hidden console; `rpassword` reads that hidden console, so the prompt would wait
/// where nobody can type (D-219). std's `IsTerminal` still reports mintty's pipe as a terminal, so
/// it is recognised by the `TERM_PROGRAM` mintty sets.
///
/// # Errors
///
/// [`CliError::PassphraseNoTerminal`] or [`CliError::PassphraseMintty`].
fn can_prompt(
    stderr_is_terminal: bool,
    windows: bool,
    term_program: Option<&std::ffi::OsStr>,
) -> Result<(), CliError> {
    if !stderr_is_terminal {
        return Err(CliError::PassphraseNoTerminal);
    }
    if windows && term_program.is_some_and(|p| p == "mintty") {
        return Err(CliError::PassphraseMintty);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_needs_a_terminal_and_not_mintty_on_windows() {
        let mintty = Some(std::ffi::OsStr::new("mintty"));
        assert_eq!(can_prompt(true, true, None), Ok(()));
        assert_eq!(can_prompt(true, false, mintty), Ok(()));
        assert_eq!(
            can_prompt(false, false, None),
            Err(CliError::PassphraseNoTerminal)
        );
        assert_eq!(
            can_prompt(true, true, mintty),
            Err(CliError::PassphraseMintty)
        );
        assert_eq!(
            can_prompt(true, true, Some(std::ffi::OsStr::new("vscode"))),
            Ok(())
        );
    }

    #[test]
    fn file_rules() {
        assert_eq!(parse_file(b"pw"), Ok(&b"pw"[..]));
        assert_eq!(parse_file(b"pw\n"), Ok(&b"pw"[..]));
        assert_eq!(parse_file(b"pw\r\n"), Ok(&b"pw"[..]));
        assert_eq!(parse_file(b"\xEF\xBB\xBFpw\n"), Ok(&b"pw"[..]));
        assert_eq!(parse_file(b" pw \n"), Ok(&b" pw "[..]));
        assert_eq!(parse_file(b""), Err(FileProblem::Empty));
        assert_eq!(parse_file(b"\r\n"), Err(FileProblem::Empty));
        assert_eq!(parse_file(b"pw\n\n"), Err(FileProblem::MoreThanOneLine));
        assert_eq!(parse_file(b"a\rb"), Err(FileProblem::MoreThanOneLine));
        assert_eq!(parse_file(b"\xFF"), Err(FileProblem::NotUtf8));
        assert_eq!(
            parse_file(&[b'a'; MAX_FILE_BYTES]),
            Ok(&[b'a'; MAX_FILE_BYTES][..])
        );
        assert_eq!(
            parse_file(&[b'a'; MAX_FILE_BYTES + 1]),
            Err(FileProblem::TooLong)
        );
    }
}
