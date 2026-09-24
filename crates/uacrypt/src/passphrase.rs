//! Passphrase encryption for `encrypt`/`decrypt` (T-262, `docs/DECISIONS.md` D-219): the header
//! in front of an ordinary stream file, the passphrase file, and the terminal prompt.
//!
//! ```text
//! 0x50 || 0x01 (container version) || 0x01 (Argon2id v1.3)
//!   || m_cost KiB (u32 LE) || t_cost (u32 LE) || p_cost (u8) || salt (16) || <stream file, D-208>
//! ```
//! The stream key is `crypto_pwhash::derive_key(passphrase, salt, Moderate)`; the header bytes are
//! not otherwise authenticated - a changed salt or preset gives another key, and the first three
//! bytes only select the code path.

use crate::CliError;
use dstu_core::crypto_pwhash::{Strength, SALT_BYTES};
use zeroize::Zeroizing;

/// First byte of a passphrase file; a key-encrypted stream starts with its format version (2).
pub(crate) const CONTAINER_TYPE: u8 = 0x50;
const CONTAINER_VERSION: u8 = 0x01;
const KDF_ARGON2ID13: u8 = 0x01;
pub(crate) const PREFIX_LEN: usize = 3 + 4 + 4 + 1;
pub(crate) const HEADER_LEN: usize = PREFIX_LEN + SALT_BYTES;
const _: () = assert!(PREFIX_LEN == 12 && HEADER_LEN == 28);

/// The one preset `encrypt` writes and `decrypt` accepts (owner choice F3, D-219).
pub(crate) const STRENGTH: Strength = Strength::Moderate;

/// A passphrase file longer than this is refused: it is more likely the wrong file.
pub(crate) const MAX_FILE_BYTES: usize = 1024;

pub(crate) fn encode_header(salt: &[u8; SALT_BYTES]) -> [u8; HEADER_LEN] {
    let (m_cost, t_cost, p_cost) = STRENGTH.cost();
    let mut header = [0u8; HEADER_LEN];
    header[..3].copy_from_slice(&[CONTAINER_TYPE, CONTAINER_VERSION, KDF_ARGON2ID13]);
    header[3..7].copy_from_slice(&m_cost.to_le_bytes());
    header[7..11].copy_from_slice(&t_cost.to_le_bytes());
    header[11] = u8::try_from(p_cost).unwrap_or(u8::MAX);
    header[PREFIX_LEN..].copy_from_slice(salt);
    header
}

/// Checks everything but the salt, before any Argon2 work, and returns the salt.
///
/// # Errors
///
/// [`CliError::PassphraseFormatUnsupported`] for another container version or KDF, and
/// [`CliError::PassphraseParamsUnsupported`] for any cost but [`STRENGTH`]'s.
pub(crate) fn parse_header(header: &[u8; HEADER_LEN]) -> Result<[u8; SALT_BYTES], CliError> {
    let [kind, version, kdf, m0, m1, m2, m3, t0, t1, t2, t3, p, salt @ ..] = *header;
    if kind != CONTAINER_TYPE || version != CONTAINER_VERSION || kdf != KDF_ARGON2ID13 {
        return Err(CliError::PassphraseFormatUnsupported { version, kdf });
    }
    let m_cost = u32::from_le_bytes([m0, m1, m2, m3]);
    let t_cost = u32::from_le_bytes([t0, t1, t2, t3]);
    if Strength::from_cost(m_cost, t_cost, u32::from(p)) != Some(STRENGTH) {
        return Err(CliError::PassphraseParamsUnsupported {
            m_cost,
            t_cost,
            p_cost: p,
        });
    }
    Ok(salt)
}

/// The stream key for `phrase` and `salt`.
///
/// # Errors
///
/// [`CliError::PassphraseDerive`] when Argon2 cannot get its memory.
pub(crate) fn stream_key(
    phrase: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<dstu_core::crypto_secretstream::Key, CliError> {
    let key = dstu_core::crypto_pwhash::derive_key(phrase, salt, STRENGTH)
        .map_err(|e| CliError::PassphraseDerive(e.to_string()))?;
    Ok(dstu_core::crypto_secretstream::Key::from_bytes(*key))
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
    fn header_round_trips() {
        let salt = [0xA5u8; SALT_BYTES];
        let header = encode_header(&salt);
        assert_eq!(&header[..3], &[0x50, 0x01, 0x01]);
        assert_eq!(&header[3..7], &262_144u32.to_le_bytes());
        assert_eq!(&header[7..11], &3u32.to_le_bytes());
        assert_eq!(header[11], 1);
        assert_eq!(parse_header(&header), Ok(salt));
    }

    #[test]
    fn header_rejects_other_versions_kdfs_and_costs() {
        let good = encode_header(&[0u8; SALT_BYTES]);
        for (i, value) in [(1, 0x02), (2, 0x02), (3, 0x01), (7, 0x02), (11, 0x04)] {
            let mut bad = good;
            bad[i] = value;
            assert!(parse_header(&bad).is_err(), "byte {i} = {value:#x}");
        }
        let mut sensitive = good;
        sensitive[3..7].copy_from_slice(&1_048_576u32.to_le_bytes());
        sensitive[7..11].copy_from_slice(&4u32.to_le_bytes());
        assert!(matches!(
            parse_header(&sensitive),
            Err(CliError::PassphraseParamsUnsupported { .. })
        ));
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
