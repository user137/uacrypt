#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `uacrypt`'s testable logic - `main.rs` is a thin wrapper that calls [`run`] and maps the
//! result to a process exit code.
//!
//! **Pre-release and provisional - not independently audited.** The Kalyna modes behind
//! `encrypt`/`decrypt`/`kalyna-*` follow the DSTU 7624:2014 draft-edition text (`docs/DECISIONS.md`
//! D-204-D-206); `strumok-crypt` is confirmed against the DSTU 8845:2019 text (D-197). See
//! `docs/SECURITY.md`/`docs/DECISIONS.md` in the project repository for the full threat model,
//! citations, and per-construction status.
//!
//! **`kalyna-block` is deliberately not named `encrypt`/`decrypt`** - those names are the real
//! top-level commands now (`docs/TASKS.md` T-16, `docs/DECISIONS.md` D-52), built over
//! `dstu_core::crypto_secretstream` (T-40/T-70, `docs/DECISIONS.md` D-68 - migrated from
//! `dstu_core::crypto_secretbox`/D-51, which stays a separate, still-tested library primitive, not
//! removed). This command only does what `hazmat::kalyna` actually supports: exactly one block, no
//! mode, no padding - so it can't be mistaken for `encrypt`/`decrypt`, which handle a whole file of
//! any size with bounded memory (see [`run_secretstream_command`]'s doc comment).
//!
//! The `--iterations`/`--raw-schedule` flags exist for the binary-vs-binary performance comparison
//! in `docs/PERFORMANCE.md` (`docs/TASKS.md`, D-28/29/30 follow-up) - with `iterations <= 1` this is just a
//! single-block file operation.

mod keyfile;

use dstu_core::hazmat::kalyna::{
    Kalyna128_128, Kalyna128_128ExpandedKey, Kalyna128_256, Kalyna128_256ExpandedKey,
    Kalyna256_256, Kalyna256_256ExpandedKey, Kalyna256_512, Kalyna256_512ExpandedKey,
    Kalyna512_512, Kalyna512_512ExpandedKey,
};
use dstu_core::hazmat::kalyna_ccm::{
    Kalyna128_128Ccm, Kalyna128_256Ccm, Kalyna256_256Ccm, Kalyna256_512Ccm, Kalyna512_512Ccm,
};
use dstu_core::hazmat::kalyna_cmac::{
    Kalyna128_128Cmac, Kalyna128_256Cmac, Kalyna256_256Cmac, Kalyna256_512Cmac, Kalyna512_512Cmac,
};
use dstu_core::hazmat::kalyna_gcm::{
    Kalyna128_128Gcm, Kalyna128_256Gcm, Kalyna256_256Gcm, Kalyna256_512Gcm, Kalyna512_512Gcm,
};
use dstu_core::hazmat::kalyna_gmac::{
    Kalyna128_128Gmac, Kalyna128_256Gmac, Kalyna256_256Gmac, Kalyna256_512Gmac, Kalyna512_512Gmac,
};
use dstu_core::hazmat::kalyna_kw::{
    Kalyna128_128Kw, Kalyna128_256Kw, Kalyna256_256Kw, Kalyna256_512Kw, Kalyna512_512Kw,
};
use dstu_core::hazmat::kalyna_xts::{
    Kalyna128_128Xts, Kalyna128_256Xts, Kalyna256_256Xts, Kalyna256_512Xts, Kalyna512_512Xts,
};
use dstu_core::hazmat::kupyna::{Kupyna256Hasher, Kupyna512Hasher};
use dstu_core::hazmat::strumok::{Strumok256, Strumok512};
pub use keyfile::KeyKind;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;

/// Which fixed-length file a [`CliError::WrongLength`] is about. An enum rather than a string so
/// [`CliError::exit_code`] can classify it with an exhaustive match: a key or parameter file is
/// exit 3, input data (a block, a signature, a tag being verified) is exit 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthOf {
    Key,
    Nonce,
    Tweak,
    Iv,
    SigningKey,
    VerifyingKey,
    BoxSecretKey,
    BoxPublicKey,
    Box512SecretKey,
    Box512PublicKey,
    InputBlock,
    Signature,
    Tag,
}

impl fmt::Display for LengthOf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LengthOf::Key => "key",
            LengthOf::Nonce => "nonce",
            LengthOf::Tweak => "tweak",
            LengthOf::Iv => "IV",
            LengthOf::SigningKey => "signing key",
            LengthOf::VerifyingKey => "verifying key",
            LengthOf::BoxSecretKey => "box secret key",
            LengthOf::BoxPublicKey => "box public key",
            LengthOf::Box512SecretKey => "box512 secret key",
            LengthOf::Box512PublicKey => "box512 public key",
            LengthOf::InputBlock => "input block",
            LengthOf::Signature => "signature",
            LengthOf::Tag => "tag",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    UnknownCommand {
        command: String,
        suggestion: Option<&'static str>,
    },
    /// A curve twin removed in 0.5 (T-257, D-213); `replacement` reads the curve from the key.
    RemovedCommand {
        command: String,
        replacement: &'static str,
    },
    MissingSubcommand(&'static str),
    UnknownVariant(String),
    MissingFlag(&'static str),
    UnknownFlag {
        flag: String,
        suggestion: Option<&'static str>,
    },
    RepeatedFlag(&'static str),
    MissingValue(&'static str),
    FlagTakesNoValue(&'static str),
    UnexpectedArgument(String),
    InvalidIterations(String),
    Io {
        path: PathBuf,
        message: String,
    },
    WrongLength {
        what: LengthOf,
        expected: usize,
        actual: usize,
    },
    /// The mode's DSTU 7624:2014 domain excludes an empty message (`kalyna-ccm` §13.1,
    /// `kalyna-cmac` §9, `kalyna-gcm`/`kalyna-gmac` §12.1 - `docs/DECISIONS.md` D-205..D-207).
    EmptyInput(&'static str),
    PlaintextTooLong,
    AadTooLong,
    CcmVerifyFailed,
    GcmVerifyFailed,
    CmacVerifyFailed,
    GmacVerifyFailed,
    KwInvalidLength,
    KwChecksumMismatch,
    XtsInvalidLength,
    Random(String),
    KeyFileExists(PathBuf),
    /// A non-key output already exists and `--force` was not given (T-258, D-214).
    /// `same_as_input` is set when it is `--in` itself (by path, after resolving symlinks).
    OutputExists {
        path: PathBuf,
        same_as_input: bool,
    },
    /// An output names the same file as another output or a key input (T-258, D-214).
    SameOutputPath(&'static str, &'static str),
    /// An existing output is a typed key file; never replaced, even with `--force` (T-268, D-216).
    OutputIsKeyFile {
        path: PathBuf,
        kind: KeyKind,
    },
    /// An existing output could not be read to rule out a key file (T-268, D-216).
    OutputUncheckable {
        path: PathBuf,
        message: String,
    },
    /// Neither of two alternative flags was given (`hash --in` / `--check`, T-259).
    MissingOneOf(&'static str, &'static str),
    /// Two mutually exclusive flags were both given.
    ExclusiveFlags(&'static str, &'static str),
    /// `hash --in` names a path that cannot be printed as one check-file line (D-215).
    HashPathUnprintable(PathBuf),
    HashCheckTooLarge {
        path: PathBuf,
        limit: usize,
    },
    HashCheckEmpty(PathBuf),
    HashCheckUtf16(PathBuf),
    HashCheckMalformed {
        path: PathBuf,
        line: usize,
    },
    HashCheckFailed {
        failed: usize,
        total: usize,
    },
    SecretstreamTruncated,
    SecretstreamVerifyFailed,
    SecretstreamUnknownTag,
    SecretstreamTrailingData,
    SecretstreamChunkTooLarge,
    SecretstreamUnsupportedVersion(u8),
    SecretstreamBadChunkLength,
    SignKeyInvalid,
    SignVerifyFailed,
    /// `--key` is not a typed key file (D-212): a raw 0.3.x/0.4.0 key or some other file.
    KeyFileNotTyped(PathBuf),
    KeyFileMalformed {
        path: PathBuf,
        kind: KeyKind,
    },
    KeyCheckMismatch {
        path: PathBuf,
        kind: KeyKind,
    },
    KeyKindMismatch {
        path: PathBuf,
        command: &'static str,
        found: KeyKind,
        expected: &'static [KeyKind],
    },
    UnknownKeyKind {
        value: String,
        suggestion: Option<&'static str>,
    },
    /// `key-import --kind sign*-public` given an old verifying-key file whose D-186 curve byte
    /// names another curve (or no known one).
    KeyImportCurveByte {
        path: PathBuf,
        kind: KeyKind,
        byte: u8,
    },
    BoxKeyInvalid,
    /// Carries the key's curve: a file sealed to the other curve's key fails here too.
    BoxOpenTruncated(&'static str),
    BoxOpenFailed(&'static str),
    BoxOpenUnsupportedVersion,
}

impl fmt::Display for CliError {
    // A flat enum-variant-to-message match, one line of real logic per arm - splitting it across
    // functions (the D-71 pattern used elsewhere in this file for line-count lints on genuine
    // control flow) would add indirection without clarity here, so this is the documented
    // exception instead, same posture as this project's other clippy quirk `#[allow]`s.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::UnknownCommand {
                command,
                suggestion,
            } => {
                write!(f, "unknown command: {command}")?;
                if let Some(s) = suggestion {
                    write!(f, " (did you mean `{s}`?)")?;
                }
                write!(f, " - run `uacrypt help` for the list of commands")
            }
            CliError::RemovedCommand {
                command,
                replacement,
            } => write!(
                f,
                "`{command}` was removed in uacrypt 0.5 - use `uacrypt {replacement}`, it reads \
                 the curve from the key"
            ),
            CliError::MissingSubcommand(choices) => {
                write!(f, "missing subcommand: expected one of {choices}")
            }
            CliError::UnknownVariant(v) => write!(
                f,
                "unknown variant: {v} (expected one of 128-128, 128-256, 256-256, 256-512, 512-512)"
            ),
            CliError::MissingFlag(name) => write!(f, "missing required flag: --{name}"),
            CliError::UnknownFlag { flag, suggestion } => {
                write!(f, "unknown flag: {flag}")?;
                match suggestion {
                    Some(s) => write!(f, " (did you mean `{s}`?)"),
                    None => Ok(()),
                }
            }
            CliError::RepeatedFlag(flag) => write!(f, "{flag} given more than once"),
            CliError::MissingValue(flag) => write!(f, "{flag} needs a value"),
            CliError::FlagTakesNoValue(flag) => write!(f, "{flag} takes no value"),
            CliError::UnexpectedArgument(arg) => write!(
                f,
                "unexpected argument: {arg} - every input is a named flag, e.g. --in <path>"
            ),
            CliError::InvalidIterations(v) => write!(f, "invalid --iterations value: {v}"),
            CliError::Io { path, message } => {
                write!(f, "{}: {message}", path.display())
            }
            CliError::KeyFileExists(path) => write!(
                f,
                "{} already exists - refusing to overwrite a key file; delete it first if you really want a new key",
                path.display()
            ),
            CliError::OutputExists {
                path,
                same_as_input: false,
            } => write!(
                f,
                "{} already exists - pass --force to replace it",
                path.display()
            ),
            CliError::OutputExists {
                path,
                same_as_input: true,
            } => write!(
                f,
                "{} already exists and is the same file as --in - pass --force to replace it in place",
                path.display()
            ),
            CliError::OutputIsKeyFile { path, kind } => write!(
                f,
                "{} is a uacrypt {} - refusing to replace a key file, even with --force; delete it yourself if you really mean to",
                path.display(),
                kind.label()
            ),
            CliError::OutputUncheckable { path, message } => write!(
                f,
                "{} already exists and could not be read to check it is not a key file ({message}) - not replacing it",
                path.display()
            ),
            CliError::SameOutputPath(first, second) => {
                write!(f, "{first} and {second} name the same file")
            }
            CliError::MissingOneOf(one, other) => {
                write!(f, "missing required flag: --{one} (or --{other})")
            }
            CliError::ExclusiveFlags(one, other) => {
                write!(f, "--{one} and --{other} cannot be used together")
            }
            CliError::HashPathUnprintable(path) => write!(
                f,
                "{}: a path that is not UTF-8 or contains a control character cannot be \
                 written as a checksum line",
                path.display()
            ),
            CliError::HashCheckTooLarge { path, limit } => write!(
                f,
                "{}: checksum file is larger than {limit} bytes",
                path.display()
            ),
            CliError::HashCheckUtf16(path) => write!(
                f,
                "{}: checksum file is UTF-16 (Windows PowerShell 5.1 writes `>` that way); create \
                 it with PowerShell 7 or `cmd /c \"uacrypt hash --in <file> > <list>\"`",
                path.display()
            ),
            CliError::HashCheckEmpty(path) => {
                write!(f, "{}: no checksum lines", path.display())
            }
            CliError::HashCheckMalformed { path, line } => write!(
                f,
                "{}: line {line} is not `<64 hex digits><two spaces><path>`; nothing was checked",
                path.display()
            ),
            CliError::HashCheckFailed { failed, total } => write!(
                f,
                "{failed} of {total} listed files did NOT match or could not be read"
            ),
            CliError::WrongLength {
                what,
                expected,
                actual,
            } => write!(f, "{what} must be exactly {expected} bytes, got {actual}"),
            CliError::EmptyInput(command) => write!(
                f,
                "{command}: --in is empty - DSTU 7624:2014 does not define this mode for an empty message"
            ),
            CliError::PlaintextTooLong => write!(
                f,
                "input exceeds kalyna-ccm's sourced 255-byte limit (see hazmat::kalyna_ccm docs)"
            ),
            CliError::AadTooLong => write!(
                f,
                "--aad exceeds kalyna-ccm's sourced 255-byte limit (see hazmat::kalyna_ccm docs)"
            ),
            CliError::CcmVerifyFailed => {
                write!(f, "kalyna-ccm: authentication failed - ciphertext, tag, AAD, nonce, or key do not match")
            }
            CliError::GcmVerifyFailed => {
                write!(f, "kalyna-gcm: authentication failed - ciphertext, tag, AAD, nonce, or key do not match")
            }
            CliError::CmacVerifyFailed => {
                write!(f, "kalyna-cmac: authentication failed - message, tag, or key do not match")
            }
            CliError::GmacVerifyFailed => {
                write!(f, "kalyna-gmac: authentication failed - message, tag, or key do not match")
            }
            CliError::KwInvalidLength => write!(
                f,
                "kalyna-kw: --in must be block-aligned and within the variant's MAX_R block limit (see hazmat::kalyna_kw docs)"
            ),
            CliError::KwChecksumMismatch => {
                write!(f, "kalyna-kw: unwrap failed - the recovered checksum block was not all-zero (wrong key or tampered input)")
            }
            CliError::XtsInvalidLength => {
                write!(f, "kalyna-xts: --in must be at least one block long")
            }
            CliError::Random(message) => write!(f, "failed to generate a random nonce: {message}"),
            CliError::SecretstreamTruncated => write!(
                f,
                "--in ends before a Final chunk was ever read - truncated or not real encrypt output"
            ),
            CliError::SecretstreamVerifyFailed => write!(
                f,
                "decrypt: authentication failed - --in, --key, or the file itself do not match"
            ),
            CliError::SecretstreamUnknownTag => {
                write!(f, "decrypt: unrecognized chunk tag in --in - not real encrypt output")
            }
            CliError::SecretstreamTrailingData => write!(
                f,
                "decrypt: extra data found in --in after the final chunk - not real encrypt output"
            ),
            CliError::SecretstreamChunkTooLarge => write!(
                f,
                "decrypt: a chunk length in --in exceeds this build's maximum chunk size - not real encrypt output"
            ),
            CliError::SecretstreamUnsupportedVersion(v) => write!(
                f,
                "decrypt: unsupported stream format version {v} in --in - this build reads version {} only; files from uacrypt 0.3.x and earlier cannot be read",
                dstu_core::crypto_secretstream::FORMAT_VERSION
            ),
            CliError::SecretstreamBadChunkLength => write!(
                f,
                "decrypt: a non-final chunk in --in is not exactly {SECRETSTREAM_CHUNK_BYTES} bytes - not real encrypt output"
            ),
            CliError::SignKeyInvalid => write!(
                f,
                "--key is not a valid signing key (must be nonzero and less than the curve order - see uacrypt sign-keygen/sign-keygen257)"
            ),
            CliError::SignVerifyFailed => write!(
                f,
                "verify: signature does not verify - message, signature, or key do not match"
            ),
            CliError::KeyFileNotTyped(path) => write!(
                f,
                "{} is not a uacrypt key file - a raw key file from uacrypt 0.4 or older can be converted with `uacrypt key-import`",
                path.display()
            ),
            CliError::KeyFileMalformed { path, kind } => write!(
                f,
                "{} starts like a {} but is not a well-formed key line (`{}:<{} hex digits>:<8 hex digits>`)",
                path.display(),
                kind.label(),
                kind.prefix(),
                2 * kind.key_len()
            ),
            CliError::KeyCheckMismatch { path, kind } => write!(
                f,
                "{} is damaged: its check value does not match the {} it holds (edited or mistyped?)",
                path.display(),
                kind.label()
            ),
            CliError::KeyKindMismatch {
                path,
                command,
                found,
                expected,
            } => {
                let wanted: Vec<&str> = expected.iter().map(|k| k.label()).collect();
                write!(
                    f,
                    "{} is a {}, but {command} needs a {} - {}",
                    path.display(),
                    found.label(),
                    wanted.join(" or a "),
                    keyfile::wrong_kind_hint(expected)
                )
            }
            CliError::KeyImportCurveByte { path, kind, byte } => write!(
                f,
                "{} starts with curve byte 0x{byte:02x}, but a raw {} file starts with 0x{:02x} - check --kind",
                path.display(),
                kind.label(),
                if *kind == KeyKind::Sign163Public {
                    dstu_core::crypto_sign::CurveId::M163.to_byte()
                } else {
                    dstu_core::crypto_sign::CurveId::M257.to_byte()
                }
            ),
            CliError::UnknownKeyKind { value, suggestion } => {
                write!(f, "unknown key kind: {value}")?;
                if let Some(s) = suggestion {
                    write!(f, " (did you mean `{s}`?)")?;
                }
                let names: Vec<&str> = KeyKind::names().collect();
                write!(f, " - expected one of {}", names.join(", "))
            }
            CliError::BoxKeyInvalid => write!(
                f,
                "--key is not a valid crypto_box key (see uacrypt box-keygen/box-pubkey)"
            ),
            CliError::BoxOpenTruncated(curve) => write!(
                f,
                "box-open: --in is too short to be real box-seal output for this {curve} key"
            ),
            CliError::BoxOpenFailed(curve) => write!(
                f,
                "box-open: authentication failed - --in was not sealed to this {curve} key, or                  it was modified"
            ),
            CliError::BoxOpenUnsupportedVersion => write!(
                f,
                "box-open: --in was sealed in a different format version (e.g. by uacrypt 0.3.x) - \
                 open it with the release that sealed it"
            ),
        }
    }
}

impl CliError {
    /// The process exit status for this error (`docs/CLI.md` "Exit status", `docs/DECISIONS.md`
    /// D-211): 1 = the input data was checked and rejected, 2 = the command line is wrong,
    /// 3 = a file or key could not be used. Exhaustive on purpose - a new variant must be
    /// classified here to compile.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        const REJECTED: u8 = 1;
        const USAGE: u8 = 2;
        const FILE_OR_KEY: u8 = 3;
        match self {
            CliError::UnknownCommand { .. }
            | CliError::RemovedCommand { .. }
            | CliError::MissingSubcommand(_)
            | CliError::UnknownVariant(_)
            | CliError::MissingFlag(_)
            | CliError::UnknownFlag { .. }
            | CliError::RepeatedFlag(_)
            | CliError::MissingValue(_)
            | CliError::FlagTakesNoValue(_)
            | CliError::UnexpectedArgument(_)
            | CliError::InvalidIterations(_)
            | CliError::UnknownKeyKind { .. }
            | CliError::SameOutputPath(..)
            | CliError::MissingOneOf(..)
            | CliError::ExclusiveFlags(..)
            | CliError::HashPathUnprintable(_) => USAGE,
            CliError::Io { .. }
            | CliError::KeyFileExists(_)
            | CliError::OutputExists { .. }
            | CliError::OutputIsKeyFile { .. }
            | CliError::OutputUncheckable { .. }
            | CliError::Random(_)
            | CliError::SignKeyInvalid
            | CliError::KeyFileNotTyped(_)
            | CliError::KeyFileMalformed { .. }
            | CliError::KeyCheckMismatch { .. }
            | CliError::KeyKindMismatch { .. }
            | CliError::KeyImportCurveByte { .. }
            | CliError::BoxKeyInvalid => FILE_OR_KEY,
            CliError::WrongLength { what, .. } => match what {
                LengthOf::Key
                | LengthOf::Nonce
                | LengthOf::Tweak
                | LengthOf::Iv
                | LengthOf::SigningKey
                | LengthOf::VerifyingKey
                | LengthOf::BoxSecretKey
                | LengthOf::BoxPublicKey
                | LengthOf::Box512SecretKey
                | LengthOf::Box512PublicKey => FILE_OR_KEY,
                LengthOf::InputBlock | LengthOf::Signature | LengthOf::Tag => REJECTED,
            },
            CliError::EmptyInput(_)
            | CliError::PlaintextTooLong
            | CliError::AadTooLong
            | CliError::CcmVerifyFailed
            | CliError::GcmVerifyFailed
            | CliError::CmacVerifyFailed
            | CliError::GmacVerifyFailed
            | CliError::KwInvalidLength
            | CliError::KwChecksumMismatch
            | CliError::XtsInvalidLength
            | CliError::SecretstreamTruncated
            | CliError::SecretstreamVerifyFailed
            | CliError::SecretstreamUnknownTag
            | CliError::SecretstreamTrailingData
            | CliError::SecretstreamChunkTooLarge
            | CliError::SecretstreamUnsupportedVersion(_)
            | CliError::SecretstreamBadChunkLength
            | CliError::SignVerifyFailed
            | CliError::BoxOpenTruncated(_)
            | CliError::BoxOpenFailed(_)
            | CliError::BoxOpenUnsupportedVersion
            | CliError::HashCheckTooLarge { .. }
            | CliError::HashCheckEmpty(_)
            | CliError::HashCheckUtf16(_)
            | CliError::HashCheckMalformed { .. }
            | CliError::HashCheckFailed { .. } => REJECTED,
        }
    }
}

impl From<dstu_core::hazmat::kalyna_gcm::GcmError> for CliError {
    fn from(err: dstu_core::hazmat::kalyna_gcm::GcmError) -> Self {
        match err {
            dstu_core::hazmat::kalyna_gcm::GcmError::EmptyInput => Self::EmptyInput("kalyna-gcm"),
            dstu_core::hazmat::kalyna_gcm::GcmError::InvalidLength
            | dstu_core::hazmat::kalyna_gcm::GcmError::TagMismatch => Self::GcmVerifyFailed,
        }
    }
}

impl From<dstu_core::hazmat::kalyna_gmac::GmacError> for CliError {
    fn from(err: dstu_core::hazmat::kalyna_gmac::GmacError) -> Self {
        match err {
            dstu_core::hazmat::kalyna_gmac::GmacError::EmptyMessage => {
                Self::EmptyInput("kalyna-gmac")
            }
            dstu_core::hazmat::kalyna_gmac::GmacError::InvalidLength
            | dstu_core::hazmat::kalyna_gmac::GmacError::TagMismatch => Self::GmacVerifyFailed,
        }
    }
}

impl From<dstu_core::hazmat::kalyna_cmac::CmacError> for CliError {
    fn from(err: dstu_core::hazmat::kalyna_cmac::CmacError) -> Self {
        match err {
            dstu_core::hazmat::kalyna_cmac::CmacError::EmptyMessage => {
                Self::EmptyInput("kalyna-cmac")
            }
            dstu_core::hazmat::kalyna_cmac::CmacError::TagMismatch => Self::CmacVerifyFailed,
        }
    }
}

impl From<dstu_core::hazmat::kalyna_ccm::CcmError> for CliError {
    fn from(err: dstu_core::hazmat::kalyna_ccm::CcmError) -> Self {
        match err {
            dstu_core::hazmat::kalyna_ccm::CcmError::EmptyPlaintext => {
                Self::EmptyInput("kalyna-ccm")
            }
            dstu_core::hazmat::kalyna_ccm::CcmError::PlaintextTooLong => Self::PlaintextTooLong,
            dstu_core::hazmat::kalyna_ccm::CcmError::AadTooLong => Self::AadTooLong,
            dstu_core::hazmat::kalyna_ccm::CcmError::TagMismatch => Self::CcmVerifyFailed,
        }
    }
}

impl From<dstu_core::crypto_secretstream::SecretstreamError> for CliError {
    fn from(err: dstu_core::crypto_secretstream::SecretstreamError) -> Self {
        use dstu_core::crypto_secretstream::SecretstreamError;
        match err {
            SecretstreamError::TagMismatch => Self::SecretstreamVerifyFailed,
            SecretstreamError::UnknownTag => Self::SecretstreamUnknownTag,
            SecretstreamError::Random(e) => Self::Random(e.to_string()),
            SecretstreamError::InvalidLength
            | SecretstreamError::StreamFinalized
            | SecretstreamError::CounterExhausted => unreachable!(
                "uacrypt always supplies matching buffer lengths, never calls push/pull again \
                 after a Final chunk, and cannot reach 2^64 - 1 chunks of 8 KiB"
            ),
        }
    }
}

/// The five Kalyna block/key-size variants (`docs/DECISIONS.md` D-13), addressed the same way
/// `oracles/kalyna-reference`'s own `KalynaInit(block_bits, key_bits)` and this project's
/// differential harnesses already do: `"<block_bits>-<key_bits>"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KalynaVariant {
    K128_128,
    K128_256,
    K256_256,
    K256_512,
    K512_512,
}

impl KalynaVariant {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "128-128" => Some(Self::K128_128),
            "128-256" => Some(Self::K128_256),
            "256-256" => Some(Self::K256_256),
            "256-512" => Some(Self::K256_512),
            "512-512" => Some(Self::K512_512),
            _ => None,
        }
    }

    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::K128_128 => 16,
            Self::K128_256 | Self::K256_256 => 32,
            Self::K256_512 | Self::K512_512 => 64,
        }
    }

    #[must_use]
    pub fn block_len(self) -> usize {
        match self {
            Self::K128_128 | Self::K128_256 => 16,
            Self::K256_256 | Self::K256_512 => 32,
            Self::K512_512 => 64,
        }
    }

    /// CCM authentication tag length in bytes for this variant - see
    /// `hazmat::kalyna_ccm`'s per-variant `(ccm_nb, q)` constants (cross-oracle-vector-confirmed,
    /// not chosen by this CLI).
    #[must_use]
    pub fn ccm_tag_len(self) -> usize {
        match self {
            Self::K128_128 | Self::K128_256 | Self::K256_256 => 16,
            Self::K256_512 => 32,
            Self::K512_512 => 64,
        }
    }
}

/// One block op (encrypt or decrypt), `iterations` times over the same in-memory key/block -
/// `iterations - 1` of those are purely for timing (the loop's final output is what gets
/// returned/written). `raw_schedule` selects which of `dstu_core`'s two Kalyna APIs is exercised:
/// the raw one-shot functions (`key_expand` redone every iteration) or `ExpandedKey` (`key_expand`
/// once, reused) - see `docs/DECISIONS.md` D-29 for why both numbers matter.
fn run_block_op(
    variant: KalynaVariant,
    key: &[u8],
    block: &[u8],
    decrypt: bool,
    iterations: u32,
    raw_schedule: bool,
) -> (Vec<u8>, std::time::Duration) {
    macro_rules! run_variant {
        ($plain:ty, $expanded:ty, $key_len:literal, $block_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(key);
            let mut block_arr = [0u8; $block_len];
            block_arr.copy_from_slice(block);

            let start = Instant::now();
            let out = if raw_schedule {
                let mut out = [0u8; $block_len];
                for _ in 0..iterations {
                    out = if decrypt {
                        <$plain>::decrypt(&key_arr, &block_arr)
                    } else {
                        <$plain>::encrypt(&key_arr, &block_arr)
                    };
                }
                out
            } else {
                let expanded = <$expanded>::new(&key_arr);
                let mut out = [0u8; $block_len];
                for _ in 0..iterations {
                    out = if decrypt {
                        expanded.decrypt_block(&block_arr)
                    } else {
                        expanded.encrypt_block(&block_arr)
                    };
                }
                out
            };
            let elapsed = start.elapsed();
            (out.to_vec(), elapsed)
        }};
    }

    match variant {
        KalynaVariant::K128_128 => {
            run_variant!(Kalyna128_128, Kalyna128_128ExpandedKey, 16, 16)
        }
        KalynaVariant::K128_256 => {
            run_variant!(Kalyna128_256, Kalyna128_256ExpandedKey, 32, 16)
        }
        KalynaVariant::K256_256 => {
            run_variant!(Kalyna256_256, Kalyna256_256ExpandedKey, 32, 32)
        }
        KalynaVariant::K256_512 => {
            run_variant!(Kalyna256_512, Kalyna256_512ExpandedKey, 64, 32)
        }
        KalynaVariant::K512_512 => {
            run_variant!(Kalyna512_512, Kalyna512_512ExpandedKey, 64, 64)
        }
    }
}

/// Generic `--flag value` scanner shared by every `parse_*_args` function below (T-188 -
/// `SonarCloud`'s duplicated-lines Quality Gate flagged ~918 duplicated lines/34 groups from
/// copy-pasted per-command scanning loops that were otherwise identical apart from which flags/
/// types each command needs). Each `parse_*_args` function still owns its own flag list and which
/// fields are required - this only replaces the "scan tokens left to right, split into flag/value
/// pairs, reject anything unrecognized" mechanics every one of them used to hand-roll.
struct ArgScanner {
    values: HashMap<&'static str, String>,
    flags: HashMap<&'static str, bool>,
}

impl ArgScanner {
    /// `value_flags` each take one value, either as the next argument or as `--flag=value`;
    /// `bool_flags` take none. Strict by design (`docs/TASKS.md` T-255, rule R4): a repeated flag,
    /// a missing or empty value, a value on a bool flag, an unknown flag (with a "did you mean"
    /// suggestion) and a bare positional argument are all usage errors. A separate value that
    /// starts with `--` is read as a forgotten value, not a path (`--key --in x`); a path that
    /// really starts with `--` is still reachable as `--in=--x`. Returns the first problem found
    /// scanning left to right.
    fn scan(
        args: &[String],
        value_flags: &[&'static str],
        bool_flags: &[&'static str],
    ) -> Result<Self, CliError> {
        let mut values = HashMap::new();
        let mut flags: HashMap<&'static str, bool> =
            bool_flags.iter().map(|f| (*f, false)).collect();
        let mut i = 0;
        while i < args.len() {
            let token = args[i].as_str();
            let (name, inline) = match token.split_once('=') {
                Some((n, v)) if n.starts_with("--") => (n, Some(v)),
                _ => (token, None),
            };
            if let Some(&flag) = bool_flags.iter().find(|f| **f == name) {
                if inline.is_some() {
                    return Err(CliError::FlagTakesNoValue(flag));
                }
                if flags.insert(flag, true) == Some(true) {
                    return Err(CliError::RepeatedFlag(flag));
                }
                i += 1;
            } else if let Some(&flag) = value_flags.iter().find(|f| **f == name) {
                let value = if let Some(v) = inline {
                    i += 1;
                    v
                } else {
                    i += 2;
                    match args.get(i - 1) {
                        Some(v) if !v.starts_with("--") => v.as_str(),
                        _ => "",
                    }
                };
                if value.is_empty() {
                    return Err(CliError::MissingValue(flag));
                }
                if values.insert(flag, value.to_string()).is_some() {
                    return Err(CliError::RepeatedFlag(flag));
                }
            } else if token.starts_with('-') {
                let candidates = value_flags.iter().chain(bool_flags).copied();
                return Err(CliError::UnknownFlag {
                    flag: name.to_string(),
                    suggestion: suggest(name, candidates.chain(["--help"])),
                });
            } else {
                return Err(CliError::UnexpectedArgument(token.to_string()));
            }
        }
        Ok(Self { values, flags })
    }

    fn path(&self, flag: &'static str) -> Result<PathBuf, CliError> {
        self.values
            .get(flag)
            .map(PathBuf::from)
            .ok_or(CliError::MissingFlag(&flag[2..]))
    }

    fn path_opt(&self, flag: &'static str) -> Option<PathBuf> {
        self.values.get(flag).map(PathBuf::from)
    }

    fn variant<T>(&self, parse: impl FnOnce(&str) -> Option<T>) -> Result<T, CliError> {
        let v = self
            .values
            .get("--variant")
            .ok_or(CliError::MissingFlag("variant"))?;
        parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))
    }

    fn iterations(&self) -> Result<u32, CliError> {
        match self.values.get("--iterations") {
            Some(v) => v
                .parse()
                .map_err(|_| CliError::InvalidIterations(v.clone())),
            None => Ok(1),
        }
    }

    fn key_kind(&self) -> Result<KeyKind, CliError> {
        let v = self
            .values
            .get("--kind")
            .ok_or(CliError::MissingFlag("kind"))?;
        KeyKind::parse_name(v).ok_or_else(|| CliError::UnknownKeyKind {
            value: v.clone(),
            suggestion: suggest(v, KeyKind::names()),
        })
    }

    fn bool_flag(&self, flag: &'static str) -> bool {
        *self.flags.get(flag).unwrap_or(&false)
    }
}

/// The candidate closest to `input`, if it is close enough to be a plausible typo: at most
/// one edit per three characters of `input` (ignoring leading dashes), minimum one. Ties go to the
/// earliest candidate.
fn suggest<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let limit = (input.trim_start_matches('-').len() / 3).max(1);
    candidates
        .into_iter()
        .map(|c| (edit_distance(input, c), c))
        .filter(|&(d, _)| d <= limit)
        .min_by_key(|&(d, _)| d)
        .map(|(_, c)| c)
}

/// Optimal-string-alignment distance (Levenshtein plus adjacent transposition, so `encrpyt` is
/// one edit from `encrypt`), iterative over three rows. Byte-wise: every name it compares against
/// is ASCII.
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut before_prev = vec![0usize; b.len() + 1];
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut d = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i >= 2 && j >= 2 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d = d.min(before_prev[j - 2] + 1);
            }
            cur[j] = d;
        }
        std::mem::swap(&mut before_prev, &mut prev);
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[derive(Debug, PartialEq, Eq)]
pub struct BlockArgs {
    pub variant: KalynaVariant,
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    pub raw_schedule: bool,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `kalyna-block encrypt`/`decrypt`'s own flags (`--variant`/`--key`/`--in`/`--out`
/// required, `--iterations`/`--raw-schedule` optional) - `args` excludes the command name itself.
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`] for an absent required flag, [`CliError::UnknownVariant`] for
/// an unrecognized `--variant` value, [`CliError::InvalidIterations`] for a non-numeric
/// `--iterations` value, or [`CliError::UnknownFlag`] for any other unrecognized token.
pub fn parse_block_args(args: &[String]) -> Result<BlockArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &["--variant", "--key", "--in", "--out", "--iterations"],
        &["--raw-schedule", "--force"],
    )?;
    Ok(BlockArgs {
        variant: scanner.variant(KalynaVariant::parse)?,
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        iterations: scanner.iterations()?,
        raw_schedule: scanner.bool_flag("--raw-schedule"),
        force: scanner.bool_flag("--force"),
    })
}

fn read_exact_file(
    path: &PathBuf,
    what: LengthOf,
    expected_len: usize,
) -> Result<Vec<u8>, CliError> {
    let bytes = std::fs::read(path).map_err(|e| CliError::Io {
        path: path.clone(),
        message: e.to_string(),
    })?;
    if bytes.len() != expected_len {
        return Err(CliError::WrongLength {
            what,
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Runs `kalyna-block encrypt`/`decrypt`: reads `--key`/`--in`, performs the op (`iterations`
/// times if given, for benchmarking), writes the final result to `--out`, and prints iteration
/// timing to stderr when `iterations > 1`.
///
/// # Errors
///
/// Returns [`CliError::Io`] if the key/input file can't be read or the output file can't be
/// written, or [`CliError::WrongLength`] if the key or input file isn't exactly the variant's
/// expected length.
pub fn run_block_command(decrypt: bool, args: &BlockArgs) -> Result<(), CliError> {
    let key = read_exact_file(&args.key_path, LengthOf::Key, args.variant.key_len())?;
    check_outputs(&[("--out", &args.out_path)], &[("--key", &args.key_path)])?;
    let (out, out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;
    let expected_in_len = args.variant.block_len();
    let input = read_exact_file(&args.in_path, LengthOf::InputBlock, expected_in_len)?;

    let (output, elapsed) = run_block_op(
        args.variant,
        &key,
        &input,
        decrypt,
        args.iterations.max(1),
        args.raw_schedule,
    );

    out.write_all_and_commit(out_file, &output)?;

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        eprintln!(
            "iterations={} schedule={} total_ns={} per_op_ns={}",
            args.iterations,
            if args.raw_schedule { "raw" } else { "cached" },
            elapsed.as_nanos(),
            per_op_ns
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct CcmArgs {
    pub variant: KalynaVariant,
    pub key_path: PathBuf,
    /// Output path on `encrypt` (a fresh random nonce is generated and written here, `docs/DECISIONS.md`
    /// D-40), input path on `decrypt` (must be the value `encrypt` produced).
    pub nonce_path: PathBuf,
    pub aad_path: Option<PathBuf>,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub tag_path: PathBuf,
    /// (benchmarking only, `docs/TASKS.md` T-120) repeats seal/open `iterations` times over the same
    /// in-memory buffer before writing the final result - same convention as [`BlockArgs`].
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `kalyna-ccm encrypt`/`decrypt`'s flags: `--variant`/`--key`/`--nonce`/`--in`/`--out`/
/// `--tag` required, `--aad`/`--iterations` optional (an empty AAD is used if omitted). `--nonce`
/// is always required as a *path* by the parser, but [`run_ccm_command`] treats it as an output on
/// encrypt and an input on decrypt - see [`CcmArgs::nonce_path`].
///
/// # Errors
///
/// Same cases as [`parse_block_args`], plus `--nonce`/`--tag` sharing `--key`'s missing-flag
/// handling.
pub fn parse_ccm_args(args: &[String]) -> Result<CcmArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &[
            "--variant",
            "--key",
            "--nonce",
            "--aad",
            "--in",
            "--out",
            "--tag",
            "--iterations",
        ],
        &["--force"],
    )?;
    Ok(CcmArgs {
        variant: scanner.variant(KalynaVariant::parse)?,
        key_path: scanner.path("--key")?,
        nonce_path: scanner.path("--nonce")?,
        aad_path: scanner.path_opt("--aad"),
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        tag_path: scanner.path("--tag")?,
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `kalyna-ccm encrypt`/`decrypt` - see `hazmat::kalyna_ccm`'s module doc comment for the
/// construction's status (D-205) and its 255-byte plaintext/AAD limit. Encrypt writes
/// ciphertext to `--out`, the authentication tag to `--tag`, **and a freshly-generated random
/// nonce to `--nonce`** (separate files - this CLI does not invent its own combined wire format).
/// `--nonce` is an *output* on encrypt, not an input: per `docs/DECISIONS.md` D-40, the nonce is never
/// caller-supplied here, so there is nothing for a caller to accidentally reuse across two
/// encryptions under the same key. Decrypt reads `--nonce` (the value encrypt produced) and
/// `--tag`, verifies before writing anything, and returns [`CliError::CcmVerifyFailed`] without
/// touching `--out` on failure.
///
/// # Errors
///
/// Returns [`CliError::Io`]/[`CliError::WrongLength`] for file problems (key/nonce/tag must be
/// exactly the variant's expected length on decrypt), [`CliError::PlaintextTooLong`]/
/// [`CliError::AadTooLong`] if `--in`/`--aad` exceed the sourced limit, [`CliError::Random`] if the
/// OS CSPRNG fails on encrypt, or [`CliError::CcmVerifyFailed`] if `decrypt` fails to authenticate.
pub fn run_ccm_command(decrypt: bool, args: &CcmArgs) -> Result<(), CliError> {
    let key = read_exact_file(&args.key_path, LengthOf::Key, args.variant.key_len())?;
    let ((out, out_file), nonce_out, tag_out) = reserve_aead_outputs(
        decrypt,
        [&args.key_path, &args.nonce_path, &args.tag_path],
        &args.in_path,
        &args.out_path,
        args.force,
    )?;
    let nonce = if decrypt {
        read_exact_file(&args.nonce_path, LengthOf::Nonce, args.variant.block_len())?
    } else {
        let mut generated = vec![0u8; args.variant.block_len()];
        dstu_core::randombytes::randombytes_buf(&mut generated)
            .map_err(|e| CliError::Random(e.to_string()))?;
        generated
    };
    let aad = match &args.aad_path {
        Some(path) => std::fs::read(path).map_err(|e| CliError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?,
        None => Vec::new(),
    };
    let input = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;

    let iterations = args.iterations.max(1);
    macro_rules! run_ccm_variant {
        ($cipher:ty, $key_len:literal, $block_len:literal, $tag_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(&key);
            let mut nonce_arr = [0u8; $block_len];
            nonce_arr.copy_from_slice(&nonce);
            let cipher = <$cipher>::new(&key_arr);

            let tag_in = if decrypt {
                let tag = read_exact_file(&args.tag_path, LengthOf::Tag, $tag_len)?;
                let mut tag_arr = [0u8; $tag_len];
                tag_arr.copy_from_slice(&tag);
                Some(tag_arr)
            } else {
                None
            };

            let start = std::time::Instant::now();
            let mut buf = input.clone();
            let mut tag_out = None;
            for _ in 0..iterations {
                buf = input.clone();
                if decrypt {
                    cipher.open_in_place(&nonce_arr, &aad, &mut buf, tag_in.as_ref().unwrap())?;
                } else {
                    let tag = cipher.seal_in_place(&nonce_arr, &aad, &mut buf)?;
                    tag_out = Some(tag.to_vec());
                }
            }
            let elapsed = start.elapsed();
            (buf, tag_out, elapsed)
        }};
    }

    let (output, tag, elapsed) = match args.variant {
        KalynaVariant::K128_128 => run_ccm_variant!(Kalyna128_128Ccm, 16, 16, 16),
        KalynaVariant::K128_256 => run_ccm_variant!(Kalyna128_256Ccm, 32, 16, 16),
        KalynaVariant::K256_256 => run_ccm_variant!(Kalyna256_256Ccm, 32, 32, 16),
        KalynaVariant::K256_512 => run_ccm_variant!(Kalyna256_512Ccm, 64, 32, 32),
        KalynaVariant::K512_512 => run_ccm_variant!(Kalyna512_512Ccm, 64, 64, 64),
    };

    out.write_all_and_commit(out_file, &output)?;
    if let (Some(tag), Some((tag_out, tag_file))) = (tag, tag_out) {
        tag_out.write_all_and_commit(tag_file, &tag)?;
    }
    if let Some((nonce_out, nonce_file)) = nonce_out {
        nonce_out.write_all_and_commit(nonce_file, &nonce)?;
    }

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        eprintln!(
            "iterations={} total_ns={} per_op_ns={}",
            args.iterations,
            elapsed.as_nanos(),
            per_op_ns
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct GcmArgs {
    pub variant: KalynaVariant,
    /// encrypt: OUTPUT, a fresh random nonce is generated and written here. decrypt: INPUT, must
    /// be the nonce file `encrypt` produced - same convention as [`CcmArgs::nonce_path`] (D-40).
    pub key_path: PathBuf,
    pub nonce_path: PathBuf,
    pub aad_path: Option<PathBuf>,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    /// Always the variant's full block length (no `--tag-len` knob) - `hazmat::kalyna_gcm` allows
    /// a caller-truncated tag, but this benchmark CLI doesn't expose that choice (D-47's "delete
    /// the knob", same call `crypto_secretbox` already made for its own fixed-length tag).
    pub tag_path: PathBuf,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `kalyna-gcm encrypt`/`decrypt`'s flags - same shape as [`parse_ccm_args`].
///
/// # Errors
///
/// Same cases as [`parse_ccm_args`].
pub fn parse_gcm_args(args: &[String]) -> Result<GcmArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &[
            "--variant",
            "--key",
            "--nonce",
            "--aad",
            "--in",
            "--out",
            "--tag",
            "--iterations",
        ],
        &["--force"],
    )?;
    Ok(GcmArgs {
        variant: scanner.variant(KalynaVariant::parse)?,
        key_path: scanner.path("--key")?,
        nonce_path: scanner.path("--nonce")?,
        aad_path: scanner.path_opt("--aad"),
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        tag_path: scanner.path("--tag")?,
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `kalyna-gcm encrypt`/`decrypt` - `hazmat::kalyna_gcm`, benchmark-scoped like
/// [`run_ccm_command`] (`docs/DECISIONS.md` D-31/D-71). Unlike `kalyna-ccm`, GCM has no sourced
/// plaintext/AAD length cap.
///
/// # Errors
///
/// Same cases as [`run_ccm_command`], plus [`CliError::GcmVerifyFailed`] on a failed decrypt.
pub fn run_gcm_command(decrypt: bool, args: &GcmArgs) -> Result<(), CliError> {
    let key = read_exact_file(&args.key_path, LengthOf::Key, args.variant.key_len())?;
    let ((out, out_file), nonce_out, tag_out) = reserve_aead_outputs(
        decrypt,
        [&args.key_path, &args.nonce_path, &args.tag_path],
        &args.in_path,
        &args.out_path,
        args.force,
    )?;
    let nonce = if decrypt {
        read_exact_file(&args.nonce_path, LengthOf::Nonce, args.variant.block_len())?
    } else {
        let mut generated = vec![0u8; args.variant.block_len()];
        dstu_core::randombytes::randombytes_buf(&mut generated)
            .map_err(|e| CliError::Random(e.to_string()))?;
        generated
    };
    let aad = match &args.aad_path {
        Some(path) => std::fs::read(path).map_err(|e| CliError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?,
        None => Vec::new(),
    };
    let input = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;

    let iterations = args.iterations.max(1);
    macro_rules! run_gcm_variant {
        ($cipher:ty, $key_len:literal, $block_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(&key);
            let mut nonce_arr = [0u8; $block_len];
            nonce_arr.copy_from_slice(&nonce);
            let cipher = <$cipher>::new(&key_arr);

            let tag_in = if decrypt {
                Some(read_exact_file(&args.tag_path, LengthOf::Tag, $block_len)?)
            } else {
                None
            };

            let start = std::time::Instant::now();
            let mut buf = vec![0u8; input.len()];
            let mut tag_out = [0u8; $block_len];
            for _ in 0..iterations {
                if decrypt {
                    cipher.decrypt(&nonce_arr, &aad, &input, tag_in.as_ref().unwrap(), &mut buf)?;
                } else {
                    tag_out = cipher.encrypt(&nonce_arr, &aad, &input, &mut buf)?;
                }
            }
            let elapsed = start.elapsed();
            let tag = if decrypt {
                None
            } else {
                Some(tag_out.to_vec())
            };
            (buf, tag, elapsed)
        }};
    }

    let (output, tag, elapsed) = match args.variant {
        KalynaVariant::K128_128 => run_gcm_variant!(Kalyna128_128Gcm, 16, 16),
        KalynaVariant::K128_256 => run_gcm_variant!(Kalyna128_256Gcm, 32, 16),
        KalynaVariant::K256_256 => run_gcm_variant!(Kalyna256_256Gcm, 32, 32),
        KalynaVariant::K256_512 => run_gcm_variant!(Kalyna256_512Gcm, 64, 32),
        KalynaVariant::K512_512 => run_gcm_variant!(Kalyna512_512Gcm, 64, 64),
    };

    out.write_all_and_commit(out_file, &output)?;
    if let (Some(tag), Some((tag_out, tag_file))) = (tag, tag_out) {
        tag_out.write_all_and_commit(tag_file, &tag)?;
    }
    if let Some((nonce_out, nonce_file)) = nonce_out {
        nonce_out.write_all_and_commit(nonce_file, &nonce)?;
    }

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        eprintln!(
            "iterations={} total_ns={} per_op_ns={}",
            args.iterations,
            elapsed.as_nanos(),
            per_op_ns
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct CmacArgs {
    pub variant: KalynaVariant,
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    /// `compute`: OUTPUT, the 16-byte tag is written here. `verify`: unused (see `tag_path`).
    pub out_path: Option<PathBuf>,
    /// `verify`: INPUT, the tag to check against. `compute`: unused (see `out_path`).
    pub tag_path: Option<PathBuf>,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `kalyna-cmac compute`/`verify`'s flags: `--variant`/`--key`/`--in` required, plus
/// `--out` (compute) or `--tag` (verify) depending on the subcommand - [`run_cmac_command`]
/// decides which one is actually required, since the parser alone can't know which subcommand
/// called it.
///
/// # Errors
///
/// [`CliError::MissingFlag`]/[`CliError::UnknownVariant`]/[`CliError::InvalidIterations`]/
/// [`CliError::UnknownFlag`], same cases as [`parse_block_args`].
pub fn parse_cmac_args(args: &[String]) -> Result<CmacArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &[
            "--variant",
            "--key",
            "--in",
            "--out",
            "--tag",
            "--iterations",
        ],
        &["--force"],
    )?;
    Ok(CmacArgs {
        variant: scanner.variant(KalynaVariant::parse)?,
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path_opt("--out"),
        tag_path: scanner.path_opt("--tag"),
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `kalyna-cmac compute` (`verify = false`, writes the 16-byte tag to `args.out_path`) or
/// `kalyna-cmac verify` (`verify = true`, checks `args.tag_path` and returns
/// [`CliError::CmacVerifyFailed`] on mismatch) - `hazmat::kalyna_cmac`, benchmark-scoped
/// (`docs/DECISIONS.md` D-31/D-71).
///
/// # Errors
///
/// [`CliError::Io`]/[`CliError::WrongLength`] for file problems, [`CliError::MissingFlag`] if
/// `compute` is missing `--out` or `verify` is missing `--tag`, or
/// [`CliError::CmacVerifyFailed`] if `verify` fails to authenticate.
pub fn run_cmac_command(verify: bool, args: &CmacArgs) -> Result<(), CliError> {
    let key = read_exact_file(&args.key_path, LengthOf::Key, args.variant.key_len())?;
    let tag_out = if verify {
        None
    } else {
        let out_path = args.out_path.as_ref().ok_or(CliError::MissingFlag("out"))?;
        check_outputs(&[("--out", out_path)], &[("--key", &args.key_path)])?;
        Some(OutputFile::create(out_path, &args.in_path, args.force)?)
    };
    let message = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;
    let tag_in = if verify {
        Some(read_exact_file(
            args.tag_path.as_ref().ok_or(CliError::MissingFlag("tag"))?,
            LengthOf::Tag,
            16,
        )?)
    } else {
        None
    };

    let iterations = args.iterations.max(1);
    // `_with_cipher` (`docs/DECISIONS.md` D-76 / `docs/TASKS.md` T-127): the key schedule is expanded once
    // outside this loop, matching `kalyna-block`/`kalyna-gcm`/`kalyna-xts`'s own cached-schedule
    // convention - `<$mac>::mac`'s raw-key-bytes form would otherwise re-expand it every iteration.
    macro_rules! run_cmac_variant {
        ($mac:ty, $expanded:ty, $key_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(&key);
            let cipher = <$expanded>::new(&key_arr);

            let start = std::time::Instant::now();
            let mut tag = [0u8; 16];
            for _ in 0..iterations {
                if verify {
                    let mut expected = [0u8; 16];
                    expected.copy_from_slice(tag_in.as_ref().unwrap());
                    <$mac>::verify_with_cipher(&cipher, &message, &expected)?;
                } else {
                    tag = <$mac>::mac_with_cipher(&cipher, &message)?;
                }
            }
            (tag, start.elapsed())
        }};
    }

    let (tag, elapsed) = match args.variant {
        KalynaVariant::K128_128 => {
            run_cmac_variant!(Kalyna128_128Cmac, Kalyna128_128ExpandedKey, 16)
        }
        KalynaVariant::K128_256 => {
            run_cmac_variant!(Kalyna128_256Cmac, Kalyna128_256ExpandedKey, 32)
        }
        KalynaVariant::K256_256 => {
            run_cmac_variant!(Kalyna256_256Cmac, Kalyna256_256ExpandedKey, 32)
        }
        KalynaVariant::K256_512 => {
            run_cmac_variant!(Kalyna256_512Cmac, Kalyna256_512ExpandedKey, 64)
        }
        KalynaVariant::K512_512 => {
            run_cmac_variant!(Kalyna512_512Cmac, Kalyna512_512ExpandedKey, 64)
        }
    };

    if let Some((tag_out, tag_file)) = tag_out {
        tag_out.write_all_and_commit(tag_file, &tag)?;
    }

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        eprintln!(
            "iterations={} total_ns={} per_op_ns={}",
            args.iterations,
            elapsed.as_nanos(),
            per_op_ns
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct GmacArgs {
    pub variant: KalynaVariant,
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: Option<PathBuf>,
    pub tag_path: Option<PathBuf>,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `kalyna-gmac compute`/`verify`'s flags - same shape as [`parse_cmac_args`]. **No
/// `--nonce`**: unlike [`kalyna_gmac`](dstu_core::hazmat::kalyna_gmac), GCM's other MAC-only
/// sibling, `hazmat::kalyna_gmac::mac`/`verify` take no IV at all (confirmed by reading the
/// module, not assumed from GCM's shape) - so there is nothing here for a `--nonce` flag to pass.
///
/// # Errors
///
/// Same cases as [`parse_cmac_args`].
pub fn parse_gmac_args(args: &[String]) -> Result<GmacArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &[
            "--variant",
            "--key",
            "--in",
            "--out",
            "--tag",
            "--iterations",
        ],
        &["--force"],
    )?;
    Ok(GmacArgs {
        variant: scanner.variant(KalynaVariant::parse)?,
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path_opt("--out"),
        tag_path: scanner.path_opt("--tag"),
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `kalyna-gmac compute`/`verify` - `hazmat::kalyna_gmac`, benchmark-scoped
/// (`docs/DECISIONS.md` D-31/D-71). Tag length is the variant's full block length (no `--tag-len`
/// knob, same choice as [`run_gcm_command`]).
///
/// # Errors
///
/// Same cases as [`run_cmac_command`], plus [`CliError::GmacVerifyFailed`] on a failed `verify`.
pub fn run_gmac_command(verify: bool, args: &GmacArgs) -> Result<(), CliError> {
    let key = read_exact_file(&args.key_path, LengthOf::Key, args.variant.key_len())?;
    let tag_out = if verify {
        None
    } else {
        let out_path = args.out_path.as_ref().ok_or(CliError::MissingFlag("out"))?;
        check_outputs(&[("--out", out_path)], &[("--key", &args.key_path)])?;
        Some(OutputFile::create(out_path, &args.in_path, args.force)?)
    };
    let message = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;
    let tag_in = if verify {
        Some(
            std::fs::read(args.tag_path.as_ref().ok_or(CliError::MissingFlag("tag"))?).map_err(
                |e| CliError::Io {
                    path: args.tag_path.clone().unwrap_or_default(),
                    message: e.to_string(),
                },
            )?,
        )
    } else {
        None
    };

    let iterations = args.iterations.max(1);
    // `_with_cipher` (`docs/DECISIONS.md` D-76 / `docs/TASKS.md` T-127) - same cached-schedule convention as
    // `run_cmac_command` above.
    macro_rules! run_gmac_variant {
        ($mac:ty, $expanded:ty, $key_len:literal, $block_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(&key);
            let cipher = <$expanded>::new(&key_arr);

            let start = std::time::Instant::now();
            let mut tag = [0u8; $block_len];
            for _ in 0..iterations {
                if verify {
                    <$mac>::verify_with_cipher(&cipher, &message, tag_in.as_ref().unwrap())?;
                } else {
                    tag = <$mac>::mac_with_cipher(&cipher, &message)?;
                }
            }
            (tag.to_vec(), start.elapsed())
        }};
    }

    let (tag, elapsed) = match args.variant {
        KalynaVariant::K128_128 => {
            run_gmac_variant!(Kalyna128_128Gmac, Kalyna128_128ExpandedKey, 16, 16)
        }
        KalynaVariant::K128_256 => {
            run_gmac_variant!(Kalyna128_256Gmac, Kalyna128_256ExpandedKey, 32, 16)
        }
        KalynaVariant::K256_256 => {
            run_gmac_variant!(Kalyna256_256Gmac, Kalyna256_256ExpandedKey, 32, 32)
        }
        KalynaVariant::K256_512 => {
            run_gmac_variant!(Kalyna256_512Gmac, Kalyna256_512ExpandedKey, 64, 32)
        }
        KalynaVariant::K512_512 => {
            run_gmac_variant!(Kalyna512_512Gmac, Kalyna512_512ExpandedKey, 64, 64)
        }
    };

    if let Some((tag_out, tag_file)) = tag_out {
        tag_out.write_all_and_commit(tag_file, &tag)?;
    }

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        eprintln!(
            "iterations={} total_ns={} per_op_ns={}",
            args.iterations,
            elapsed.as_nanos(),
            per_op_ns
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct KwArgs {
    pub variant: KalynaVariant,
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `kalyna-kw wrap`/`unwrap`'s flags: `--variant`/`--key`/`--in`/`--out` required,
/// `--iterations` optional - same shape as [`parse_block_args`] minus `--raw-schedule` (KW has no
/// cached-vs-raw distinction to expose, same reason [`kupyna-digest`](parse_digest_args) doesn't).
///
/// # Errors
///
/// Same cases as [`parse_block_args`].
pub fn parse_kw_args(args: &[String]) -> Result<KwArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &["--variant", "--key", "--in", "--out", "--iterations"],
        &["--force"],
    )?;
    Ok(KwArgs {
        variant: scanner.variant(KalynaVariant::parse)?,
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `kalyna-kw wrap` (`unwrap = false`, `--in` is the key material to wrap) or
/// `kalyna-kw unwrap` (`unwrap = true`, `--in` is a wrapped blob) - `hazmat::kalyna_kw`,
/// benchmark-scoped (`docs/DECISIONS.md` D-31/D-71). `--in` must be block-aligned (1..=20 blocks for
/// `wrap`, 2..=21 blocks for `unwrap` - see `hazmat::kalyna_kw`'s `MAX_R` bound).
///
/// # Errors
///
/// [`CliError::Io`]/[`CliError::WrongLength`] for file problems, [`CliError::KwInvalidLength`] if
/// `--in` isn't block-aligned or within `MAX_R`, or [`CliError::KwChecksumMismatch`] if `unwrap`'s
/// trailing checksum block doesn't verify.
pub fn run_kw_command(unwrap: bool, args: &KwArgs) -> Result<(), CliError> {
    let key = read_exact_file(&args.key_path, LengthOf::Key, args.variant.key_len())?;
    check_outputs(&[("--out", &args.out_path)], &[("--key", &args.key_path)])?;
    let (out, out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;
    let input = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;

    let iterations = args.iterations.max(1);
    // `_with_cipher` (`docs/DECISIONS.md` D-76 / `docs/TASKS.md` T-127) - same cached-schedule convention as
    // `run_cmac_command`/`run_gmac_command` above; this is the one benchmark T-127 identified where
    // the redone-every-call schedule cost isn't amortized by message size (KW's input is at most
    // `MAX_R` blocks), so this fix has the most direct effect on KW's own reported numbers.
    macro_rules! run_kw_variant {
        ($kw:ty, $expanded:ty, $key_len:literal, $block_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(&key);
            let cipher = <$expanded>::new(&key_arr);

            let out_len = if unwrap {
                input
                    .len()
                    .checked_sub($block_len)
                    .ok_or(CliError::KwInvalidLength)?
            } else {
                input.len() + $block_len
            };
            let mut out = vec![0u8; out_len];

            let start = std::time::Instant::now();
            for _ in 0..iterations {
                if unwrap {
                    <$kw>::unwrap_with_cipher(&cipher, &input, &mut out).map_err(|e| match e {
                        dstu_core::hazmat::kalyna_kw::KwError::InvalidLength => {
                            CliError::KwInvalidLength
                        }
                        dstu_core::hazmat::kalyna_kw::KwError::ChecksumMismatch => {
                            CliError::KwChecksumMismatch
                        }
                    })?;
                } else {
                    <$kw>::wrap_with_cipher(&cipher, &input, &mut out)
                        .map_err(|_| CliError::KwInvalidLength)?;
                }
            }
            (out, start.elapsed())
        }};
    }

    let (output, elapsed) = match args.variant {
        KalynaVariant::K128_128 => {
            run_kw_variant!(Kalyna128_128Kw, Kalyna128_128ExpandedKey, 16, 16)
        }
        KalynaVariant::K128_256 => {
            run_kw_variant!(Kalyna128_256Kw, Kalyna128_256ExpandedKey, 32, 16)
        }
        KalynaVariant::K256_256 => {
            run_kw_variant!(Kalyna256_256Kw, Kalyna256_256ExpandedKey, 32, 32)
        }
        KalynaVariant::K256_512 => {
            run_kw_variant!(Kalyna256_512Kw, Kalyna256_512ExpandedKey, 64, 32)
        }
        KalynaVariant::K512_512 => {
            run_kw_variant!(Kalyna512_512Kw, Kalyna512_512ExpandedKey, 64, 64)
        }
    };

    out.write_all_and_commit(out_file, &output)?;

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        eprintln!(
            "iterations={} total_ns={} per_op_ns={}",
            args.iterations,
            elapsed.as_nanos(),
            per_op_ns
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct XtsArgs {
    pub variant: KalynaVariant,
    pub key_path: PathBuf,
    /// One block's worth of bytes - the "data unit" tweak seed (`hazmat::kalyna_xts`'s `iv`
    /// parameter), not a sector index this CLI derives on the caller's behalf.
    pub tweak_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `kalyna-xts encrypt`/`decrypt`'s flags: `--variant`/`--key`/`--tweak`/`--in`/`--out`
/// required, `--iterations` optional.
///
/// # Errors
///
/// Same cases as [`parse_block_args`], plus `--tweak` sharing `--key`'s missing-flag handling.
pub fn parse_xts_args(args: &[String]) -> Result<XtsArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &[
            "--variant",
            "--key",
            "--tweak",
            "--in",
            "--out",
            "--iterations",
        ],
        &["--force"],
    )?;
    Ok(XtsArgs {
        variant: scanner.variant(KalynaVariant::parse)?,
        key_path: scanner.path("--key")?,
        tweak_path: scanner.path("--tweak")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `kalyna-xts encrypt`/`decrypt` - `hazmat::kalyna_xts`, benchmark-scoped
/// (`docs/DECISIONS.md` D-31/D-71). Confidentiality-only, no tag - see the module doc comment for why
/// that's the correct design for this mode, not a gap. `--in` must be at least one block long.
///
/// # Errors
///
/// [`CliError::Io`]/[`CliError::WrongLength`] for file problems, or
/// [`CliError::XtsInvalidLength`] if `--in` is shorter than one block.
pub fn run_xts_command(decrypt: bool, args: &XtsArgs) -> Result<(), CliError> {
    let key = read_exact_file(&args.key_path, LengthOf::Key, args.variant.key_len())?;
    let tweak = read_exact_file(&args.tweak_path, LengthOf::Tweak, args.variant.block_len())?;
    check_outputs(
        &[("--out", &args.out_path)],
        &[("--key", &args.key_path), ("--tweak", &args.tweak_path)],
    )?;
    let (out, out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;
    let input = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;

    let iterations = args.iterations.max(1);
    macro_rules! run_xts_variant {
        ($xts:ty, $key_len:literal, $block_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(&key);
            let mut tweak_arr = [0u8; $block_len];
            tweak_arr.copy_from_slice(&tweak);
            let cipher = <$xts>::new(&key_arr);

            let start = std::time::Instant::now();
            let mut buf = input.clone();
            for _ in 0..iterations {
                buf = input.clone();
                if decrypt {
                    cipher
                        .decrypt_in_place(&tweak_arr, &mut buf)
                        .map_err(|_| CliError::XtsInvalidLength)?;
                } else {
                    cipher
                        .encrypt_in_place(&tweak_arr, &mut buf)
                        .map_err(|_| CliError::XtsInvalidLength)?;
                }
            }
            (buf, start.elapsed())
        }};
    }

    let (output, elapsed) = match args.variant {
        KalynaVariant::K128_128 => run_xts_variant!(Kalyna128_128Xts, 16, 16),
        KalynaVariant::K128_256 => run_xts_variant!(Kalyna128_256Xts, 32, 16),
        KalynaVariant::K256_256 => run_xts_variant!(Kalyna256_256Xts, 32, 32),
        KalynaVariant::K256_512 => run_xts_variant!(Kalyna256_512Xts, 64, 32),
        KalynaVariant::K512_512 => run_xts_variant!(Kalyna512_512Xts, 64, 64),
    };

    out.write_all_and_commit(out_file, &output)?;

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        eprintln!(
            "iterations={} total_ns={} per_op_ns={}",
            args.iterations,
            elapsed.as_nanos(),
            per_op_ns
        );
    }

    Ok(())
}

const SECRETSTREAM_KEY_LEN: usize = 32;
const SECRETSTREAM_HEADER_LEN: usize = 32;
const SECRETSTREAM_TAG_LEN: usize = 16;

/// Plaintext bytes per record in the `encrypt` file format. It is part of the wire format (D-208):
/// every non-`Final` record is exactly this long and the `Final` one at most this long, `decrypt`
/// rejects anything else, and the 8 language bindings' readers and writers use the same number.
/// Changing it therefore needs a new format version, not just a rebuild. It also bounds peak
/// memory on both sides, independent of `--in`'s size (D-42).
const SECRETSTREAM_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct SecretstreamArgs {
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `encrypt`/`decrypt`'s flags (`--key`/`--in`/`--out`, all required). No `--nonce`/`--tag`/
/// `--aad`/`--variant` - `dstu_core::crypto_secretstream` (D-68) already removed every one of those
/// knobs: a single fixed construction, an internally-generated header, no caller-facing AAD, and
/// one chunked output stream, so there is nothing left here for a CLI flag to expose.
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`] or [`CliError::UnknownFlag`].
pub fn parse_secretstream_args(args: &[String]) -> Result<SecretstreamArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--key", "--in", "--out"], &["--force"])?;
    Ok(SecretstreamArgs {
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        force: scanner.bool_flag("--force"),
    })
}

/// A fresh temp path next to `out_path` (same directory, so the final `std::fs::rename` stays on
/// one filesystem), with a random suffix from the OS CSPRNG. A fixed suffix let anyone who can
/// write to that directory plant a symlink there in advance (T-241). The suffix is appended to the
/// `OsString`, not built with `Path::with_extension` (which would replace an existing extension) or
/// `format!` (lossy on non-UTF-8 paths).
///
/// # Errors
///
/// Returns [`CliError::Random`] if the OS CSPRNG fails.
fn temp_path_beside(out_path: &std::path::Path) -> Result<PathBuf, CliError> {
    let mut suffix = [0u8; 8];
    dstu_core::randombytes::randombytes_buf(&mut suffix)
        .map_err(|e| CliError::Random(e.to_string()))?;
    let mut name = out_path.as_os_str().to_os_string();
    name.push(".uacrypt-tmp-");
    for byte in suffix {
        name.push(format!("{byte:02x}"));
    }
    Ok(PathBuf::from(name))
}

/// Opens `path` for writing only if nothing exists there yet, whether a file or a symlink:
/// `create_new` is `O_CREAT | O_EXCL`, which never follows a link. On Unix the file gets mode
/// `0600`, so a key, a temp file or a decrypted plaintext is never readable by other users. On
/// Windows it inherits its directory's ACL (T-241).
fn create_private_new(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Refuses an existing regular file at an output path that starts like a typed key file, or that
/// cannot be read to find out (T-268, R2, `docs/DECISIONS.md` D-216): `--force` never destroys a
/// key. Reads only [`keyfile::SNIFF_LEN`] bytes, never key hex. A symlink is not followed: the
/// rename replaces the link itself. A safety net, not a boundary - raw keys are not recognised, and
/// the file can change between this check and the rename.
///
/// # Errors
///
/// [`CliError::OutputIsKeyFile`] or [`CliError::OutputUncheckable`].
fn refuse_key_file(path: &std::path::Path) -> Result<(), CliError> {
    use std::io::Read;

    if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
        return Ok(());
    }
    let mut head = Vec::with_capacity(keyfile::SNIFF_LEN);
    std::fs::File::open(path)
        .and_then(|file| file.take(keyfile::SNIFF_LEN as u64).read_to_end(&mut head))
        .map_err(|e| CliError::OutputUncheckable {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
    match keyfile::sniff_kind(&head) {
        Some(kind) => Err(CliError::OutputIsKeyFile {
            path: path.to_path_buf(),
            kind,
        }),
        None => Ok(()),
    }
}

/// One non-key output file (`docs/TASKS.md` T-258, rule R2, `docs/DECISIONS.md` D-214). The
/// result is written to a private temp file beside `path` and only renamed onto it by
/// [`OutputFile::commit`], so a failed command never leaves partial output. Without `--force`,
/// [`OutputFile::create`] first reserves `path` as an empty placeholder with `create_new`, which
/// refuses an existing file or symlink atomically and before any work is done; std has no
/// rename that refuses to replace, and a hard-link publish fails on FAT/exFAT. With `--force` there
/// is no placeholder and the rename replaces the old file (or a symlink itself, never its target).
/// Dropped without a commit, it removes the temp file and the placeholder.
struct OutputFile {
    path: PathBuf,
    tmp_path: Option<PathBuf>,
    placeholder: bool,
    committed: bool,
}

impl OutputFile {
    /// Reserves `path` (unless `force`) and opens the temp file the output is written to.
    /// `input` only shapes the error message when `path` already exists.
    ///
    /// # Errors
    ///
    /// [`CliError::OutputExists`] if `path` exists and `force` is off, [`CliError::Random`] if the
    /// temp name cannot be drawn, or [`CliError::Io`].
    fn create(
        path: &std::path::Path,
        input: &std::path::Path,
        force: bool,
    ) -> Result<(Self, std::fs::File), CliError> {
        let io_err = |p: &std::path::Path, e: std::io::Error| CliError::Io {
            path: p.to_path_buf(),
            message: e.to_string(),
        };
        let mut output = Self {
            path: path.to_path_buf(),
            tmp_path: None,
            placeholder: false,
            committed: false,
        };
        if force {
            refuse_key_file(path)?;
        } else {
            match create_private_new(path) {
                Ok(_) => output.placeholder = true,
                // Windows reports a directory as access denied, not as already existing.
                Err(_) if path.is_dir() => {
                    return Err(io_err(path, std::io::Error::other("is a directory")));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    refuse_key_file(path)?;
                    return Err(CliError::OutputExists {
                        path: path.to_path_buf(),
                        same_as_input: same_file(path, input),
                    });
                }
                Err(e) => return Err(io_err(path, e)),
            }
        }
        let tmp_path = temp_path_beside(path)?;
        let file = create_private_new(&tmp_path).map_err(|e| io_err(&tmp_path, e))?;
        output.tmp_path = Some(tmp_path);
        Ok((output, file))
    }

    /// The temp path, for error messages about writes to the file [`OutputFile::create`] returned.
    fn tmp_path(&self) -> &std::path::Path {
        self.tmp_path.as_deref().unwrap_or(&self.path)
    }

    /// Flushes `file` to disk, closes it (Windows cannot rename an open file) and renames it onto
    /// the output path.
    ///
    /// # Errors
    ///
    /// [`CliError::Io`]; the temp file and placeholder are then removed on drop.
    fn commit(mut self, file: std::fs::File) -> Result<(), CliError> {
        file.sync_all().map_err(|e| CliError::Io {
            path: self.tmp_path().to_path_buf(),
            message: e.to_string(),
        })?;
        drop(file);
        if let Some(tmp_path) = &self.tmp_path {
            std::fs::rename(tmp_path, &self.path).map_err(|e| CliError::Io {
                path: self.path.clone(),
                message: e.to_string(),
            })?;
        }
        self.committed = true;
        Ok(())
    }

    /// Writes `bytes` to `file` and commits it - the whole-buffer commands' single write.
    ///
    /// # Errors
    ///
    /// [`CliError::Io`].
    fn write_all_and_commit(self, mut file: std::fs::File, bytes: &[u8]) -> Result<(), CliError> {
        use std::io::Write;
        file.write_all(bytes).map_err(|e| CliError::Io {
            path: self.tmp_path().to_path_buf(),
            message: e.to_string(),
        })?;
        self.commit(file)
    }
}

impl Drop for OutputFile {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(tmp_path) = &self.tmp_path {
            let _ = std::fs::remove_file(tmp_path);
        }
        if self.placeholder {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Whether `a` and `b` resolve to the same existing path (symlinks followed). Only used to word
/// [`CliError::OutputExists`]; a hard link to `--in` is still refused, just without the hint.
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    matches!(
        (std::fs::canonicalize(a), std::fs::canonicalize(b)),
        (Ok(x), Ok(y)) if x == y
    )
}

/// One reserved output and the temp file it is written to.
type ReservedOutput = (OutputFile, std::fs::File);

/// The outputs of `kalyna-ccm`/`kalyna-gcm` (T-258, D-214): `--out` always, plus `--nonce` and
/// `--tag` on encrypt, all reserved up front so a failure releases every one. On decrypt `--nonce`
/// and `--tag` are inputs, protected like `--key` from being named as `--out`.
///
/// # Errors
///
/// [`CliError::SameOutputPath`], or whatever [`OutputFile::create`] returns.
fn reserve_aead_outputs(
    decrypt: bool,
    [key, nonce, tag]: [&std::path::Path; 3],
    input: &std::path::Path,
    out: &std::path::Path,
    force: bool,
) -> Result<
    (
        ReservedOutput,
        Option<ReservedOutput>,
        Option<ReservedOutput>,
    ),
    CliError,
> {
    if decrypt {
        check_outputs(
            &[("--out", out)],
            &[("--key", key), ("--nonce", nonce), ("--tag", tag)],
        )?;
        return Ok((OutputFile::create(out, input, force)?, None, None));
    }
    check_outputs(
        &[("--nonce", nonce), ("--out", out), ("--tag", tag)],
        &[("--key", key)],
    )?;
    let out = OutputFile::create(out, input, force)?;
    let nonce = OutputFile::create(nonce, input, force)?;
    let tag = OutputFile::create(tag, input, force)?;
    Ok((out, Some(nonce), Some(tag)))
}

/// Refuses an output that names the same file as another output or as one of the command's key
/// inputs (T-258, D-214): `decrypt --key k --out k --force` would otherwise replace the only key
/// for the file with its plaintext, and two outputs would silently replace each other. A usage
/// error with or without `--force`; without it the "pass --force" hint would be wrong. Paths are
/// compared as absolute paths and, when both exist, after resolving symlinks.
///
/// # Errors
///
/// [`CliError::SameOutputPath`] for the first such pair.
fn check_outputs(
    outputs: &[(&'static str, &std::path::Path)],
    keys: &[(&'static str, &std::path::Path)],
) -> Result<(), CliError> {
    let absolute = |p: &std::path::Path| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    for (i, (flag, path)) in outputs.iter().enumerate() {
        for (other, other_path) in outputs[i + 1..].iter().chain(keys) {
            if absolute(path) == absolute(other_path) || same_file(path, other_path) {
                return Err(CliError::SameOutputPath(flag, other));
            }
        }
    }
    Ok(())
}

/// Writes a key file (secret or public) to `path` via [`create_private_new`]. It refuses to
/// replace anything already there, because a keygen run over an existing key file would destroy
/// that key and everything encrypted to it (T-241, owner decision 2026-09-23); a public key gets
/// the same refusal, with no `--force`, since `box-pubkey --key k --out k` would otherwise destroy
/// the secret key it was derived from (T-258, D-214). A failed write removes the partial file.
///
/// # Errors
///
/// Returns [`CliError::KeyFileExists`] if `path` exists (including as a symlink), or
/// [`CliError::Io`] for any other open/write/sync failure.
fn write_new_key_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    let io_err = |e: std::io::Error| CliError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    };
    let mut file = create_private_new(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::KeyFileExists(path.to_path_buf())
        } else {
            io_err(e)
        }
    })?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(io_err(e));
    }
    Ok(())
}

fn read_exact_or_truncated(
    file: &mut std::fs::File,
    buf: &mut [u8],
    path: &std::path::Path,
) -> Result<(), CliError> {
    use std::io::Read;
    match file.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(CliError::SecretstreamTruncated)
        }
        Err(e) => Err(CliError::Io {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
    }
}

/// Encrypts `in_path` into `tmp_path` (the caller renames onto the real `--out` only after this
/// returns `Ok`) using [`dstu_core::crypto_secretstream::PushState`]. One-chunk-ahead buffering
/// (`cur`/`next`) is what lets the last chunk be tagged
/// [`Tag::Final`](dstu_core::crypto_secretstream::Tag::Final) without a second pass over the file -
/// including the empty-input case, which produces a single zero-length `Final` chunk.
/// Reads from `reader` until `buf` is full or the input ends, and returns how many bytes it got. A
/// single `read` may legally return fewer bytes than asked for, which would emit a short
/// non-`Final` record that every reader rejects (D-208).
fn fill_chunk(reader: &mut impl std::io::Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Writes the `encrypt` file format (D-208) for everything `input` yields: the format version byte,
/// the secretstream header, then one record per [`SECRETSTREAM_CHUNK_BYTES`] of plaintext.
fn write_secretstream_file(
    key: &dstu_core::crypto_secretstream::Key,
    input: &mut impl std::io::Read,
    in_path: &std::path::Path,
    out_file: &mut impl std::io::Write,
    tmp_path: &std::path::Path,
) -> Result<(), CliError> {
    use dstu_core::crypto_secretstream::{PushState, Tag, FORMAT_VERSION};

    let (mut push, header) = PushState::init(key)?;
    out_file
        .write_all(&[FORMAT_VERSION])
        .and_then(|()| out_file.write_all(&header))
        .map_err(|e| CliError::Io {
            path: tmp_path.to_path_buf(),
            message: e.to_string(),
        })?;

    let mut read_chunk = |buf: &mut [u8]| -> Result<usize, CliError> {
        fill_chunk(input, buf).map_err(|e| CliError::Io {
            path: in_path.to_path_buf(),
            message: e.to_string(),
        })
    };

    let mut cur = vec![0u8; SECRETSTREAM_CHUNK_BYTES];
    let mut cur_len = read_chunk(&mut cur)?;
    loop {
        let mut next = vec![0u8; SECRETSTREAM_CHUNK_BYTES];
        let next_len = read_chunk(&mut next)?;
        let tag = if next_len == 0 {
            Tag::Final
        } else {
            Tag::Message
        };

        let mut ciphertext = vec![0u8; cur_len];
        let auth_tag = push.push(tag, &cur[..cur_len], &mut ciphertext)?;

        #[allow(clippy::cast_possible_truncation)]
        // cur_len <= SECRETSTREAM_CHUNK_BYTES, always << u32::MAX
        let chunk_len = cur_len as u32;
        out_file
            .write_all(&[tag.to_byte()])
            .and_then(|()| out_file.write_all(&chunk_len.to_le_bytes()))
            .and_then(|()| out_file.write_all(&ciphertext))
            .and_then(|()| out_file.write_all(&auth_tag))
            .map_err(|e| CliError::Io {
                path: tmp_path.to_path_buf(),
                message: e.to_string(),
            })?;

        if next_len == 0 {
            break;
        }
        cur = next;
        cur_len = next_len;
    }
    Ok(())
}

fn run_secretstream_encrypt(
    key: &dstu_core::crypto_secretstream::Key,
    in_path: &PathBuf,
    out_file: &mut std::fs::File,
    tmp_path: &std::path::Path,
) -> Result<(), CliError> {
    let mut in_file = std::fs::File::open(in_path).map_err(|e| CliError::Io {
        path: in_path.clone(),
        message: e.to_string(),
    })?;
    write_secretstream_file(key, &mut in_file, in_path, out_file, tmp_path)
}

/// Decrypts `in_path` into `tmp_path` (the caller renames onto the real `--out` only after this
/// returns `Ok`) using [`dstu_core::crypto_secretstream::PullState`]. It checks the format version
/// byte first, and that every non-`Final` record is exactly [`SECRETSTREAM_CHUNK_BYTES`] long
/// (D-208). Stops as soon as a
/// [`Tag::Final`](dstu_core::crypto_secretstream::Tag::Final) chunk verifies, then checks for
/// trailing bytes - both an early EOF (no `Final` ever seen, via [`read_exact_or_truncated`]) and
/// leftover bytes after `Final` are rejected, not silently accepted.
fn run_secretstream_decrypt(
    key: &dstu_core::crypto_secretstream::Key,
    in_path: &PathBuf,
    out_file: &mut std::fs::File,
    tmp_path: &std::path::Path,
) -> Result<(), CliError> {
    use dstu_core::crypto_secretstream::{PullState, Tag};
    use std::io::{Read, Write};

    let mut in_file = std::fs::File::open(in_path).map_err(|e| CliError::Io {
        path: in_path.clone(),
        message: e.to_string(),
    })?;

    let mut version = [0u8; 1];
    read_exact_or_truncated(&mut in_file, &mut version, in_path)?;
    if version[0] != dstu_core::crypto_secretstream::FORMAT_VERSION {
        return Err(CliError::SecretstreamUnsupportedVersion(version[0]));
    }
    let mut header = [0u8; SECRETSTREAM_HEADER_LEN];
    read_exact_or_truncated(&mut in_file, &mut header, in_path)?;
    let mut pull = PullState::init(key, &header);

    loop {
        let mut prefix = [0u8; 5];
        read_exact_or_truncated(&mut in_file, &mut prefix, in_path)?;
        let tag_byte = prefix[0];
        let chunk_len = u32::from_le_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]) as usize;
        if chunk_len > SECRETSTREAM_CHUNK_BYTES {
            return Err(CliError::SecretstreamChunkTooLarge);
        }
        let Some(declared) = Tag::from_byte(tag_byte) else {
            return Err(CliError::SecretstreamUnknownTag);
        };
        if declared != Tag::Final && chunk_len != SECRETSTREAM_CHUNK_BYTES {
            return Err(CliError::SecretstreamBadChunkLength);
        }

        let mut ciphertext = vec![0u8; chunk_len];
        read_exact_or_truncated(&mut in_file, &mut ciphertext, in_path)?;
        let mut auth_tag = [0u8; SECRETSTREAM_TAG_LEN];
        read_exact_or_truncated(&mut in_file, &mut auth_tag, in_path)?;

        let mut plaintext = vec![0u8; chunk_len];
        let tag = pull.pull(tag_byte, &ciphertext, &auth_tag, &mut plaintext)?;
        out_file.write_all(&plaintext).map_err(|e| CliError::Io {
            path: tmp_path.to_path_buf(),
            message: e.to_string(),
        })?;

        if tag == Tag::Final {
            break;
        }
    }

    let mut probe = [0u8; 1];
    let trailing = in_file.read(&mut probe).map_err(|e| CliError::Io {
        path: in_path.clone(),
        message: e.to_string(),
    })?;
    if trailing != 0 {
        return Err(CliError::SecretstreamTrailingData);
    }
    Ok(())
}

/// Runs `encrypt`/`decrypt` over `dstu_core::crypto_secretstream` (T-40/T-70, `docs/DECISIONS.md` D-68 -
/// migrated from `dstu_core::crypto_secretbox`/D-51, which stays a separate library primitive, not
/// removed). Unlike the old `crypto_secretbox`-backed command, `--in` is read and `--out` is
/// written in [`SECRETSTREAM_CHUNK_BYTES`]-sized chunks (D-42) - peak memory stays bounded
/// regardless of `--in`'s size, on both `encrypt` and `decrypt`, matching `kupyna-digest`/
/// `strumok-crypt`'s existing streaming discipline. `--out` is written to a temp file next to it
/// first and only `std::fs::rename`d onto the real path once the whole stream verifies (`encrypt`
/// can only fail on OS-CSPRNG/IO errors, but `decrypt` can fail mid-stream on a tampered/truncated
/// `--in` - this keeps "no partial output on failure" true under genuine streaming I/O the same
/// way the old whole-buffer command got it for free).
///
/// **Breaking wire-format change from the old `crypto_secretbox`-backed command** (D-68) - a file
/// `encrypt` produced before this migration cannot be read by this `decrypt`, and vice versa.
/// Acceptable pre-1.0 (`README.md`'s pre-release banner), called out explicitly rather than left
/// implicit.
///
/// # Errors
///
/// Returns [`CliError::WrongLength`] if `--key` isn't exactly 32 bytes,
/// [`CliError::SecretstreamTruncated`] if `--in` (on `decrypt`) ends before a `Final` chunk is
/// read, [`CliError::SecretstreamVerifyFailed`] if a chunk fails authentication,
/// [`CliError::SecretstreamUnsupportedVersion`] if `--in` does not start with this build's format
/// version, [`CliError::SecretstreamUnknownTag`]/[`CliError::SecretstreamChunkTooLarge`]/
/// [`CliError::SecretstreamBadChunkLength`] for a malformed chunk record, [`CliError::SecretstreamTrailingData`] if bytes remain after `Final`, or
/// [`CliError::Io`] for file read/write failures - `--out` is left untouched on every error path.
pub fn run_secretstream_command(decrypt: bool, args: &SecretstreamArgs) -> Result<(), CliError> {
    let command = if decrypt { "decrypt" } else { "encrypt" };
    let (_, key_bytes) = keyfile::read_key(&args.key_path, command, &[KeyKind::Symmetric])?;
    let mut key_arr = zeroize::Zeroizing::new([0u8; SECRETSTREAM_KEY_LEN]);
    key_arr.copy_from_slice(&key_bytes);
    let key = dstu_core::crypto_secretstream::Key::from_bytes(*key_arr);

    check_outputs(&[("--out", &args.out_path)], &[("--key", &args.key_path)])?;
    let (out, mut out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;
    let tmp_path = out.tmp_path().to_path_buf();
    if decrypt {
        run_secretstream_decrypt(&key, &args.in_path, &mut out_file, &tmp_path)?;
    } else {
        run_secretstream_encrypt(&key, &args.in_path, &mut out_file, &tmp_path)?;
    }
    out.commit(out_file)
}

/// The two hash/key sizes shared by Kupyna (output width) and Strumok (key width) - `"256"`/
/// `"512"` either way, matching each algorithm's own variant naming (`Kupyna256`/`Kupyna512`,
/// `Strumok256`/`Strumok512`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashBits {
    B256,
    B512,
}

impl HashBits {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "256" => Some(Self::B256),
            "512" => Some(Self::B512),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DigestArgs {
    pub variant: HashBits,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `kupyna-digest`'s flags (`--variant`/`--in`/`--out` required, `--iterations` optional).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`], [`CliError::UnknownVariant`], [`CliError::InvalidIterations`],
/// or [`CliError::UnknownFlag`] - same cases as [`parse_block_args`], minus the key/raw-schedule
/// flags Kupyna (unkeyed) has no use for.
pub fn parse_digest_args(args: &[String]) -> Result<DigestArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &["--variant", "--in", "--out", "--iterations"],
        &["--force"],
    )?;
    Ok(DigestArgs {
        variant: scanner.variant(HashBits::parse)?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Read-buffer size for `kupyna-digest`'s real (`iterations <= 1`) path - deliberately small so
/// peak memory stays bounded by this constant regardless of `--in`'s size, putting `hazmat::
/// kupyna`'s `Hasher` (T-83) to its actual intended use rather than just proving it exists. 8 KiB
/// is a conservative "small, safe default" I/O buffer size - large enough that per-`read()`-call
/// syscall overhead stays negligible, small enough to still be a genuine streaming bound rather
/// than "the whole file, just given a constant name."
const DIGEST_STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// Chunk size for `kupyna-digest`'s benchmark path (`iterations > 1`, D-34). The file is still
/// read once, up front - re-reading it per iteration would reintroduce disk-cache-dependent I/O
/// noise into the very MB/s figure this path exists to measure - but each iteration re-hashes that
/// resident buffer through the same streaming `Hasher` used above, fed in much larger chunks tuned
/// for throughput rather than memory footprint (`update()` call overhead negligible against 1 MiB
/// of hashing work, unlike the 8 KiB streaming case above where memory is the actual constraint).
/// Produces byte-identical output to the one-shot `digest()` this replaced (chunk-invariance
/// proven directly at the `hazmat::kupyna` level, T-83), so this does not change any number
/// already recorded in `docs/PERFORMANCE.md`.
const DIGEST_BENCH_CHUNK_BYTES: usize = 1024 * 1024;

/// Runs `kupyna-digest`: hashes `--in` (arbitrary length - Kupyna has no block-size restriction on
/// its public API, unlike Kalyna), writes the digest to `--out`, and prints timing to stderr when
/// `iterations > 1`. `iterations <= 1` streams `--in` from disk in [`DIGEST_STREAM_CHUNK_BYTES`]-
/// sized chunks (real usage; the message is not re-read, so this is a single genuine pass);
/// `iterations > 1` is the D-34 benchmark path (see [`DIGEST_BENCH_CHUNK_BYTES`]'s doc comment for
/// why it reads once and re-hashes in memory instead).
///
/// # Errors
///
/// Returns [`CliError::Io`] if `--in` can't be read or `--out` can't be written.
#[allow(clippy::cast_precision_loss)] // human-readable MB/s diagnostic, not exact at any realistic byte count
pub fn run_digest_command(args: &DigestArgs) -> Result<(), CliError> {
    use std::io::Read;

    let (out, out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;

    let iterations = args.iterations.max(1);

    macro_rules! stream_from_disk {
        ($hasher:ty) => {{
            let mut file = std::fs::File::open(&args.in_path).map_err(|e| CliError::Io {
                path: args.in_path.clone(),
                message: e.to_string(),
            })?;
            let mut hasher = <$hasher>::new();
            let mut chunk = [0u8; DIGEST_STREAM_CHUNK_BYTES];
            let mut total_bytes: u64 = 0;
            loop {
                let n = file.read(&mut chunk).map_err(|e| CliError::Io {
                    path: args.in_path.clone(),
                    message: e.to_string(),
                })?;
                if n == 0 {
                    break;
                }
                hasher.update(&chunk[..n]);
                total_bytes += n as u64;
            }
            (hasher.finalize().to_vec(), total_bytes)
        }};
    }

    macro_rules! bench_in_memory {
        ($hasher:ty, $message:expr) => {{
            let mut out = None;
            for _ in 0..iterations {
                let mut hasher = <$hasher>::new();
                for chunk in $message.chunks(DIGEST_BENCH_CHUNK_BYTES) {
                    hasher.update(chunk);
                }
                out = Some(hasher.finalize().to_vec());
            }
            out.expect("iterations is clamped to at least 1 above")
        }};
    }

    let start;
    let digest: Vec<u8>;
    let total_bytes: u64;

    if iterations <= 1 {
        start = Instant::now();
        (digest, total_bytes) = match args.variant {
            HashBits::B256 => stream_from_disk!(Kupyna256Hasher),
            HashBits::B512 => stream_from_disk!(Kupyna512Hasher),
        };
    } else {
        let message = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
            path: args.in_path.clone(),
            message: e.to_string(),
        })?;
        total_bytes = message.len() as u64;
        start = Instant::now();
        digest = match args.variant {
            HashBits::B256 => bench_in_memory!(Kupyna256Hasher, message),
            HashBits::B512 => bench_in_memory!(Kupyna512Hasher, message),
        };
    }
    let elapsed = start.elapsed();

    out.write_all_and_commit(out_file, &digest)?;

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        let mb_per_s = if per_op_ns == 0 {
            0.0
        } else {
            (total_bytes as f64) / (per_op_ns as f64 / 1e9) / 1e6
        };
        eprintln!(
            "iterations={} total_ns={} per_op_ns={per_op_ns} mb_per_s={mb_per_s:.2}",
            args.iterations,
            elapsed.as_nanos(),
        );
    }

    Ok(())
}

/// `hash`'s two modes (T-259, `docs/DECISIONS.md` D-215).
#[derive(Debug, PartialEq, Eq)]
pub enum HashArgs {
    /// `--in <path>`: print `<hex>  <path>` to stdout.
    File(PathBuf),
    /// `--check <file>`: verify every `<hex>  <path>` line of a file.
    Check(PathBuf),
}

/// Parses `hash`'s flags: exactly one of `--in`/`--check`. No `--variant` (fixed to Kupyna-256,
/// see [`run_hash_command`]) and no `--out`: the digest goes to stdout.
///
/// # Errors
///
/// Returns [`CliError::MissingOneOf`], [`CliError::ExclusiveFlags`] or another usage error.
pub fn parse_hash_args(args: &[String]) -> Result<HashArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--in", "--check"], &[])?;
    match (scanner.path_opt("--in"), scanner.path_opt("--check")) {
        (Some(path), None) => Ok(HashArgs::File(path)),
        (None, Some(list)) => Ok(HashArgs::Check(list)),
        (Some(_), Some(_)) => Err(CliError::ExclusiveFlags("in", "check")),
        (None, None) => Err(CliError::MissingOneOf("in", "check")),
    }
}

/// Upper bound on a `hash --check` file: it is untrusted input and is read whole.
const HASH_CHECK_LIST_MAX_BYTES: usize = 16 * 1024 * 1024;

/// One `<hex>  <path>` line of a `hash --check` file.
#[derive(Debug, PartialEq, Eq)]
struct CheckEntry {
    digest: [u8; 32],
    path: String,
}

#[derive(Debug, PartialEq, Eq)]
enum CheckListError {
    Empty,
    /// Starts with a UTF-16 byte-order mark: Windows PowerShell 5.1's `>` (D-215).
    Utf16,
    /// 1-based line number.
    Malformed(usize),
}

/// A path that round-trips through one checksum line and cannot move the terminal: UTF-8, no
/// control character (a newline would split the line, an escape sequence would be echoed).
fn is_printable_path(path: &str) -> bool {
    !path.is_empty() && !path.chars().any(char::is_control)
}

/// Parses a whole check file: one `<64 hex digits>  <path>` per line, upper- or lower-case hex, an
/// optional `\r` before each `\n`, the last `\n` optional, one leading UTF-8 byte-order mark
/// ignored. Anything else rejects the whole file.
fn parse_check_list(text: &[u8]) -> Result<Vec<CheckEntry>, CheckListError> {
    if text.starts_with(&[0xff, 0xfe]) || text.starts_with(&[0xfe, 0xff]) {
        return Err(CheckListError::Utf16);
    }
    let text = text.strip_prefix(b"\xef\xbb\xbf").unwrap_or(text);
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    if text.is_empty() {
        return Err(CheckListError::Empty);
    }
    text.split(|&b| b == b'\n')
        .enumerate()
        .map(|(index, line)| {
            parse_check_line(line.strip_suffix(b"\r").unwrap_or(line))
                .ok_or(CheckListError::Malformed(index + 1))
        })
        .collect()
}

fn parse_check_line(line: &[u8]) -> Option<CheckEntry> {
    let (hex, rest) = line.split_at_checked(64)?;
    let path = std::str::from_utf8(rest.strip_prefix(b"  ")?).ok()?;
    if !is_printable_path(path) {
        return None;
    }
    let mut lower = [0u8; 64];
    for (out, c) in lower.iter_mut().zip(hex) {
        *out = c.to_ascii_lowercase();
    }
    let mut digest = [0u8; 32];
    (keyfile::decode_hex(&lower, &mut digest) == 1).then(|| CheckEntry {
        digest,
        path: path.to_string(),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn stdout_error(e: &std::io::Error) -> CliError {
    CliError::Io {
        path: PathBuf::from("<stdout>"),
        message: e.to_string(),
    }
}

/// Runs `hash`. `--in`: prints `<hex>  <path>` (the path as given) to stdout, like `sha256sum`.
/// `--check`: reads such lines, hashes each listed file (relative paths against the working
/// directory) and prints `<path>: OK` or `<path>: FAILED`. Fixed to Kupyna-256 - no `--variant`
/// knob (D-47; Kupyna-256 is this project's default message hash, D-46). Files are streamed in
/// bounded chunks via [`hash_file_streamed`] (D-42), so there is no size limit.
///
/// # Errors
///
/// Returns [`CliError::Io`] if `--in`, the check file or stdout fails,
/// [`CliError::HashPathUnprintable`] for a path that cannot be a checksum line,
/// [`CliError::HashCheckTooLarge`]/[`CliError::HashCheckEmpty`]/[`CliError::HashCheckMalformed`]
/// for a bad check file (nothing is hashed then), and [`CliError::HashCheckFailed`] if any listed
/// file does not match or cannot be read.
pub fn run_hash_command(args: &HashArgs) -> Result<(), CliError> {
    use std::io::Write as _;

    match args {
        HashArgs::File(path) => {
            let shown = path
                .to_str()
                .filter(|p| is_printable_path(p))
                .ok_or_else(|| CliError::HashPathUnprintable(path.clone()))?;
            let digest = hash_file_streamed(path)?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}  {shown}", hex_lower(&digest))
                .and_then(|()| out.flush())
                .map_err(|e| stdout_error(&e))
        }
        HashArgs::Check(list) => run_hash_check(list),
    }
}

fn read_check_list(list: &PathBuf) -> Result<Vec<u8>, CliError> {
    use std::io::Read;

    let io_error = |e: std::io::Error| CliError::Io {
        path: list.clone(),
        message: e.to_string(),
    };
    let mut text = Vec::new();
    std::fs::File::open(list)
        .map_err(io_error)?
        .take(HASH_CHECK_LIST_MAX_BYTES as u64 + 1)
        .read_to_end(&mut text)
        .map_err(io_error)?;
    if text.len() > HASH_CHECK_LIST_MAX_BYTES {
        return Err(CliError::HashCheckTooLarge {
            path: list.clone(),
            limit: HASH_CHECK_LIST_MAX_BYTES,
        });
    }
    Ok(text)
}

fn run_hash_check(list: &PathBuf) -> Result<(), CliError> {
    use std::io::Write as _;

    let entries = parse_check_list(&read_check_list(list)?).map_err(|e| match e {
        CheckListError::Empty => CliError::HashCheckEmpty(list.clone()),
        CheckListError::Utf16 => CliError::HashCheckUtf16(list.clone()),
        CheckListError::Malformed(line) => CliError::HashCheckMalformed {
            path: list.clone(),
            line,
        },
    })?;
    let mut out = std::io::stdout().lock();
    let mut failed = 0;
    for entry in &entries {
        let status = match hash_file_streamed(&PathBuf::from(&entry.path)) {
            // A file digest is public: no constant-time comparison needed.
            Ok(digest) if digest == entry.digest => "OK".to_string(),
            Ok(_) => "FAILED".to_string(),
            Err(CliError::Io { message, .. }) => format!("FAILED (cannot read: {message})"),
            Err(e) => format!("FAILED (cannot read: {e})"),
        };
        if status != "OK" {
            failed += 1;
        }
        writeln!(out, "{}: {status}", entry.path).map_err(|e| stdout_error(&e))?;
    }
    out.flush().map_err(|e| stdout_error(&e))?;
    if failed > 0 {
        return Err(CliError::HashCheckFailed {
            failed,
            total: entries.len(),
        });
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeygenArgs {
    pub out_path: PathBuf,
}

/// Parses `keygen`'s flags (`--out`, required - no other flag exists; there is nothing to
/// configure about a random 32-byte key).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`] or [`CliError::UnknownFlag`].
pub fn parse_keygen_args(args: &[String]) -> Result<KeygenArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--out"], &[])?;
    Ok(KeygenArgs {
        out_path: scanner.path("--out")?,
    })
}

/// Runs `keygen`: draws a fresh 32-byte key from the OS CSPRNG
/// ([`dstu_core::crypto_secretstream::Key::generate`]) and writes it raw to `--out` - the same
/// 32-byte format `encrypt`/`decrypt --key` already expects, closing the gap
/// `docs/user-journey-gaps.md` named (persona 1's first action had no CLI path before this: both
/// crate READMEs only said "generate one via any 32-byte-CSPRNG source," no command to do it).
///
/// # Errors
///
/// Returns [`CliError::Random`] if the OS CSPRNG fails, or [`CliError::Io`] if `--out` can't be
/// written (e.g. it names a directory).
pub fn run_keygen_command(args: &KeygenArgs) -> Result<(), CliError> {
    let key = dstu_core::crypto_secretstream::Key::generate()
        .map_err(|e| CliError::Random(e.to_string()))?;
    write_new_key_file(
        &args.out_path,
        &keyfile::encode(KeyKind::Symmetric, key.as_bytes()),
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyImportArgs {
    pub kind: KeyKind,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
}

/// Parses `key-import`'s flags (`--kind`/`--in`/`--out`, all required).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`], [`CliError::UnknownKeyKind`] or [`CliError::UnknownFlag`].
pub fn parse_key_import_args(args: &[String]) -> Result<KeyImportArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--kind", "--in", "--out"], &[])?;
    Ok(KeyImportArgs {
        kind: scanner.key_kind()?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
    })
}

/// The raw 0.4-and-older file layout of `kind`: its length, plus D-186's leading curve byte for a
/// verifying key.
fn raw_key_layout(kind: KeyKind) -> (LengthOf, usize, Option<u8>) {
    match kind {
        KeyKind::Symmetric => (LengthOf::Key, 32, None),
        KeyKind::Sign163Secret | KeyKind::Sign257Secret => {
            (LengthOf::SigningKey, kind.key_len(), None)
        }
        KeyKind::Sign163Public => (
            LengthOf::VerifyingKey,
            43,
            Some(dstu_core::crypto_sign::CurveId::M163.to_byte()),
        ),
        KeyKind::Sign257Public => (
            LengthOf::VerifyingKey,
            67,
            Some(dstu_core::crypto_sign::CurveId::M257.to_byte()),
        ),
        KeyKind::Box256Secret => (LengthOf::BoxSecretKey, 32, None),
        KeyKind::Box256Public => (LengthOf::BoxPublicKey, 32, None),
        KeyKind::Box512Secret => (LengthOf::Box512SecretKey, 64, None),
        KeyKind::Box512Public => (LengthOf::Box512PublicKey, 64, None),
    }
}

fn key_array<const N: usize>(key: &[u8]) -> zeroize::Zeroizing<[u8; N]> {
    let mut out = zeroize::Zeroizing::new([0u8; N]);
    out.copy_from_slice(key);
    out
}

/// Validates `key` as `kind` the same way the commands that use it will, and returns the check
/// value of the matching public key for a sign/box secret key.
fn validate_imported_key(kind: KeyKind, key: &[u8]) -> Result<Option<String>, CliError> {
    Ok(match kind {
        KeyKind::Symmetric | KeyKind::Sign163Public | KeyKind::Sign257Public => None,
        KeyKind::Sign163Secret => {
            let sk = dstu_core::crypto_sign::SigningKey::from_bytes(&key_array::<21>(key))
                .ok_or(CliError::SignKeyInvalid)?;
            let pk = sk.verifying_key().to_uncompressed_bytes();
            Some(keyfile::check_hex(KeyKind::Sign163Public, &pk))
        }
        KeyKind::Sign257Secret => {
            let sk = dstu_core::crypto_sign257::SigningKey::from_bytes(&key_array::<33>(key))
                .ok_or(CliError::SignKeyInvalid)?;
            let pk = sk.verifying_key().to_uncompressed_bytes();
            Some(keyfile::check_hex(KeyKind::Sign257Public, &pk))
        }
        KeyKind::Box256Secret => {
            let sk = dstu_core::crypto_box::SecretKey::from_bytes(&key_array::<32>(key))
                .ok_or(CliError::BoxKeyInvalid)?;
            Some(keyfile::check_hex(
                KeyKind::Box256Public,
                &sk.public_key().to_bytes(),
            ))
        }
        KeyKind::Box256Public => {
            dstu_core::crypto_box::PublicKey::from_bytes(&key_array::<32>(key))
                .ok_or(CliError::BoxKeyInvalid)?;
            None
        }
        KeyKind::Box512Secret => {
            let sk = dstu_core::crypto_box512::SecretKey::from_bytes(&key_array::<64>(key))
                .ok_or(CliError::BoxKeyInvalid)?;
            Some(keyfile::check_hex(
                KeyKind::Box512Public,
                &sk.public_key().to_bytes(),
            ))
        }
        KeyKind::Box512Public => {
            dstu_core::crypto_box512::PublicKey::from_bytes(&key_array::<64>(key))
                .ok_or(CliError::BoxKeyInvalid)?;
            None
        }
    })
}

/// Runs `key-import` (`docs/TASKS.md` T-256, K2 (a)): converts one raw key file written by
/// uacrypt 0.4 or older into a typed key file (D-212). `--kind` is the only place a key kind is
/// ever typed by hand, so the raw bytes are validated exactly as the commands using them will
/// validate them, and the report line on stderr gives the new file's check value - and, for a
/// secret key, its public key's check value, to compare with a public key already shared.
///
/// # Errors
///
/// [`CliError::Io`]/[`CliError::WrongLength`] for the raw file, [`CliError::KeyImportCurveByte`]
/// for a verifying key of the other curve, [`CliError::SignKeyInvalid`]/
/// [`CliError::BoxKeyInvalid`] for invalid key bytes, and
/// [`CliError::KeyFileExists`] if `--out` exists.
pub fn run_key_import_command(args: &KeyImportArgs) -> Result<(), CliError> {
    let kind = args.kind;
    let (what, len, curve_byte) = raw_key_layout(kind);
    let raw = zeroize::Zeroizing::new(read_exact_file(&args.in_path, what, len)?);
    let key = match curve_byte {
        Some(expected) if raw[0] != expected => {
            return Err(CliError::KeyImportCurveByte {
                path: args.in_path.clone(),
                kind,
                byte: raw[0],
            })
        }
        Some(_) => &raw[1..],
        None => &raw[..],
    };
    let public_check = validate_imported_key(kind, key)?;
    let line = keyfile::encode(kind, key);
    write_new_key_file(&args.out_path, &line)?;
    let public_note = public_check
        .map(|check| format!("; its public key has check {check}"))
        .unwrap_or_default();
    eprintln!(
        "wrote {} to {} (check {}){public_note}",
        kind.label(),
        args.out_path.display(),
        keyfile::check_hex(kind, key)
    );
    Ok(())
}

/// Read-buffer size for streaming a message through Kupyna-256 on `sign`/`verify`'s behalf
/// (`docs/TASKS.md` T-124) - same constant value and same reasoning as `kupyna-digest`'s own
/// [`DIGEST_STREAM_CHUNK_BYTES`] (D-42): `dstu_core::crypto_sign::SigningKey::sign_digest`/
/// `VerifyingKey::verify_digest` (T-113) exist specifically so a caller can hash a large message
/// incrementally instead of loading it whole, so `sign`/`verify` use them rather than
/// `SigningKey::sign`/`VerifyingKey::verify`'s own whole-message convenience wrappers.
const SIGN_STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// Hashes `path` with Kupyna-256 in [`SIGN_STREAM_CHUNK_BYTES`]-sized chunks, for `sign`/`verify`.
fn hash_file_streamed(path: &PathBuf) -> Result<[u8; 32], CliError> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| CliError::Io {
        path: path.clone(),
        message: e.to_string(),
    })?;
    let mut hasher = Kupyna256Hasher::new();
    let mut chunk = [0u8; SIGN_STREAM_CHUNK_BYTES];
    loop {
        let n = file.read(&mut chunk).map_err(|e| CliError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }
    Ok(hasher.finalize())
}

/// A signing key of either curve; the key file's kind decides which (T-257, D-213). Like
/// [`AnyVerifyingKey`], a `uacrypt`-only dispatch enum: the library types stay separate (D-186).
enum AnySigningKey {
    M163(dstu_core::crypto_sign::SigningKey),
    M257(dstu_core::crypto_sign257::SigningKey),
}

impl AnySigningKey {
    /// `r || s`: 42 bytes for m=163, 66 for m=257.
    fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        match self {
            AnySigningKey::M163(k) => k.sign_digest(digest).to_bytes().to_vec(),
            AnySigningKey::M257(k) => k.sign_digest(digest).to_bytes().to_vec(),
        }
    }

    /// The matching verifying key as a typed key line of the same curve.
    fn verifying_key_line(&self) -> zeroize::Zeroizing<Vec<u8>> {
        match self {
            AnySigningKey::M163(k) => keyfile::encode(
                KeyKind::Sign163Public,
                &k.verifying_key().to_uncompressed_bytes(),
            ),
            AnySigningKey::M257(k) => keyfile::encode(
                KeyKind::Sign257Public,
                &k.verifying_key().to_uncompressed_bytes(),
            ),
        }
    }
}

/// Reads a signing key of either curve and validates it with that curve's
/// `SigningKey::from_bytes`.
fn read_signing_key(
    path: &std::path::Path,
    command: &'static str,
) -> Result<AnySigningKey, CliError> {
    let (kind, bytes) = keyfile::read_key(
        path,
        command,
        &[KeyKind::Sign163Secret, KeyKind::Sign257Secret],
    )?;
    let key = if kind == KeyKind::Sign163Secret {
        dstu_core::crypto_sign::SigningKey::from_bytes(&key_array::<21>(&bytes))
            .map(AnySigningKey::M163)
    } else {
        dstu_core::crypto_sign257::SigningKey::from_bytes(&key_array::<33>(&bytes))
            .map(AnySigningKey::M257)
    };
    key.ok_or(CliError::SignKeyInvalid)
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignKeygenArgs {
    pub out_path: PathBuf,
}

/// Parses `sign-keygen`'s flags (`--out`, required - no other flag exists; there is nothing to
/// configure about a randomly generated signing key, `docs/DECISIONS.md` D-72).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`] or [`CliError::UnknownFlag`].
pub fn parse_sign_keygen_args(args: &[String]) -> Result<SignKeygenArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--out"], &[])?;
    Ok(SignKeygenArgs {
        out_path: scanner.path("--out")?,
    })
}

/// Runs `sign-keygen`: draws a fresh signing key via rejection sampling against the curve order
/// ([`dstu_core::crypto_sign::SigningKey::generate`], `docs/TASKS.md` T-122/D-72) and writes its raw
/// 21-byte encoding to `--out`. A separate command from `keygen` rather than a `--type` flag on
/// it - a flag choosing between two incompatible key shapes (32-byte symmetric vs. 21-byte
/// signing scalar) is exactly the kind of knob D-47's "delete the knob" criterion avoids;
/// `sign-keygen` can't be pointed at the wrong algorithm by a typo'd flag value.
///
/// # Errors
///
/// Returns [`CliError::Random`] if the OS CSPRNG fails, or [`CliError::Io`] if `--out` can't be
/// written (e.g. it names a directory).
pub fn run_sign_keygen_command(args: &SignKeygenArgs) -> Result<(), CliError> {
    let key = dstu_core::crypto_sign::SigningKey::generate()
        .map_err(|e| CliError::Random(e.to_string()))?;
    write_new_key_file(
        &args.out_path,
        &keyfile::encode(KeyKind::Sign163Secret, &key.to_bytes()),
    )
}

/// `m=257` sibling of [`run_sign_keygen_command`] - writes the raw 33-byte private scalar.
/// A separate command, not a `--curve` flag, same `box-keygen512` precedent
/// `BOX_KEYGEN512_HELP` already documents (`docs/TASKS.md` T-199).
///
/// # Errors
///
/// Returns [`CliError::Random`] if the OS CSPRNG fails, or [`CliError::Io`] if `--out` can't be
/// written.
pub fn run_sign_keygen257_command(args: &SignKeygenArgs) -> Result<(), CliError> {
    let key = dstu_core::crypto_sign257::SigningKey::generate()
        .map_err(|e| CliError::Random(e.to_string()))?;
    write_new_key_file(
        &args.out_path,
        &keyfile::encode(KeyKind::Sign257Secret, &key.to_bytes()),
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignPubkeyArgs {
    pub key_path: PathBuf,
    pub out_path: PathBuf,
}

/// Parses `sign-pubkey`'s flags (`--key`/`--out`, both required).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`] or [`CliError::UnknownFlag`].
pub fn parse_sign_pubkey_args(args: &[String]) -> Result<SignPubkeyArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--key", "--out"], &[])?;
    Ok(SignPubkeyArgs {
        key_path: scanner.path("--key")?,
        out_path: scanner.path("--out")?,
    })
}

/// Runs `sign-pubkey`: reads a signing key of either curve from `--key`, derives `Q = -d*G`
/// (`SigningKey::verifying_key`), and writes it to `--out` as a verifying-key line of the same
/// curve (D-212), the format `verify --key` expects.
///
/// # Errors
///
/// Returns [`CliError::Io`] or a key-file error for file problems, or
/// [`CliError::SignKeyInvalid`] if `--key` isn't a valid signing key.
pub fn run_sign_pubkey_command(args: &SignPubkeyArgs) -> Result<(), CliError> {
    let signing_key = read_signing_key(&args.key_path, "sign-pubkey")?;
    let line = signing_key.verifying_key_line();
    write_new_key_file(&args.out_path, &line)
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignArgs {
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `sign`'s flags (`--key`/`--in`/`--out` required, `--iterations` optional - benchmarking
/// only, same shape as [`parse_digest_args`]: no `--raw-schedule`, since signing has no key-
/// schedule step to cache/redo, the same reason `kupyna-digest`/`kalyna-kw` don't have one either).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`], [`CliError::InvalidIterations`], or [`CliError::UnknownFlag`].
pub fn parse_sign_args(args: &[String]) -> Result<SignArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &["--key", "--in", "--out", "--iterations"],
        &["--force"],
    )?;
    Ok(SignArgs {
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `sign`: hashes `--in` with Kupyna-256 in bounded-memory chunks
/// ([`hash_file_streamed`], D-42), signs the digest with `--key` of either curve
/// (`SigningKey::sign_digest`, deterministic nonce - D-46), and writes the `r || s` signature to
/// `--out` (42 bytes for m=163, 66 for m=257; the key's kind picks the curve, T-257). `iterations > 1` is the D-34 benchmark path: the
/// message is hashed once (matching `openssl speed`'s own methodology of signing one fixed digest
/// repeatedly, not re-hashing per call, `docs/DECISIONS.md` D-106's extension note), then only the
/// `sign_digest` call itself is timed in a loop, key parsed once outside it (D-80's cached-schedule
/// lesson).
///
/// # Errors
///
/// Returns [`CliError::Io`]/[`CliError::WrongLength`] for file problems, or
/// [`CliError::SignKeyInvalid`] if `--key` isn't a valid signing key.
#[allow(clippy::cast_precision_loss)] // human-readable ops/s diagnostic, not exact at any realistic count
pub fn run_sign_command(args: &SignArgs) -> Result<(), CliError> {
    let signing_key = read_signing_key(&args.key_path, "sign")?;
    check_outputs(&[("--out", &args.out_path)], &[("--key", &args.key_path)])?;
    let (out, out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;
    let digest = hash_file_streamed(&args.in_path)?;
    let iterations = args.iterations.max(1);

    let start = Instant::now();
    let mut sig = signing_key.sign_digest(&digest);
    for _ in 1..iterations {
        sig = signing_key.sign_digest(&digest);
    }
    let elapsed = start.elapsed();

    out.write_all_and_commit(out_file, &sig)?;

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        let ops_per_s = if per_op_ns == 0 {
            0.0
        } else {
            1e9 / (per_op_ns as f64)
        };
        eprintln!(
            "iterations={} total_ns={} per_op_ns={per_op_ns} ops_per_s={ops_per_s:.2}",
            args.iterations,
            elapsed.as_nanos(),
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifyArgs {
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub sig_path: PathBuf,
    pub iterations: u32,
}

/// Parses `verify`'s flags (`--key`/`--in`/`--sig` required, `--iterations` optional -
/// benchmarking only, same no-`--raw-schedule` shape as [`parse_sign_args`]).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`], [`CliError::InvalidIterations`], or [`CliError::UnknownFlag`].
pub fn parse_verify_args(args: &[String]) -> Result<VerifyArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--key", "--in", "--sig", "--iterations"], &[])?;
    Ok(VerifyArgs {
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        sig_path: scanner.path("--sig")?,
        iterations: scanner.iterations()?,
    })
}

/// Which curve a `verify --key` file's own leading tag byte selected, holding the matching
/// verifying key - `uacrypt`'s own dispatch enum, not part of `dstu-core`'s public API (the
/// library's `crypto_sign`/`crypto_sign257` types stay distinct and untagged, D-186's own
/// reasoning for why that split lives here, not in the library).
enum AnyVerifyingKey {
    M163(dstu_core::crypto_sign::VerifyingKey),
    M257(dstu_core::crypto_sign257::VerifyingKey),
}

impl AnyVerifyingKey {
    fn curve_label(&self) -> &'static str {
        match self {
            AnyVerifyingKey::M163(_) => "m=163",
            AnyVerifyingKey::M257(_) => "m=257",
        }
    }

    fn verify_digest(&self, digest: &[u8; 32], sig_bytes: &[u8]) -> Result<bool, CliError> {
        match self {
            AnyVerifyingKey::M163(k) => {
                if sig_bytes.len() != 42 {
                    return Err(CliError::WrongLength {
                        what: LengthOf::Signature,
                        expected: 42,
                        actual: sig_bytes.len(),
                    });
                }
                let mut arr = [0u8; 42];
                arr.copy_from_slice(sig_bytes);
                let sig = dstu_core::crypto_sign::Signature::from_bytes(&arr);
                Ok(k.verify_digest(digest, &sig))
            }
            AnyVerifyingKey::M257(k) => {
                if sig_bytes.len() != 66 {
                    return Err(CliError::WrongLength {
                        what: LengthOf::Signature,
                        expected: 66,
                        actual: sig_bytes.len(),
                    });
                }
                let mut arr = [0u8; 66];
                arr.copy_from_slice(sig_bytes);
                let sig = dstu_core::crypto_sign257::Signature::from_bytes(&arr);
                Ok(k.verify_digest(digest, &sig))
            }
        }
    }
}

/// Reads `verify --key`: a verifying key of either curve (D-212 - the key line's prefix names
/// the curve, replacing D-186's leading tag byte).
fn read_verifying_key(path: &std::path::Path) -> Result<AnyVerifyingKey, CliError> {
    let (kind, bytes) = keyfile::read_key(
        path,
        "verify",
        &[KeyKind::Sign163Public, KeyKind::Sign257Public],
    )?;
    if kind == KeyKind::Sign163Public {
        let mut q = [0u8; 42];
        q.copy_from_slice(&bytes);
        Ok(AnyVerifyingKey::M163(
            dstu_core::crypto_sign::VerifyingKey::from_uncompressed_bytes(&q),
        ))
    } else {
        let mut q = [0u8; 66];
        q.copy_from_slice(&bytes);
        Ok(AnyVerifyingKey::M257(
            dstu_core::crypto_sign257::VerifyingKey::from_uncompressed_bytes(&q),
        ))
    }
}

/// Runs `verify`: hashes `--in` with Kupyna-256 in bounded-memory chunks
/// ([`hash_file_streamed`], D-42), reads `--key` as a verifying key of either curve (the key
/// line names it, D-212), then checks `--sig` against it. On a valid signature prints `Signature OK (DSTU 4145, m=...)` to
/// stderr and returns `Ok(())` (T-255); stdout stays empty. `iterations > 1` is the D-34
/// benchmark path, same shape as [`run_sign_command`]: hash/key/signature parsed once, only
/// `verify_digest` itself timed in a loop.
///
/// # Errors
///
/// Returns [`CliError::Io`] or a key-file error for `--key`, [`CliError::WrongLength`] if `--sig`
/// has the wrong length for the key's curve, or [`CliError::SignVerifyFailed`] if the signature
/// does not verify.
#[allow(clippy::cast_precision_loss)] // human-readable ops/s diagnostic, not exact at any realistic count
pub fn run_verify_command(args: &VerifyArgs) -> Result<(), CliError> {
    let verifying_key = read_verifying_key(&args.key_path)?;
    let sig_bytes = std::fs::read(&args.sig_path).map_err(|e| CliError::Io {
        path: args.sig_path.clone(),
        message: e.to_string(),
    })?;

    let digest = hash_file_streamed(&args.in_path)?;
    let iterations = args.iterations.max(1);

    let start = Instant::now();
    let mut ok = verifying_key.verify_digest(&digest, &sig_bytes)?;
    for _ in 1..iterations {
        ok = verifying_key.verify_digest(&digest, &sig_bytes)?;
    }
    let elapsed = start.elapsed();

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        let ops_per_s = if per_op_ns == 0 {
            0.0
        } else {
            1e9 / (per_op_ns as f64)
        };
        eprintln!(
            "iterations={} total_ns={} per_op_ns={per_op_ns} ops_per_s={ops_per_s:.2}",
            args.iterations,
            elapsed.as_nanos(),
        );
    }

    if ok {
        eprintln!("Signature OK (DSTU 4145, {})", verifying_key.curve_label());
        Ok(())
    } else {
        Err(CliError::SignVerifyFailed)
    }
}

/// A `crypto_box` secret key of either curve; the key file's kind decides which (T-257, D-213).
enum AnyBoxSecret {
    L256(dstu_core::crypto_box::SecretKey),
    L512(dstu_core::crypto_box512::SecretKey),
}

/// A `crypto_box` public key of either curve; the key file's kind decides which (T-257, D-213).
enum AnyBoxPublic {
    L256(dstu_core::crypto_box::PublicKey),
    L512(dstu_core::crypto_box512::PublicKey),
}

impl AnyBoxSecret {
    fn curve_label(&self) -> &'static str {
        match self {
            AnyBoxSecret::L256(_) => "l(p)=256",
            AnyBoxSecret::L512(_) => "l(p)=512",
        }
    }

    fn public_key_line(&self) -> zeroize::Zeroizing<Vec<u8>> {
        match self {
            AnyBoxSecret::L256(k) => {
                keyfile::encode(KeyKind::Box256Public, &k.public_key().to_bytes())
            }
            AnyBoxSecret::L512(k) => {
                keyfile::encode(KeyKind::Box512Public, &k.public_key().to_bytes())
            }
        }
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, CliError> {
        let curve = self.curve_label();
        match self {
            AnyBoxSecret::L256(k) => dstu_core::crypto_box::open(sealed, k).map_err(|e| match e {
                dstu_core::crypto_box::OpenError::Truncated => CliError::BoxOpenTruncated(curve),
                dstu_core::crypto_box::OpenError::InvalidCiphertext => {
                    CliError::BoxOpenFailed(curve)
                }
                dstu_core::crypto_box::OpenError::UnsupportedVersion => {
                    CliError::BoxOpenUnsupportedVersion
                }
            }),
            AnyBoxSecret::L512(k) => {
                dstu_core::crypto_box512::open(sealed, k).map_err(|e| match e {
                    dstu_core::crypto_box512::OpenError::Truncated => {
                        CliError::BoxOpenTruncated(curve)
                    }
                    dstu_core::crypto_box512::OpenError::InvalidCiphertext => {
                        CliError::BoxOpenFailed(curve)
                    }
                    dstu_core::crypto_box512::OpenError::UnsupportedVersion => {
                        CliError::BoxOpenUnsupportedVersion
                    }
                })
            }
        }
    }
}

impl AnyBoxPublic {
    fn seal(&self, message: &[u8]) -> Result<Vec<u8>, CliError> {
        match self {
            AnyBoxPublic::L256(k) => {
                dstu_core::crypto_box::seal(message, k).map_err(|e| CliError::Random(e.to_string()))
            }
            AnyBoxPublic::L512(k) => dstu_core::crypto_box512::seal(message, k)
                .map_err(|e| CliError::Random(e.to_string())),
        }
    }
}

/// Reads a `crypto_box` secret key of either curve and validates it with that curve's
/// `SecretKey::from_bytes`.
fn read_box_secret_key(
    path: &std::path::Path,
    command: &'static str,
) -> Result<AnyBoxSecret, CliError> {
    let (kind, bytes) = keyfile::read_key(
        path,
        command,
        &[KeyKind::Box256Secret, KeyKind::Box512Secret],
    )?;
    let key = if kind == KeyKind::Box256Secret {
        dstu_core::crypto_box::SecretKey::from_bytes(&key_array::<32>(&bytes))
            .map(AnyBoxSecret::L256)
    } else {
        dstu_core::crypto_box512::SecretKey::from_bytes(&key_array::<64>(&bytes))
            .map(AnyBoxSecret::L512)
    };
    key.ok_or(CliError::BoxKeyInvalid)
}

/// Reads a `crypto_box` public key of either curve and validates it with that curve's
/// `PublicKey::from_bytes`.
fn read_box_public_key(
    path: &std::path::Path,
    command: &'static str,
) -> Result<AnyBoxPublic, CliError> {
    let (kind, bytes) = keyfile::read_key(
        path,
        command,
        &[KeyKind::Box256Public, KeyKind::Box512Public],
    )?;
    let key = if kind == KeyKind::Box256Public {
        dstu_core::crypto_box::PublicKey::from_bytes(&key_array::<32>(&bytes))
            .map(AnyBoxPublic::L256)
    } else {
        dstu_core::crypto_box512::PublicKey::from_bytes(&key_array::<64>(&bytes))
            .map(AnyBoxPublic::L512)
    };
    key.ok_or(CliError::BoxKeyInvalid)
}

#[derive(Debug, PartialEq, Eq)]
pub struct BoxKeygenArgs {
    pub out_path: PathBuf,
}

/// Parses `box-keygen`'s flags (`--out`, required).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`] or [`CliError::UnknownFlag`].
pub fn parse_box_keygen_args(args: &[String]) -> Result<BoxKeygenArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--out"], &[])?;
    Ok(BoxKeygenArgs {
        out_path: scanner.path("--out")?,
    })
}

/// Runs `box-keygen`: draws a fresh `crypto_box` secret key via rejection sampling
/// ([`dstu_core::crypto_box::SecretKey::generate`], `docs/TASKS.md` T-178) and writes its raw
/// 32-byte encoding to `--out`. A separate command from `keygen`/`sign-keygen` - a `crypto_box`
/// secret key is a third, incompatible key shape (D-47's "delete the knob": no `--type` flag
/// choosing between them).
///
/// # Errors
///
/// Returns [`CliError::Random`] if the OS CSPRNG fails, or [`CliError::Io`] if `--out` can't be
/// written.
pub fn run_box_keygen_command(args: &BoxKeygenArgs) -> Result<(), CliError> {
    let key = dstu_core::crypto_box::SecretKey::generate()
        .map_err(|e| CliError::Random(e.to_string()))?;
    write_new_key_file(
        &args.out_path,
        &keyfile::encode(KeyKind::Box256Secret, &key.to_bytes()),
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct BoxPubkeyArgs {
    pub key_path: PathBuf,
    pub out_path: PathBuf,
}

/// Parses `box-pubkey`'s flags (`--key`/`--out`, both required).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`] or [`CliError::UnknownFlag`].
pub fn parse_box_pubkey_args(args: &[String]) -> Result<BoxPubkeyArgs, CliError> {
    let scanner = ArgScanner::scan(args, &["--key", "--out"], &[])?;
    Ok(BoxPubkeyArgs {
        key_path: scanner.path("--key")?,
        out_path: scanner.path("--out")?,
    })
}

/// Runs `box-pubkey`: reads a `crypto_box` secret key of either curve from `--key`, derives its
/// public key (`SecretKey::public_key`), and writes the compressed (`x`-coordinate only, 32 or 64
/// bytes, see `crypto_box`'s own module doc) encoding to `--out` as a public-key line of the same
/// curve - the format `box-seal --key` expects (T-257).
///
/// # Errors
///
/// Returns [`CliError::Io`] or a key-file error for file problems, or
/// [`CliError::BoxKeyInvalid`] if `--key` isn't a valid `crypto_box` secret key.
pub fn run_box_pubkey_command(args: &BoxPubkeyArgs) -> Result<(), CliError> {
    let line = read_box_secret_key(&args.key_path, "box-pubkey")?.public_key_line();
    write_new_key_file(&args.out_path, &line)
}

#[derive(Debug, PartialEq, Eq)]
pub struct BoxSealArgs {
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `box-seal`'s flags (`--key`/`--in`/`--out` required, `--iterations` optional -
/// benchmarking only, same shape as [`parse_sign_args`]).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`], [`CliError::InvalidIterations`], or [`CliError::UnknownFlag`].
pub fn parse_box_seal_args(args: &[String]) -> Result<BoxSealArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &["--key", "--in", "--out", "--iterations"],
        &["--force"],
    )?;
    Ok(BoxSealArgs {
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `box-seal`: reads a recipient public key of either curve from `--key` and encrypts `--in`
/// to it (`crypto_box::seal` or `crypto_box512::seal`, by the key's kind, T-257).
///
/// **Not memory-bounded** (D-42 note, deliberate rather than overlooked): `crypto_box::seal`
/// itself takes `message: &[u8]` - a genuinely chunked `seal_stream` would need its own library
/// addition first (see `crypto_box`'s own module doc, "Hybrid via KDF" section), so `--in` is read
/// whole into memory here, unlike `encrypt`/`decrypt`'s bounded-chunk streaming.
///
/// `iterations > 1` is the D-34/T-179 benchmark path (`docs/PERFORMANCE.md`): unlike `sign`
/// (deterministic nonce, bit-identical every call), each `seal` call draws fresh randomness
/// internally (a new seed and ephemeral scalar), so this measures real per-call throughput
/// including that cost - not a cached-schedule shortcut to avoid (D-80's concern doesn't apply
/// here, there is no schedule to cache). Only the last iteration's output is written to `--out`.
///
/// # Errors
///
/// Returns [`CliError::Io`] if `--key`/`--in` can't be read or `--out` can't be written, a key-file
/// error if `--key` isn't a box public-key line, [`CliError::BoxKeyInvalid`] if its bytes aren't a
/// valid public key, or [`CliError::Random`] if the OS CSPRNG fails.
#[allow(clippy::cast_precision_loss)] // human-readable ops/s diagnostic, not exact at any realistic count
pub fn run_box_seal_command(args: &BoxSealArgs) -> Result<(), CliError> {
    let public = read_box_public_key(&args.key_path, "box-seal")?;
    check_outputs(&[("--out", &args.out_path)], &[("--key", &args.key_path)])?;
    let (out, out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;
    let message = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;
    let iterations = args.iterations.max(1);

    let start = Instant::now();
    let mut sealed = public.seal(&message)?;
    for _ in 1..iterations {
        sealed = public.seal(&message)?;
    }
    let elapsed = start.elapsed();

    out.write_all_and_commit(out_file, &sealed)?;

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        let ops_per_s = if per_op_ns == 0 {
            0.0
        } else {
            1e9 / (per_op_ns as f64)
        };
        eprintln!(
            "iterations={} total_ns={} per_op_ns={per_op_ns} ops_per_s={ops_per_s:.2}",
            args.iterations,
            elapsed.as_nanos(),
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct BoxOpenArgs {
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `box-open`'s flags (`--key`/`--in`/`--out` required, `--iterations` optional -
/// benchmarking only, same shape as [`parse_verify_args`]).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`], [`CliError::InvalidIterations`], or [`CliError::UnknownFlag`].
pub fn parse_box_open_args(args: &[String]) -> Result<BoxOpenArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &["--key", "--in", "--out", "--iterations"],
        &["--force"],
    )?;
    Ok(BoxOpenArgs {
        key_path: scanner.path("--key")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        iterations: scanner.iterations()?,
        force: scanner.bool_flag("--force"),
    })
}

/// Runs `box-open`: reads a secret key of either curve from `--key` and decrypts `--in`
/// (`crypto_box::open` or `crypto_box512::open`, by the key's kind, T-257) - see [`run_box_seal_command`]'s doc comment for the same
/// not-memory-bounded caveat.
///
/// `iterations > 1` is the D-34/T-179 benchmark path: `open` is deterministic given the same
/// input, so every iteration reproduces the identical output - only the decrypt call itself is
/// timed in a loop, key/ciphertext parsed once outside it (D-80's cached-schedule discipline).
///
/// # Errors
///
/// Returns [`CliError::Io`] if `--key`/`--in` can't be read or `--out` can't be written, a key-file
/// error if `--key` isn't a box secret-key line, [`CliError::BoxKeyInvalid`] if its bytes aren't a
/// valid secret key, [`CliError::BoxOpenTruncated`] if `--in` is too short to be real `box-seal`
/// output for the key's curve, or [`CliError::BoxOpenFailed`] for any other authentication failure
/// (including a file sealed to the other curve).
#[allow(clippy::cast_precision_loss)] // human-readable ops/s diagnostic, not exact at any realistic count
pub fn run_box_open_command(args: &BoxOpenArgs) -> Result<(), CliError> {
    let secret = read_box_secret_key(&args.key_path, "box-open")?;
    check_outputs(&[("--out", &args.out_path)], &[("--key", &args.key_path)])?;
    let (out, out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;
    let sealed = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;
    let iterations = args.iterations.max(1);

    let start = Instant::now();
    let mut opened = secret.open(&sealed)?;
    for _ in 1..iterations {
        opened = secret.open(&sealed)?;
    }
    let elapsed = start.elapsed();

    out.write_all_and_commit(out_file, &opened)?;

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        let ops_per_s = if per_op_ns == 0 {
            0.0
        } else {
            1e9 / (per_op_ns as f64)
        };
        eprintln!(
            "iterations={} total_ns={} per_op_ns={per_op_ns} ops_per_s={ops_per_s:.2}",
            args.iterations,
            elapsed.as_nanos(),
        );
    }

    Ok(())
}

/// Runs `box-keygen512`: draws a fresh `crypto_box512` secret key via rejection sampling
/// ([`dstu_core::crypto_box512::SecretKey::generate`], `docs/TASKS.md` T-193) and writes its raw
/// 64-byte encoding to `--out`. A separate command from `box-keygen` - `crypto_box512` keys are a
/// distinct, wider shape (E512/1 vs. E256/1), not the same key type at a different size (D-47's
/// "delete the knob": no `--curve` flag choosing between them).
///
/// # Errors
///
/// Returns [`CliError::Random`] if the OS CSPRNG fails, or [`CliError::Io`] if `--out` can't be
/// written.
pub fn run_box512_keygen_command(args: &BoxKeygenArgs) -> Result<(), CliError> {
    let key = dstu_core::crypto_box512::SecretKey::generate()
        .map_err(|e| CliError::Random(e.to_string()))?;
    write_new_key_file(
        &args.out_path,
        &keyfile::encode(KeyKind::Box512Secret, &key.to_bytes()),
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct StrumokArgs {
    pub variant: HashBits,
    pub key_path: PathBuf,
    pub iv_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    pub raw_schedule: bool,
    /// Replace an existing output (T-258, D-214).
    pub force: bool,
}

/// Parses `strumok-crypt`'s flags (`--variant`/`--key`/`--iv`/`--in`/`--out` required,
/// `--iterations`/`--raw-schedule` optional).
///
/// # Errors
///
/// Same cases as [`parse_block_args`], plus `--iv` sharing `--key`'s missing-flag/IO handling.
pub fn parse_strumok_args(args: &[String]) -> Result<StrumokArgs, CliError> {
    let scanner = ArgScanner::scan(
        args,
        &[
            "--variant",
            "--key",
            "--iv",
            "--in",
            "--out",
            "--iterations",
        ],
        &["--raw-schedule", "--force"],
    )?;
    Ok(StrumokArgs {
        variant: scanner.variant(HashBits::parse)?,
        key_path: scanner.path("--key")?,
        iv_path: scanner.path("--iv")?,
        in_path: scanner.path("--in")?,
        out_path: scanner.path("--out")?,
        iterations: scanner.iterations()?,
        raw_schedule: scanner.bool_flag("--raw-schedule"),
        force: scanner.bool_flag("--force"),
    })
}

/// Read/write chunk size for `strumok-crypt`'s real (`iterations <= 1`) path - same rationale and
/// size as `kupyna-digest`'s [`DIGEST_STREAM_CHUNK_BYTES`] (D-42): small enough that peak memory
/// stays bounded by this constant rather than `--in`'s size, large enough that per-syscall
/// overhead (now on *both* the read and the write side, unlike a hash which only reads) stays
/// negligible. `Strumok::apply_keystream`'s own chunk-invariance (`docs/TASKS.md` T-24) is exactly what
/// makes feeding it one chunk at a time - instead of the whole file - safe to begin with.
const STRUMOK_STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// Temp file: same rationale and shape as [`run_secretstream_command`]'s: `--out` is written to a temp file next
/// to it first and only `std::fs::rename`d onto the real path once the whole stream succeeds. Found
/// necessary the hard way (not designed in up front): `strumok-crypt`'s old streaming path opened
/// `--out` via `File::create` (truncating it) before finishing reading `--in`, so `--in`==`--out`
/// ("encrypt this file in place") silently produced a 0-byte file - exit code 0, no error, real data
/// loss, caught only by an empirical `--in`==`--out` smoke-test probe (`docs/TASKS.md` T-200). This
/// also happens to fix a second, independent gap: an I/O error mid-stream used to leave a partially-
/// written `--out` behind, violating this project's own no-partial-output-on-failure standard (D-65)
/// that every other command already meets.
///
/// Streams `--in` to a temp file next to `--out` in fixed-size chunks (the `iterations <= 1`, real
/// usage path), then renames onto `args.out_path` only once the whole stream has succeeded -
/// removing the temp file instead on any error. Split out of [`run_strumok_command`] to keep that
/// function under clippy's line-count lint and to give this temp-file-then-rename discipline (the
/// same one [`run_secretstream_command`] already uses) one clear place to read.
///
/// # Errors
///
/// Returns [`CliError::Io`] if `--in` can't be read or the temp/final `--out` path can't be
/// written/renamed.
fn run_strumok_stream(
    args: &StrumokArgs,
    key: &[u8],
    iv: &[u8],
    out: OutputFile,
    mut out_file: std::fs::File,
) -> Result<(), CliError> {
    use std::io::{Read, Write};

    macro_rules! stream_variant {
        ($cipher:ty, $key_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(key);
            let mut iv_arr = [0u8; 32];
            iv_arr.copy_from_slice(iv);

            let mut in_file = std::fs::File::open(&args.in_path).map_err(|e| CliError::Io {
                path: args.in_path.clone(),
                message: e.to_string(),
            })?;
            let mut cipher = <$cipher>::new(&key_arr, &iv_arr);
            let mut chunk = [0u8; STRUMOK_STREAM_CHUNK_BYTES];
            loop {
                let n = in_file.read(&mut chunk).map_err(|e| CliError::Io {
                    path: args.in_path.clone(),
                    message: e.to_string(),
                })?;
                if n == 0 {
                    break;
                }
                cipher.apply_keystream(&mut chunk[..n]);
                out_file.write_all(&chunk[..n]).map_err(|e| CliError::Io {
                    path: out.tmp_path().to_path_buf(),
                    message: e.to_string(),
                })?;
            }
        }};
    }

    match args.variant {
        HashBits::B256 => stream_variant!(Strumok256, 32),
        HashBits::B512 => stream_variant!(Strumok512, 64),
    }
    out.commit(out_file)
}

/// Runs `strumok-crypt`: applies the keystream to `--in` (arbitrary length).
///
/// `iterations <= 1` (real usage) streams `--in` to `--out` through [`STRUMOK_STREAM_CHUNK_BYTES`]-
/// sized chunks via [`run_strumok_stream`] - read, `apply_keystream` in place, write, discard - so
/// peak memory is bounded regardless of file size (D-42, same treatment as `kupyna-digest`/T-83).
/// `--raw-schedule` has no effect here: with exactly one iteration, constructing the cipher fresh
/// vs. once makes no observable difference, so this path always constructs it once.
///
/// `iterations > 1` is the D-34 benchmark path, unchanged: `--raw-schedule` re-initializes the
/// cipher (`Strumok*::new`) fresh before every iteration and re-applies it to a fresh copy of the
/// original buffer each time - this matches `benches/strumok.rs`'s own convention
/// (`Strumok256::new(...).apply_keystream(...)` inside every `b.iter`), so it's the number to
/// sanity-check against the in-process `criterion` figures. The default (no flag) initializes once
/// and applies the keystream `iterations` times continuing the same state (a real continuous
/// stream) - the cheaper, steady-state-throughput number. This path still reads the whole file
/// once up front (not streamed) - re-reading it from disk every iteration would reintroduce
/// disk-cache-dependent I/O noise into the timed MB/s figure, the same reasoning as
/// `kupyna-digest`'s benchmark path in D-42.
///
/// # Errors
///
/// Returns [`CliError::Io`] if `--key`/`--iv`/`--in` can't be read or `--out` can't be written, or
/// [`CliError::WrongLength`] if `--key`/`--iv` aren't the variant's expected length.
#[allow(clippy::cast_precision_loss)] // human-readable MB/s diagnostic, not exact at any realistic byte count
pub fn run_strumok_command(args: &StrumokArgs) -> Result<(), CliError> {
    let key_len = match args.variant {
        HashBits::B256 => 32,
        HashBits::B512 => 64,
    };
    let key = read_exact_file(&args.key_path, LengthOf::Key, key_len)?;
    let iv = read_exact_file(&args.iv_path, LengthOf::Iv, 32)?;
    check_outputs(
        &[("--out", &args.out_path)],
        &[("--key", &args.key_path), ("--iv", &args.iv_path)],
    )?;
    let (out, out_file) = OutputFile::create(&args.out_path, &args.in_path, args.force)?;
    let iterations = args.iterations.max(1);

    if iterations <= 1 {
        return run_strumok_stream(args, &key, &iv, out, out_file);
    }

    let input = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;

    macro_rules! run_strumok_variant {
        ($cipher:ty, $key_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(&key);
            let mut iv_arr = [0u8; 32];
            iv_arr.copy_from_slice(&iv);

            let start = Instant::now();
            let mut buf = input.clone();
            if args.raw_schedule {
                for _ in 0..iterations {
                    buf.copy_from_slice(&input);
                    <$cipher>::new(&key_arr, &iv_arr).apply_keystream(&mut buf);
                }
            } else {
                let mut cipher = <$cipher>::new(&key_arr, &iv_arr);
                for _ in 0..iterations {
                    cipher.apply_keystream(&mut buf);
                }
            }
            (buf, start.elapsed())
        }};
    }

    let (output, elapsed) = match args.variant {
        HashBits::B256 => run_strumok_variant!(Strumok256, 32),
        HashBits::B512 => run_strumok_variant!(Strumok512, 64),
    };

    out.write_all_and_commit(out_file, &output)?;

    if args.iterations > 1 {
        let per_op_ns = elapsed.as_nanos() / u128::from(args.iterations);
        let total_bytes = (input.len() as u128) * u128::from(args.iterations);
        let mb_per_s = if elapsed.as_nanos() == 0 {
            0.0
        } else {
            (total_bytes as f64) / (elapsed.as_secs_f64()) / 1e6
        };
        eprintln!(
            "iterations={} schedule={} total_ns={} per_op_ns={per_op_ns} mb_per_s={mb_per_s:.2}",
            args.iterations,
            if args.raw_schedule { "raw" } else { "cached" },
            elapsed.as_nanos(),
        );
    }

    Ok(())
}

/// `true` for `--help`/`-h` - checked against every token in a (sub)command's remaining args
/// (not just the first one), so `uacrypt kalyna-block encrypt --key k --help` still shows help
/// instead of failing on a missing `--in`/`--out`.
fn is_help_flag(s: &str) -> bool {
    s == "--help" || s == "-h"
}

/// `true` for `--version`/`-V` (the `-V` short form matches `cargo --version`'s own convention,
/// e.g. `cargo -V`). Only checked at the top level (`uacrypt --version`), unlike `is_help_flag` -
/// there is no per-subcommand version to report, every command ships as one binary.
/// The version byte `encrypt` and `box-seal` write first (`dstu_core`'s
/// `crypto_secretstream::FORMAT_VERSION` and `crypto_box`'s `FORMAT_VERSION`, D-202/D-208), printed
/// by `--version`. A const assert pins the first and a unit test checks a real sealed file for the
/// second, so it cannot silently drift from the library.
const CONTAINER_FORMAT_VERSION: u8 = 2;
const _: () = assert!(CONTAINER_FORMAT_VERSION == dstu_core::crypto_secretstream::FORMAT_VERSION);

fn is_version_flag(s: &str) -> bool {
    s == "--version" || s == "-V"
}

const TOP_LEVEL_HELP: &str = "\
uacrypt - a CLI over dstu-core, Ukrainian DSTU cryptographic standards (Kalyna, Kupyna, Strumok).

Pre-release, not independently audited - see docs/SECURITY.md in the project repository for the
threat model.

USAGE:
    uacrypt <command> [flags]
    uacrypt <command> --help    show that command's flags and an example invocation
    uacrypt help [<command>]    the same, or this overview
    uacrypt --version           print the version and the container format version, then exit

EVERYDAY COMMANDS:
    keygen          Generate a fresh random key for `encrypt`/`decrypt`.
    encrypt         Encrypt a file of any size with a `keygen` key (authenticated, streamed).
    decrypt         Decrypt a file produced by `encrypt`.
    hash            Print a file's Kupyna-256 digest, or --check a list of them.
    sign-keygen     Generate a fresh signing key (DSTU 4145, m=163).
    sign-keygen257  Generate a fresh signing key (DSTU 4145, m=257, what Diia signatures use).
    sign-pubkey     Derive the matching verifying key from a signing key, for `verify`.
    sign            Sign a file of any size with a signing key.
    verify          Check a `sign` signature against a verifying key.
    box-keygen      Generate a fresh crypto_box secret key (DSTU 9041, l(p)=256).
    box-keygen512   Generate a fresh crypto_box secret key (DSTU 9041, l(p)=512).
    box-pubkey      Derive the matching public key from a secret key, for `box-seal`.
    box-seal        Encrypt a file to a recipient's public key (DSTU 9041, hybrid via KDF).
    box-open        Decrypt a file produced by `box-seal`.
    key-import      Convert a raw key file from uacrypt 0.4 or older into a typed key file.

LOWER-LEVEL COMMANDS (benchmarking and interop with other DSTU implementations):
    kalyna-block    Single Kalyna block encrypt/decrypt - exactly one block, no file support.
    kalyna-ccm      Kalyna-CCM authenticated encryption - messages/AAD capped at 255 bytes.
    kalyna-gcm      Kalyna-GCM authenticated encryption - no message-length cap.
    kalyna-cmac     Kalyna-CMAC message authentication (compute/verify a tag, no encryption).
    kalyna-gmac     Kalyna-GMAC message authentication (compute/verify a tag, no encryption).
    kalyna-kw       Kalyna key wrap/unwrap - wraps block-aligned key material, not a general cipher.
    kalyna-xts      Kalyna-XTS disk-sector mode - confidentiality only, no tag, by design.
    kupyna-digest   Kupyna hash with a selectable variant (256/512) and a benchmark --iterations flag.
    strumok-crypt   Strumok keystream cipher - NOT authenticated, tampering is never detected.

FILE FORMATS (byte layouts, with field sizes in bytes: see docs/CLI.md 'File formats'):
    encrypt         version (1) || header (32), then records:
                    chunk tag (1) || length (4, LE) || ciphertext || auth tag (16)
    box-seal        version (1) || KEM ciphertext (128 / 256) || header (32) || ciphertext || auth tag (16)
    key files       one text line `<kind>:<key hex>:<check hex>`, see docs/CLI.md 'Key files';
                    the lower-level commands above take raw key bytes instead
    kalyna-gcm/-gmac write raw ciphertext/tag files with no container and no format version, so
    use `encrypt` or `box-seal` for files.

The curve is chosen once, by the keygen command; every other command reads it from the key.

An existing output file is never replaced unless you pass --force; a failed command leaves no
output behind. Key files (secret or public) are never replaced at all - there is no --force for
them, and another command's --force does not replace an existing key file either.

EXIT STATUS:
    0   success
    1   the input was checked and rejected (authentication failed, bad signature, malformed data,
        a `hash --check` mismatch)
    2   usage error (unknown command or flag, a flag missing, repeated or without a value)
    3   a file or key could not be used (missing, unreadable, wrong size, already exists)

Run `uacrypt <command> --help` for that command's flags and an example.
";

const KEYGEN_HELP: &str = "\
uacrypt keygen - generate a fresh random key for `encrypt`/`decrypt`.

Draws from the OS CSPRNG (dstu_core::randombytes, via crypto_secretstream::Key::generate) and
writes it to --out as a typed key file: one text line that names its kind, so no other command
mistakes it for its own kind of key (docs/CLI.md 'Key files'). Refuses to overwrite
--out if it already exists (so a repeated run cannot destroy a key); delete the old file first if
you really want a new key. Every `*-keygen` command behaves the same way, and on Unix writes the
key with mode 0600.

USAGE:
    uacrypt keygen --out <path>

FLAGS:
    --out <path>    where to write the key

EXAMPLE:
    uacrypt keygen --out key.bin
";

const ENCRYPT_HELP: &str = "\
uacrypt encrypt - encrypt a file of any size with a `keygen` key.

Streamed in bounded memory chunks (no whole-file buffering) and authenticated: `decrypt` detects
any tampering with the output rather than silently returning wrong plaintext. Built on
dstu_core::crypto_secretstream.

OUTPUT FORMAT:
    version (1, currently 2) || header (32) || records, each: chunk tag (1) || ciphertext
    length (4, little-endian) || ciphertext || auth tag (16). Plaintext is split into 8192-byte
    chunks: every record but the last is exactly 8192 bytes, and the last is tagged final, so a
    truncated file is rejected. See docs/CLI.md 'File formats'.

USAGE:
    uacrypt encrypt --key <path> --in <path> --out <path> [--force]

FLAGS:
    --key <path>    a key file made by `uacrypt keygen` (not a passphrase)
    --in <path>     file to encrypt
    --out <path>    where to write the encrypted output
    --force         replace --out if it already exists (without it: refused)

EXAMPLE:
    uacrypt encrypt --key key.bin --in report.pdf --out report.pdf.enc

Notes:
    - Make a key with `uacrypt keygen --out key.bin`; a raw key file from uacrypt 0.4 or older
      can be converted with `uacrypt key-import --kind symmetric`.
    - --in and --out may be the same path (encrypts in place) with --force; --out is only
      replaced after the whole file is written, so a failure never leaves partial output.
";

const DECRYPT_HELP: &str = "\
uacrypt decrypt - decrypt a file produced by `encrypt`, using the same key.

Streamed in bounded memory chunks and authenticated: a wrong key or a tampered/truncated file is
rejected with an error before anything is written to --out, rather than producing wrong plaintext.

USAGE:
    uacrypt decrypt --key <path> --in <path> --out <path> [--force]

FLAGS:
    --key <path>    the same key file used for `encrypt`
    --in <path>     the encrypted file (must be real `encrypt` output)
    --out <path>    where to write the decrypted output
    --force         replace --out if it already exists (without it: refused)

EXAMPLE:
    uacrypt decrypt --key key.bin --in report.pdf.enc --out report.pdf

Notes:
    - --in and --out may be the same path (decrypts in place) with --force.
    - Fails loudly (no --out written) on a wrong key, a wrong/tampered file, or a file produced by
      an older uacrypt version - the on-disk format is not yet stable pre-1.0.
";

const HASH_HELP: &str = "\
uacrypt hash - print a file's Kupyna-256 digest, or check a list of them (like sha256sum).

Fixed to Kupyna-256 (no --variant knob) - for the other Kupyna variant, a binary digest file or
benchmarking, see `kupyna-digest --help`. Streams each file from disk in bounded chunks, so file
size is not a memory concern.

USAGE:
    uacrypt hash --in <path>
    uacrypt hash --check <file>

FLAGS:
    --in <path>      file to hash; prints `<64 hex digits>  <path>` to stdout
    --check <file>   read such lines and hash each listed file; prints `<path>: OK` or
                     `<path>: FAILED` and exits 1 if any file does not match or cannot be read

EXAMPLE:
    uacrypt hash --in report.pdf > report.pdf.kupyna256
    uacrypt hash --check report.pdf.kupyna256

Notes:
    - The check file is validated whole before anything is hashed: every line must be exactly
      `<64 hex digits><two spaces><path>` (CRLF and upper-case hex are accepted), at most 16 MiB.
    - Relative paths in the check file are resolved against the current directory, not the check
      file's directory - run --check from where you ran `hash`.
    - The digests are Kupyna-256, not SHA-256: a `sha256sum` file checks as FAILED on every line.
    - Windows PowerShell 5.1's `>` writes UTF-16 and garbles non-ASCII paths; use PowerShell 7,
      cmd or `cmd /c \"uacrypt hash --in <file> > <list>\"`. A UTF-8 BOM is accepted.
    - A path that is not UTF-8 or contains a control character (a newline, a terminal escape) is
      refused: it could not be read back as one line.
";

const SIGN_KEYGEN_HELP: &str = "\
uacrypt sign-keygen - generate a fresh signing key for `sign` (DSTU 4145, m=163).

Draws from the OS CSPRNG via rejection sampling against the DSTU 4145 curve order (never a modulo
reduction, which would bias the result) and writes it to --out as a typed key file
(docs/CLI.md 'Key files'). A separate command from `keygen` - a signing key and an `encrypt`/`decrypt` key
are different, incompatible things, not two settings of the same command. For DSTU 4145's other
implemented curve (m=257, what real Diia-issued signatures use), use `sign-keygen257` instead.
`sign-pubkey`, `sign` and `verify` take a key of either curve and read the curve from it.

USAGE:
    uacrypt sign-keygen --out <path>

FLAGS:
    --out <path>    where to write the signing key

EXAMPLE:
    uacrypt sign-keygen --out signing.key

Notes:
    - Keep this file secret - anyone who has it can sign as you.
    - Derive the matching public verifying key with `uacrypt sign-pubkey`.
";

const SIGN_PUBKEY_HELP: &str = "\
uacrypt sign-pubkey - derive the matching verifying key from a signing key.

Reads --key (a `sign-keygen` or `sign-keygen257` output) and writes the matching verifying key,
of the same curve, to --out as a typed key file - safe to share, unlike the signing key.
Never replaces an existing --out, which could be the secret key itself.

USAGE:
    uacrypt sign-pubkey --key <path> --out <path>

FLAGS:
    --key <path>    a signing key (from `uacrypt sign-keygen` or `sign-keygen257`)
    --out <path>    where to write the verifying key

EXAMPLE:
    uacrypt sign-pubkey --key signing.key --out verifying.key
";

const SIGN_HELP: &str = "\
uacrypt sign - sign a file of any size with a signing key (DSTU 4145).

Hashes --in with Kupyna-256 in bounded memory chunks, then signs the digest (deterministic nonce -
no RNG involved in signing itself, only in `sign-keygen`). The curve is the key's: writes a
42-byte signature to --out for an m=163 key, 66 bytes for an m=257 key.

USAGE:
    uacrypt sign --key <path> --in <path> --out <path> [--force]

FLAGS:
    --key <path>        a signing key (from `uacrypt sign-keygen` or `sign-keygen257`)
    --in <path>         file to sign
    --out <path>        where to write the signature
    --force             replace --out if it already exists (without it: refused)

EXAMPLE:
    uacrypt sign --key signing.key --in report.pdf --out report.pdf.sig
";

const VERIFY_HELP: &str = "\
uacrypt verify - check a `sign` signature against a verifying key (DSTU 4145).

Hashes --in the same way `sign` did, then checks --sig against --key (a `sign-pubkey` output, of
either curve). The key file names its curve, so you never need to tell `verify` which one; a key of any other kind is refused by name. Prints `Signature OK (DSTU 4145, m=...)` to stderr and exits 0 on a
valid signature; exits with an error
(nothing written) if the message, signature, or key do not match - a tampered file or a wrong key
is detected, not silently accepted.

USAGE:
    uacrypt verify --key <path> --in <path> --sig <path>

FLAGS:
    --key <path>        a verifying key (from `uacrypt sign-pubkey`)
    --in <path>         the file that was signed
    --sig <path>        the signature (from `uacrypt sign`, made with the matching signing key)

EXAMPLE:
    uacrypt verify --key verifying.key --in report.pdf --sig report.pdf.sig
";

const SIGN_KEYGEN257_HELP: &str = "\
uacrypt sign-keygen257 - generate a fresh signing key for `sign` (DSTU 4145, m=257).

Same shape as `sign-keygen`, over DSTU 4145's m=257 curve instead of m=163. The curve is chosen
here, once, and recorded in the key: `sign-pubkey`, `sign` and `verify` read it from there.
m=257 is what real Diia-issued qualified signatures use in production, confirmed by inspecting an
actual issued certificate - m=163 is the plain `sign-keygen` only because this project shipped it
first, not because it's recommended over m=257.

USAGE:
    uacrypt sign-keygen257 --out <path>

FLAGS:
    --out <path>    where to write the signing key

EXAMPLE:
    uacrypt sign-keygen257 --out signing257.key

Notes:
    - Keep this file secret - anyone who has it can sign as you.
    - Derive the matching public verifying key with `uacrypt sign-pubkey`.
";

const BOX_KEYGEN_HELP: &str = "\
uacrypt box-keygen - generate a fresh crypto_box secret key for `box-open`.

Draws from the OS CSPRNG via rejection sampling against the DSTU 9041 curve order and
writes it to --out as a typed key file (docs/CLI.md 'Key files'). A separate command from `keygen`/
`sign-keygen` - a crypto_box key is a third, incompatible key shape. This is the l(p)=256 curve;
`box-keygen512` makes an l(p)=512 key, and every other box command reads the curve from the key.

USAGE:
    uacrypt box-keygen --out <path>

FLAGS:
    --out <path>    where to write the secret key

EXAMPLE:
    uacrypt box-keygen --out box.key

Notes:
    - Keep this file secret - anyone who has it can decrypt messages sealed to it.
    - Derive the matching public key with `uacrypt box-pubkey`.
";

const BOX_PUBKEY_HELP: &str = "\
uacrypt box-pubkey - derive the matching public key from a crypto_box secret key.

Reads --key (a `box-keygen` or `box-keygen512` output) and writes the matching public key, of the
same curve, that `box-seal` needs to --out as a typed key file - safe to share, unlike the secret
key itself.
Never replaces an existing --out, which could be the secret key itself.

USAGE:
    uacrypt box-pubkey --key <path> --out <path>

FLAGS:
    --key <path>    a crypto_box secret key (from `uacrypt box-keygen` or `box-keygen512`)
    --out <path>    where to write the public key

EXAMPLE:
    uacrypt box-pubkey --key box.key --out box.pub
";

const BOX_SEAL_HELP: &str = "\
uacrypt box-seal - encrypt a file to a recipient's public key (DSTU 9041, hybrid via KDF).

Unlike `encrypt` (which needs a shared symmetric key both sides already have), box-seal only needs
the recipient's public key - anyone can seal a message only the matching secret key can open. Wraps
a fresh random seed asymmetrically (dstu_core::crypto_box or crypto_box512, whichever curve --key
is), derives a symmetric key from it, and encrypts --in with that key.

Not memory-bounded: --in is read whole into memory (unlike `encrypt`'s bounded-chunk streaming) -
fine for typical messages/keys, not recommended for very large files yet.

OUTPUT FORMAT:
    version (1, currently 2) || KEM ciphertext (128 for an l(p)=256 key, 256 for l(p)=512) ||
    header (32) || ciphertext (same length as --in) || auth tag (16) - 177 or 305 bytes of
    overhead. See docs/CLI.md 'File formats'.

USAGE:
    uacrypt box-seal --key <path> --in <path> --out <path> [--force]

FLAGS:
    --key <path>        the recipient's public key (from `uacrypt box-pubkey`, either curve)
    --in <path>         file to encrypt
    --out <path>        where to write the sealed output
    --force             replace --out if it already exists (without it: refused)

EXAMPLE:
    uacrypt box-seal --key recipient.pub --in message.txt --out message.txt.box
";

const BOX_OPEN_HELP: &str = "\
uacrypt box-open - decrypt a file produced by `box-seal`, using the matching secret key.

A wrong key (including one of the other curve) or a tampered/truncated file is rejected with an
error before anything is written to --out, rather than producing wrong plaintext.

USAGE:
    uacrypt box-open --key <path> --in <path> --out <path> [--force]

FLAGS:
    --key <path>        the recipient's secret key (from `uacrypt box-keygen` or `box-keygen512`)
    --in <path>         the sealed file (must be real `box-seal` output)
    --out <path>        where to write the decrypted output
    --force             replace --out if it already exists (without it: refused)

EXAMPLE:
    uacrypt box-open --key box.key --in message.txt.box --out message.txt
";

const KEY_IMPORT_HELP: &str = "\
uacrypt key-import - convert a raw key file from uacrypt 0.4 or older into a typed key file.

uacrypt 0.5 key files are one text line that names the key's kind (see docs/CLI.md 'Key files'),
so a key of the wrong kind is rejected by name. Older versions wrote raw bytes; this converts one
such file. --kind says what the raw file is - the only place you ever type a key's kind - and the
bytes are checked exactly as the commands that use them will check them. A raw verifying key
must carry the curve byte `sign-pubkey`/`sign-pubkey257` wrote. Prints the new file's check value
to stderr, and for a secret key its public key's check value too, so you can compare it with a
public key you already shared. Like every keygen, it never overwrites an existing file.

USAGE:
    uacrypt key-import --kind <kind> --in <path> --out <path>

FLAGS:
    --kind <kind>   symmetric (a `keygen` key), sign163-secret, sign163-public, sign257-secret,
                    sign257-public, box256-secret, box256-public, box512-secret, box512-public
    --in <path>     the raw key file
    --out <path>    where to write the typed key file

EXAMPLE:
    uacrypt key-import --kind box256-secret --in box.key --out box.key.txt
";

const BOX_KEYGEN512_HELP: &str = "\
uacrypt box-keygen512 - generate a fresh crypto_box secret key over DSTU 9041's l(p)=512 curve.

Same shape as `box-keygen`, over DSTU 9041's l(p)=512 curve (E512/1) instead of l(p)=256. The
curve is chosen here, once, and recorded in the key: `box-pubkey`, `box-seal` and `box-open` read
it from there. Draws from the OS CSPRNG via rejection sampling and writes it to --out as a typed
key file.

USAGE:
    uacrypt box-keygen512 --out <path>

FLAGS:
    --out <path>    where to write the secret key

EXAMPLE:
    uacrypt box-keygen512 --out box512.key

Notes:
    - Keep this file secret - anyone who has it can decrypt messages sealed to it.
    - Derive the matching public key with `uacrypt box-pubkey`.
";

const KALYNA_BLOCK_HELP: &str = "\
uacrypt kalyna-block - encrypt or decrypt exactly one Kalyna block, no mode of operation.

Low-level: this is a single block-cipher call, not a file-encryption tool - it does not chain
multiple blocks or add padding. For encrypting a whole file, use `encrypt`/`decrypt` instead.

USAGE:
    uacrypt kalyna-block encrypt --variant <v> --key <path> --in <path> --out <path> [--force]
    uacrypt kalyna-block decrypt --variant <v> --key <path> --in <path> --out <path> [--force]

FLAGS:
    --variant <v>      one of 128-128, 128-256, 256-256, 256-512, 512-512 (block/key size in bits)
    --key <path>       key file - must be exactly the variant's key length
    --in <path>        input file - must be exactly one block (the variant's block length)
    --out <path>       where to write the one-block result
    --force            replace --out if it already exists (without it: refused)
    --iterations <n>   (benchmarking only) repeat the operation n times, print timing to stderr
    --raw-schedule     (benchmarking only) re-expand the key schedule on every iteration

EXAMPLE:
    uacrypt kalyna-block encrypt --variant 128-128 --key key.bin --in block.bin --out block.enc
";

const KALYNA_CCM_HELP: &str = "\
uacrypt kalyna-ccm - Kalyna-CCM authenticated encryption (DSTU 7624:2014 §13, docs/DECISIONS.md D-205).

Messages and AAD are capped at 255 bytes each (see hazmat::kalyna_ccm docs) - for larger files use
`encrypt`/`decrypt` instead, which have no such cap.

USAGE:
    uacrypt kalyna-ccm encrypt --variant <v> --key <path> --nonce <path> --in <path> --out <path> --tag <path> [--aad <path>] [--force]
    uacrypt kalyna-ccm decrypt --variant <v> --key <path> --nonce <path> --in <path> --out <path> --tag <path> [--aad <path>] [--force]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --nonce <path>   encrypt: OUTPUT, a fresh random nonce is generated and written here.
                     decrypt: INPUT, must be the nonce file `encrypt` produced.
    --aad <path>     optional - additional authenticated data (not encrypted, but tamper-checked)
    --in <path>      plaintext (encrypt) or ciphertext (decrypt), 1 to 255 bytes
    --out <path>     ciphertext (encrypt) or plaintext (decrypt)
    --tag <path>     encrypt: OUTPUT auth tag. decrypt: INPUT, must be encrypt's tag.
    --force          replace existing output files instead of refusing
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-ccm encrypt --variant 128-256 --key key.bin --nonce nonce.bin --in msg.bin \\
        --out msg.enc --tag tag.bin
";

const KALYNA_GCM_HELP: &str = "\
uacrypt kalyna-gcm - Kalyna-GCM authenticated encryption (DSTU 7624:2014 §12, docs/DECISIONS.md D-204).

Benchmarking/interop tool (docs/DECISIONS.md D-31/D-71), same shape as `kalyna-ccm` but with no
message-length cap - for everyday use, `encrypt`/`decrypt` (crypto_secretstream) are simpler and
already stream to disk.

WARNING:
    The output is a raw ciphertext file plus separate nonce/tag files, with no container and no
    format version, and the tag does not cover the nonce (docs/DECISIONS.md D-63). An empty --in
    with no --aad is rejected (D-207). For files, use `encrypt` or `box-seal`.

USAGE:
    uacrypt kalyna-gcm encrypt --variant <v> --key <path> --nonce <path> --in <path> --out <path> --tag <path> [--aad <path>] [--iterations <n>] [--force]
    uacrypt kalyna-gcm decrypt --variant <v> --key <path> --nonce <path> --in <path> --out <path> --tag <path> [--aad <path>] [--iterations <n>] [--force]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --nonce <path>   encrypt: OUTPUT, a fresh random nonce is generated and written here.
                     decrypt: INPUT, must be the nonce file `encrypt` produced.
    --aad <path>     optional - additional authenticated data (not encrypted, but tamper-checked)
    --in <path>      plaintext (encrypt) or ciphertext (decrypt), any length
    --out <path>     ciphertext (encrypt) or plaintext (decrypt)
    --tag <path>     encrypt: OUTPUT auth tag (full block length). decrypt: INPUT, must be encrypt's tag.
    --force          replace existing output files instead of refusing
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-gcm encrypt --variant 128-256 --key key.bin --nonce nonce.bin --in msg.bin \\
        --out msg.enc --tag tag.bin
";

const KALYNA_CMAC_HELP: &str = "\
uacrypt kalyna-cmac - Kalyna-CMAC message authentication, for benchmarking/interop (docs/DECISIONS.md D-31/D-71).

Computes or verifies a 16-byte tag over a message - no encryption. Do not reuse this key for any
encryption mode in this crate (see hazmat::kalyna_cmac docs for why).

USAGE:
    uacrypt kalyna-cmac compute --variant <v> --key <path> --in <path> --out <path> [--iterations <n>] [--force]
    uacrypt kalyna-cmac verify --variant <v> --key <path> --in <path> --tag <path> [--iterations <n>]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --in <path>      message to authenticate (must not be empty, D-206)
    --out <path>     compute: OUTPUT, where to write the 16-byte tag
    --tag <path>     verify: INPUT, the tag to check against
    --force          replace --out if it already exists (without it: refused)
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-cmac compute --variant 128-128 --key key.bin --in msg.bin --out tag.bin
";

const KALYNA_GMAC_HELP: &str = "\
uacrypt kalyna-gmac - Kalyna-GMAC message authentication, for benchmarking/interop (docs/DECISIONS.md D-31/D-71).

Computes or verifies a full-block-length tag over a message - no encryption, no nonce (unlike
kalyna-gcm, hazmat::kalyna_gmac takes none). Do not reuse this key for any encryption mode.

WARNING:
    A MAC proves only that someone holding the key produced the tag. An empty --in is rejected
    (docs/DECISIONS.md D-207). Use `sign` to prove who wrote a file.

USAGE:
    uacrypt kalyna-gmac compute --variant <v> --key <path> --in <path> --out <path> [--iterations <n>] [--force]
    uacrypt kalyna-gmac verify --variant <v> --key <path> --in <path> --tag <path> [--iterations <n>]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --in <path>      message to authenticate (must not be empty, D-206)
    --out <path>     compute: OUTPUT, where to write the tag (full block length)
    --tag <path>     verify: INPUT, the tag to check against
    --force          replace --out if it already exists (without it: refused)
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-gmac compute --variant 128-128 --key key.bin --in msg.bin --out tag.bin
";

const KALYNA_KW_HELP: &str = "\
uacrypt kalyna-kw - Kalyna key wrap/unwrap, for benchmarking/interop (docs/DECISIONS.md D-31/D-71).

Wraps block-aligned key material (1..=20 blocks) into a blob one block longer, with a checksum
block for tamper-evidence - not a general-purpose cipher, see hazmat::kalyna_kw docs.

USAGE:
    uacrypt kalyna-kw wrap --variant <v> --key <path> --in <path> --out <path> [--iterations <n>] [--force]
    uacrypt kalyna-kw unwrap --variant <v> --key <path> --in <path> --out <path> [--iterations <n>] [--force]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --in <path>      key material to wrap (block-aligned) or a wrapped blob to unwrap
    --out <path>     wrapped blob (wrap) or recovered key material (unwrap)
    --force          replace --out if it already exists (without it: refused)
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-kw wrap --variant 128-128 --key kek.bin --in key-to-wrap.bin --out wrapped.bin
";

const KALYNA_XTS_HELP: &str = "\
uacrypt kalyna-xts - Kalyna-XTS disk-sector mode, for benchmarking/interop (docs/DECISIONS.md D-31/D-71).

Confidentiality only, no tag - the correct design for disk-sector encryption, not a gap (see
hazmat::kalyna_xts docs). --in must be at least one block long.

USAGE:
    uacrypt kalyna-xts encrypt --variant <v> --key <path> --tweak <path> --in <path> --out <path> [--iterations <n>] [--force]
    uacrypt kalyna-xts decrypt --variant <v> --key <path> --tweak <path> --in <path> --out <path> [--iterations <n>] [--force]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --tweak <path>   one block's worth of bytes - the data-unit tweak seed (e.g. a sector index
                     encoded into a block-length buffer by the caller; this CLI does not derive one)
    --in <path>      plaintext (encrypt) or ciphertext (decrypt), at least one block
    --out <path>     ciphertext (encrypt) or plaintext (decrypt)
    --force          replace --out if it already exists (without it: refused)
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-xts encrypt --variant 128-128 --key key.bin --tweak tweak.bin --in sector.bin \\
        --out sector.enc
";

const KUPYNA_DIGEST_HELP: &str = "\
uacrypt kupyna-digest - Kupyna hash with a selectable variant, for benchmarking/interop.

For everyday hashing, `hash` is simpler (fixed to Kupyna-256, no --variant flag needed).

USAGE:
    uacrypt kupyna-digest --variant <v> --in <path> --out <path> [--iterations <n>] [--force]

FLAGS:
    --variant <v>      256 or 512
    --in <path>        file to hash
    --out <path>       where to write the digest
    --force            replace --out if it already exists (without it: refused)
    --iterations <n>   (benchmarking only) re-hash n times, print timing/MB-per-s to stderr

EXAMPLE:
    uacrypt kupyna-digest --variant 512 --in report.pdf --out report.pdf.kupyna512
";

const STRUMOK_CRYPT_HELP: &str = "\
uacrypt strumok-crypt - Strumok keystream cipher (XOR-based), for benchmarking/interop.

WARNING: NOT authenticated. A tampered output file decrypts silently into wrong plaintext instead
of an error - there is no tag to detect it. For a file cipher that detects tampering, use
`encrypt`/`decrypt` instead. Also never reuse the same --key/--iv pair for two different messages -
doing so lets an attacker recover both messages by XORing the two ciphertexts together.

USAGE:
    uacrypt strumok-crypt --variant <v> --key <path> --iv <path> --in <path> --out <path> \\
        [--iterations <n>] [--raw-schedule] [--force]

FLAGS:
    --variant <v>      256 or 512 (key size in bits; IV is always 32 bytes)
    --key <path>       key file - must be exactly the variant's key length
    --iv <path>        IV file - must be exactly 32 bytes
    --in <path>        file to encrypt or decrypt (same operation either way - XOR keystream)
    --out <path>       where to write the result
    --force            replace --out if it already exists (without it: refused)
    --iterations <n>   (benchmarking only) repeat n times, print timing/MB-per-s to stderr
    --raw-schedule     (benchmarking only) re-initialize the cipher fresh on every iteration

EXAMPLE:
    uacrypt strumok-crypt --variant 256 --key key.bin --iv iv.bin --in msg.bin --out msg.enc
";

/// Every top-level command with its `--help` text - the one table typo suggestions,
/// `uacrypt help <command>` and (later) shell completions read, so they cannot drift apart. A unit
/// test checks it against [`run`]'s own dispatch arms.
const COMMANDS: &[(&str, &str)] = &[
    ("keygen", KEYGEN_HELP),
    ("encrypt", ENCRYPT_HELP),
    ("decrypt", DECRYPT_HELP),
    ("hash", HASH_HELP),
    ("sign-keygen", SIGN_KEYGEN_HELP),
    ("sign-pubkey", SIGN_PUBKEY_HELP),
    ("sign", SIGN_HELP),
    ("verify", VERIFY_HELP),
    ("sign-keygen257", SIGN_KEYGEN257_HELP),
    ("box-keygen", BOX_KEYGEN_HELP),
    ("box-pubkey", BOX_PUBKEY_HELP),
    ("box-seal", BOX_SEAL_HELP),
    ("box-open", BOX_OPEN_HELP),
    ("box-keygen512", BOX_KEYGEN512_HELP),
    ("key-import", KEY_IMPORT_HELP),
    ("kalyna-block", KALYNA_BLOCK_HELP),
    ("kalyna-ccm", KALYNA_CCM_HELP),
    ("kalyna-gcm", KALYNA_GCM_HELP),
    ("kalyna-cmac", KALYNA_CMAC_HELP),
    ("kalyna-gmac", KALYNA_GMAC_HELP),
    ("kalyna-kw", KALYNA_KW_HELP),
    ("kalyna-xts", KALYNA_XTS_HELP),
    ("kupyna-digest", KUPYNA_DIGEST_HELP),
    ("strumok-crypt", STRUMOK_CRYPT_HELP),
];

fn command_help(command: &str) -> Option<&'static str> {
    COMMANDS
        .iter()
        .find(|(name, _)| *name == command)
        .map(|(_, help)| *help)
}

/// The curve twins T-257 removed, each with the command that replaces it (D-213). Kept out of
/// [`COMMANDS`] so help, suggestions and completions never offer them.
const REMOVED_COMMANDS: &[(&str, &str)] = &[
    ("sign-pubkey257", "sign-pubkey"),
    ("sign257", "sign"),
    ("box-pubkey512", "box-pubkey"),
    ("box-seal512", "box-seal"),
    ("box-open512", "box-open"),
];

fn unknown_command(command: &str) -> CliError {
    if let Some(&(_, replacement)) = REMOVED_COMMANDS.iter().find(|(old, _)| *old == command) {
        return CliError::RemovedCommand {
            command: command.to_string(),
            replacement,
        };
    }
    let names = COMMANDS.iter().map(|(name, _)| *name).chain(["help"]);
    CliError::UnknownCommand {
        command: command.to_string(),
        suggestion: suggest(command, names),
    }
}

/// `cmd other` where `other` is not one of `cmd`'s subcommands; the suggestion is the bare
/// subcommand.
fn unknown_subcommand(cmd: &str, other: &str, choices: &[&'static str]) -> CliError {
    CliError::UnknownCommand {
        command: format!("{cmd} {other}"),
        suggestion: suggest(other, choices.iter().copied()),
    }
}

/// Prints one command's `--help` text to stdout, or [`TOP_LEVEL_HELP`] for anything not in
/// [`COMMANDS`] (including `""`).
fn print_command_help(command: &str) {
    println!("{}", command_help(command).unwrap_or(TOP_LEVEL_HELP));
}

/// `uacrypt help [command]`: no argument prints the top-level help, a known command its own help;
/// anything else is a usage error.
fn run_help_command(rest: &[String]) -> Result<(), CliError> {
    match rest {
        [] => {
            print_command_help("");
            Ok(())
        }
        [cmd] if is_help_flag(cmd) || cmd == "help" => {
            print_command_help("");
            Ok(())
        }
        [cmd] => match command_help(cmd) {
            Some(text) => {
                println!("{text}");
                Ok(())
            }
            None => Err(unknown_command(cmd)),
        },
        [_, extra, ..] => Err(CliError::UnexpectedArgument(extra.clone())),
    }
}

/// Dispatches `sign-keygen`/`sign-keygen257`/`sign-pubkey`/`sign`/`verify` - split out of [`run`] for
/// the same `clippy::pedantic` line-count reason as [`dispatch_kalyna_mode`] (`docs/DECISIONS.md`
/// D-71's precedent, `docs/TASKS.md` T-124); `cmd` is always one of the five literals [`run`]'s own match arm
/// already narrowed it to. `rest` excludes both the program name and `cmd` itself.
/// Shared "check `--help` once, then parse-and-run" shape every single-purpose command
/// (`kupyna-digest`/`strumok-crypt`/`hash`/`keygen`/`encrypt`/`decrypt`) repeated inline in
/// [`run`] - extracted purely to bring that function's own Cognitive Complexity back under
/// `SonarCloud`'s threshold (`docs/TASKS.md` T-140, `docs/DECISIONS.md` D-94), the same "split out of `run`
/// to satisfy a lint on that one function" precedent [`dispatch_kalyna_mode`]/
/// [`dispatch_sign_command`] already established for `D-71`'s line-count lint. `cmd` is only used
/// for the help text; `parse`/`run` are each command's own existing `parse_*_args`/
/// `run_*_command` pair (or a closure over it, for the two `crypto_secretstream` directions that
/// need a fixed leading `bool`), unchanged.
fn dispatch_simple<T>(
    cmd: &str,
    rest: &[String],
    parse: impl FnOnce(&[String]) -> Result<T, CliError>,
    run: impl FnOnce(&T) -> Result<(), CliError>,
) -> Result<(), CliError> {
    if rest.iter().any(|a| is_help_flag(a)) {
        print_command_help(cmd);
        return Ok(());
    }
    run(&parse(rest)?)
}

fn dispatch_sign_command(cmd: &str, rest: &[String]) -> Result<(), CliError> {
    if rest.iter().any(|a| is_help_flag(a)) {
        print_command_help(cmd);
        return Ok(());
    }
    match cmd {
        "sign-keygen" => run_sign_keygen_command(&parse_sign_keygen_args(rest)?),
        "sign-keygen257" => run_sign_keygen257_command(&parse_sign_keygen_args(rest)?),
        "sign-pubkey" => run_sign_pubkey_command(&parse_sign_pubkey_args(rest)?),
        "sign" => run_sign_command(&parse_sign_args(rest)?),
        _ => run_verify_command(&parse_verify_args(rest)?),
    }
}

/// Dispatches `box-keygen`/`box-keygen512`/`box-pubkey`/`box-seal`/`box-open` - same D-71
/// line-count-lint reason as [`dispatch_sign_command`]; `cmd` is always one of the five literals [`run`]'s own match arm
/// already narrowed it to. `rest` excludes both the program name and `cmd` itself.
fn dispatch_box_command(cmd: &str, rest: &[String]) -> Result<(), CliError> {
    if rest.iter().any(|a| is_help_flag(a)) {
        print_command_help(cmd);
        return Ok(());
    }
    match cmd {
        "box-keygen" => run_box_keygen_command(&parse_box_keygen_args(rest)?),
        "box-keygen512" => run_box512_keygen_command(&parse_box_keygen_args(rest)?),
        "box-pubkey" => run_box_pubkey_command(&parse_box_pubkey_args(rest)?),
        "box-seal" => run_box_seal_command(&parse_box_seal_args(rest)?),
        _ => run_box_open_command(&parse_box_open_args(rest)?),
    }
}

/// Dispatches `kalyna-gcm`/`kalyna-cmac`/`kalyna-gmac`/`kalyna-kw`/`kalyna-xts` - split out of
/// [`run`] purely to keep that function under `clippy::pedantic`'s line-count lint (`docs/DECISIONS.md`
/// D-71); `cmd` is always one of the five literals [`run`]'s own match arm already narrowed it to.
/// `rest` excludes both the program name and `cmd` itself.
fn dispatch_kalyna_mode(cmd: &str, rest: &[String]) -> Result<(), CliError> {
    if rest.iter().any(|a| is_help_flag(a)) {
        print_command_help(cmd);
        return Ok(());
    }
    let sub = rest.first().map(String::as_str);
    match cmd {
        "kalyna-gcm" => match sub {
            Some("encrypt") => run_gcm_command(false, &parse_gcm_args(&rest[1..])?),
            Some("decrypt") => run_gcm_command(true, &parse_gcm_args(&rest[1..])?),
            Some(other) => Err(unknown_subcommand(
                "kalyna-gcm",
                other,
                &["encrypt", "decrypt"],
            )),
            None => Err(CliError::MissingSubcommand("encrypt|decrypt")),
        },
        "kalyna-cmac" => match sub {
            Some("compute") => run_cmac_command(false, &parse_cmac_args(&rest[1..])?),
            Some("verify") => run_cmac_command(true, &parse_cmac_args(&rest[1..])?),
            Some(other) => Err(unknown_subcommand(
                "kalyna-cmac",
                other,
                &["compute", "verify"],
            )),
            None => Err(CliError::MissingSubcommand("compute|verify")),
        },
        "kalyna-gmac" => match sub {
            Some("compute") => run_gmac_command(false, &parse_gmac_args(&rest[1..])?),
            Some("verify") => run_gmac_command(true, &parse_gmac_args(&rest[1..])?),
            Some(other) => Err(unknown_subcommand(
                "kalyna-gmac",
                other,
                &["compute", "verify"],
            )),
            None => Err(CliError::MissingSubcommand("compute|verify")),
        },
        "kalyna-kw" => match sub {
            Some("wrap") => run_kw_command(false, &parse_kw_args(&rest[1..])?),
            Some("unwrap") => run_kw_command(true, &parse_kw_args(&rest[1..])?),
            Some(other) => Err(unknown_subcommand("kalyna-kw", other, &["wrap", "unwrap"])),
            None => Err(CliError::MissingSubcommand("wrap|unwrap")),
        },
        _ => match sub {
            Some("encrypt") => run_xts_command(false, &parse_xts_args(&rest[1..])?),
            Some("decrypt") => run_xts_command(true, &parse_xts_args(&rest[1..])?),
            Some(other) => Err(unknown_subcommand(
                "kalyna-xts",
                other,
                &["encrypt", "decrypt"],
            )),
            None => Err(CliError::MissingSubcommand("encrypt|decrypt")),
        },
    }
}

/// Top-level dispatch - `args` excludes the program name (`std::env::args().skip(1)`).
///
/// `uacrypt` with no arguments and `uacrypt --help`/`-h` both print [`TOP_LEVEL_HELP`] and return
/// `Ok(())` - a friendlier default than an error for a CLI's most common first invocation. Every
/// command also accepts `--help`/`-h` anywhere among its own arguments to print that command's own
/// help instead of running it (`docs/TASKS.md` T-108).
///
/// # Errors
///
/// Returns [`CliError::UnknownCommand`] for an unrecognized (sub)command, or whatever the
/// relevant `parse_*_args`/`run_*_command` returns for the matched one.
pub fn run(args: &[String]) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        None => {
            print_command_help("");
            Ok(())
        }
        Some(cmd) if is_help_flag(cmd) => {
            print_command_help("");
            Ok(())
        }
        Some(cmd) if is_version_flag(cmd) => {
            println!(
                "uacrypt {} (container format {CONTAINER_FORMAT_VERSION})",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some("kalyna-block") => {
            let rest = &args[1..];
            if rest.iter().any(|a| is_help_flag(a)) {
                print_command_help("kalyna-block");
                return Ok(());
            }
            match rest.first().map(String::as_str) {
                Some("encrypt") => run_block_command(false, &parse_block_args(&rest[1..])?),
                Some("decrypt") => run_block_command(true, &parse_block_args(&rest[1..])?),
                Some(other) => Err(unknown_subcommand(
                    "kalyna-block",
                    other,
                    &["encrypt", "decrypt"],
                )),
                None => Err(CliError::MissingSubcommand("encrypt|decrypt")),
            }
        }
        Some("kalyna-ccm") => {
            let rest = &args[1..];
            if rest.iter().any(|a| is_help_flag(a)) {
                print_command_help("kalyna-ccm");
                return Ok(());
            }
            match rest.first().map(String::as_str) {
                Some("encrypt") => run_ccm_command(false, &parse_ccm_args(&rest[1..])?),
                Some("decrypt") => run_ccm_command(true, &parse_ccm_args(&rest[1..])?),
                Some(other) => Err(unknown_subcommand(
                    "kalyna-ccm",
                    other,
                    &["encrypt", "decrypt"],
                )),
                None => Err(CliError::MissingSubcommand("encrypt|decrypt")),
            }
        }
        Some(cmd @ ("kalyna-gcm" | "kalyna-cmac" | "kalyna-gmac" | "kalyna-kw" | "kalyna-xts")) => {
            dispatch_kalyna_mode(cmd, &args[1..])
        }
        Some("kupyna-digest") => dispatch_simple(
            "kupyna-digest",
            &args[1..],
            parse_digest_args,
            run_digest_command,
        ),
        Some("strumok-crypt") => dispatch_simple(
            "strumok-crypt",
            &args[1..],
            parse_strumok_args,
            run_strumok_command,
        ),
        Some("hash") => dispatch_simple("hash", &args[1..], parse_hash_args, run_hash_command),
        Some("keygen") => {
            dispatch_simple("keygen", &args[1..], parse_keygen_args, run_keygen_command)
        }
        Some("encrypt") => dispatch_simple("encrypt", &args[1..], parse_secretstream_args, |a| {
            run_secretstream_command(false, a)
        }),
        Some("decrypt") => dispatch_simple("decrypt", &args[1..], parse_secretstream_args, |a| {
            run_secretstream_command(true, a)
        }),
        Some(cmd @ ("sign-keygen" | "sign-keygen257" | "sign-pubkey" | "sign" | "verify")) => {
            dispatch_sign_command(cmd, &args[1..])
        }
        Some(cmd @ ("box-keygen" | "box-keygen512" | "box-pubkey" | "box-seal" | "box-open")) => {
            dispatch_box_command(cmd, &args[1..])
        }
        Some("key-import") => dispatch_simple(
            "key-import",
            &args[1..],
            parse_key_import_args,
            run_key_import_command,
        ),
        Some("help") => run_help_command(&args[1..]),
        Some(other) => Err(unknown_command(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dstu_core::hazmat::kupyna::{Kupyna256, Kupyna512};

    #[test]
    fn variant_parse_roundtrips_known_names() {
        assert_eq!(
            KalynaVariant::parse("128-128"),
            Some(KalynaVariant::K128_128)
        );
        assert_eq!(
            KalynaVariant::parse("512-512"),
            Some(KalynaVariant::K512_512)
        );
        assert_eq!(KalynaVariant::parse("nonsense"), None);
    }

    #[test]
    fn variant_lengths_match_dstu_core() {
        assert_eq!(KalynaVariant::K128_128.key_len(), 16);
        assert_eq!(KalynaVariant::K128_128.block_len(), 16);
        assert_eq!(KalynaVariant::K128_256.key_len(), 32);
        assert_eq!(KalynaVariant::K128_256.block_len(), 16);
        assert_eq!(KalynaVariant::K256_512.key_len(), 64);
        assert_eq!(KalynaVariant::K256_512.block_len(), 32);
        assert_eq!(KalynaVariant::K512_512.key_len(), 64);
        assert_eq!(KalynaVariant::K512_512.block_len(), 64);
    }

    #[test]
    fn parse_block_args_requires_all_of_variant_key_in_out() {
        let args = vec!["--variant".to_string(), "128-128".to_string()];
        assert_eq!(parse_block_args(&args), Err(CliError::MissingFlag("key")));
    }

    #[test]
    fn parse_block_args_rejects_unknown_variant() {
        let args = vec![
            "--variant".to_string(),
            "999-999".to_string(),
            "--key".to_string(),
            "k".to_string(),
            "--in".to_string(),
            "i".to_string(),
            "--out".to_string(),
            "o".to_string(),
        ];
        assert_eq!(
            parse_block_args(&args),
            Err(CliError::UnknownVariant("999-999".to_string()))
        );
    }

    #[test]
    fn parse_block_args_happy_path() {
        let args = vec![
            "--variant".to_string(),
            "256-256".to_string(),
            "--key".to_string(),
            "key.bin".to_string(),
            "--in".to_string(),
            "in.bin".to_string(),
            "--out".to_string(),
            "out.bin".to_string(),
            "--iterations".to_string(),
            "1000".to_string(),
            "--raw-schedule".to_string(),
        ];
        let parsed = parse_block_args(&args).expect("valid args should parse");
        assert_eq!(parsed.variant, KalynaVariant::K256_256);
        assert_eq!(parsed.key_path, PathBuf::from("key.bin"));
        assert_eq!(parsed.in_path, PathBuf::from("in.bin"));
        assert_eq!(parsed.out_path, PathBuf::from("out.bin"));
        assert_eq!(parsed.iterations, 1000);
        assert!(parsed.raw_schedule);
    }

    #[test]
    fn run_block_op_encrypt_matches_dstu_core_directly() {
        let key = [0x11u8; 16];
        let block = [0x22u8; 16];
        let expected = Kalyna128_128::encrypt(&key, &block);

        let (out_cached, _) = run_block_op(KalynaVariant::K128_128, &key, &block, false, 1, false);
        assert_eq!(out_cached, expected.to_vec());

        let (out_raw, _) = run_block_op(KalynaVariant::K128_128, &key, &block, false, 1, true);
        assert_eq!(out_raw, expected.to_vec());
    }

    #[test]
    fn run_block_op_decrypt_matches_dstu_core_directly() {
        let key = [0x33u8; 64];
        let block = [0x44u8; 64];
        let ciphertext = Kalyna512_512::encrypt(&key, &block);
        let expected = Kalyna512_512::decrypt(&key, &ciphertext);

        let (out_cached, _) =
            run_block_op(KalynaVariant::K512_512, &key, &ciphertext, true, 1, false);
        assert_eq!(out_cached, expected.to_vec());

        let (out_raw, _) = run_block_op(KalynaVariant::K512_512, &key, &ciphertext, true, 1, true);
        assert_eq!(out_raw, expected.to_vec());
    }

    #[test]
    fn run_block_op_repeated_iterations_give_same_final_result_as_one() {
        let key = [0x55u8; 32];
        let block = [0x66u8; 32];

        let (out_one, _) = run_block_op(KalynaVariant::K256_256, &key, &block, false, 1, false);
        let (out_many, _) = run_block_op(KalynaVariant::K256_256, &key, &block, false, 50, false);
        assert_eq!(out_one, out_many);
    }

    /// A per-test scratch directory under the OS temp dir, cleaned up on drop - avoids collisions
    /// between tests running in parallel.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("uacrypt_test_{label}_{}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir for test");
            Self(path)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A small, obviously-valid signing-key candidate (`n`'s top byte is `0x04` - see
    /// `dstu_core::hazmat::dstu4145::curve163::order`) for `sign`/`verify` tests that just need
    /// *some* valid key, distinguished only by its low byte - same convention as
    /// `dstu-core`'s own `tests/crypto_sign.rs::small_scalar`.
    fn write_typed_key(path: &std::path::Path, kind: KeyKind, raw: &[u8]) {
        std::fs::write(path, keyfile::encode(kind, raw).as_slice()).expect("write typed key");
    }

    fn small_signing_key(low_byte: u8) -> [u8; 21] {
        let mut out = [0u8; 21];
        out[20] = low_byte;
        out
    }

    #[test]
    fn hash_bits_parse_roundtrips_known_names() {
        assert_eq!(HashBits::parse("256"), Some(HashBits::B256));
        assert_eq!(HashBits::parse("512"), Some(HashBits::B512));
        assert_eq!(HashBits::parse("1024"), None);
    }

    #[test]
    fn parse_digest_args_happy_path() {
        let args = vec![
            "--variant".to_string(),
            "512".to_string(),
            "--in".to_string(),
            "msg.bin".to_string(),
            "--out".to_string(),
            "digest.bin".to_string(),
            "--iterations".to_string(),
            "42".to_string(),
        ];
        let parsed = parse_digest_args(&args).expect("valid args should parse");
        assert_eq!(parsed.variant, HashBits::B512);
        assert_eq!(parsed.in_path, PathBuf::from("msg.bin"));
        assert_eq!(parsed.out_path, PathBuf::from("digest.bin"));
        assert_eq!(parsed.iterations, 42);
    }

    #[test]
    fn run_digest_command_matches_dstu_core_directly() {
        let dir = TempDir::new("digest");
        let message = b"the quick brown fox";
        std::fs::write(dir.file("msg.bin"), message).expect("write message");

        let args = DigestArgs {
            variant: HashBits::B256,
            in_path: dir.file("msg.bin"),
            out_path: dir.file("digest.bin"),
            iterations: 1,
            force: false,
        };
        run_digest_command(&args).expect("digest command should succeed");

        let written = std::fs::read(dir.file("digest.bin")).expect("read digest output");
        assert_eq!(written, Kupyna256::digest(message).to_vec());
    }

    #[test]
    fn run_digest_command_repeated_iterations_give_same_result_as_one() {
        let dir = TempDir::new("digest_iter");
        std::fs::write(dir.file("msg.bin"), b"repeat me").expect("write message");

        let args_one = DigestArgs {
            variant: HashBits::B512,
            in_path: dir.file("msg.bin"),
            out_path: dir.file("digest_one.bin"),
            iterations: 1,
            force: false,
        };
        run_digest_command(&args_one).expect("first run should succeed");
        let args_many = DigestArgs {
            iterations: 25,
            out_path: dir.file("digest_many.bin"),
            ..args_one
        };
        run_digest_command(&args_many).expect("second run should succeed");

        assert_eq!(
            std::fs::read(dir.file("digest_one.bin")).expect("read"),
            std::fs::read(dir.file("digest_many.bin")).expect("read"),
        );
    }

    /// `run_digest_command` streams `--in` from disk in fixed-size chunks rather than reading it
    /// whole (T-83 follow-up) - every test above uses a message far smaller than one chunk, which
    /// never exercises the multi-chunk read loop. This uses a message several chunk-widths long,
    /// deliberately not a multiple of the chunk size, and checks both the single-pass streaming
    /// path (`iterations <= 1`) and the benchmark path (`iterations > 1`, which chunks an
    /// already-resident buffer instead of re-reading the file) against `hazmat::kupyna` directly.
    #[test]
    fn run_digest_command_streams_multi_chunk_input_correctly() {
        let dir = TempDir::new("digest_multichunk");
        let len = DIGEST_STREAM_CHUNK_BYTES * 3 + 777;
        let message: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
        std::fs::write(dir.file("msg.bin"), &message).expect("write message");

        let single_pass_args = DigestArgs {
            variant: HashBits::B512,
            in_path: dir.file("msg.bin"),
            out_path: dir.file("digest_single.bin"),
            iterations: 1,
            force: false,
        };
        run_digest_command(&single_pass_args).expect("single-pass run should succeed");
        assert_eq!(
            std::fs::read(dir.file("digest_single.bin")).expect("read"),
            Kupyna512::digest(&message).to_vec()
        );

        let bench_args = DigestArgs {
            iterations: 3,
            out_path: dir.file("digest_bench.bin"),
            ..single_pass_args
        };
        run_digest_command(&bench_args).expect("benchmark-path run should succeed");
        assert_eq!(
            std::fs::read(dir.file("digest_bench.bin")).expect("read"),
            Kupyna512::digest(&message).to_vec()
        );
    }

    #[test]
    fn parse_hash_args_happy_path() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_hash_args(&args(&["--in", "msg.bin"])),
            Ok(HashArgs::File(PathBuf::from("msg.bin")))
        );
        assert_eq!(
            parse_hash_args(&args(&["--check=SUMS"])),
            Ok(HashArgs::Check(PathBuf::from("SUMS")))
        );
    }

    #[test]
    fn parse_hash_args_requires_exactly_one_of_in_and_check() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_hash_args(&[]),
            Err(CliError::MissingOneOf("in", "check"))
        );
        assert_eq!(
            parse_hash_args(&args(&["--in", "a", "--check", "b"])),
            Err(CliError::ExclusiveFlags("in", "check"))
        );
        assert_eq!(
            parse_hash_args(&args(&["--in", "a", "--out", "b"])),
            Err(CliError::UnknownFlag {
                flag: "--out".to_string(),
                suggestion: None,
            })
        );
    }

    fn check_line(digest: &[u8], path: &str) -> String {
        format!("{}  {path}", hex_lower(digest))
    }

    #[test]
    fn parse_check_list_accepts_the_hash_output_format() {
        let a = Kupyna256::digest(b"a");
        let b = Kupyna256::digest(b"b");
        let text = format!("{}\n{}\n", check_line(&a, "x"), check_line(&b, "dir/y z"));
        assert_eq!(
            parse_check_list(text.as_bytes()),
            Ok(vec![
                CheckEntry {
                    digest: a,
                    path: "x".to_string()
                },
                CheckEntry {
                    digest: b,
                    path: "dir/y z".to_string()
                },
            ])
        );
        let crlf_upper = format!(
            "{}\r\n",
            check_line(&a, "x").to_uppercase().replace("  X", "  x")
        );
        assert_eq!(
            parse_check_list(crlf_upper.as_bytes()).map(|v| v.len()),
            Ok(1)
        );
        assert_eq!(
            parse_check_list(check_line(&a, "x").as_bytes()).map(|v| v.len()),
            Ok(1)
        );
    }

    #[test]
    fn parse_check_list_rejects_everything_else_with_the_line_number() {
        let good = check_line(&Kupyna256::digest(b"a"), "x");
        let hex = &good[..64];
        assert_eq!(parse_check_list(b""), Err(CheckListError::Empty));
        let mut utf8_bom = b"\xef\xbb\xbf".to_vec();
        utf8_bom.extend_from_slice(good.as_bytes());
        assert_eq!(parse_check_list(&utf8_bom).map(|v| v.len()), Ok(1));
        let utf16le: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain(good.bytes().flat_map(|b| [b, 0]))
            .collect();
        assert_eq!(parse_check_list(&utf16le), Err(CheckListError::Utf16));
        assert_eq!(
            parse_check_list(b"\xfe\xff\x00a"),
            Err(CheckListError::Utf16)
        );
        assert_eq!(parse_check_list(b"\n"), Err(CheckListError::Empty));
        for bad in [
            String::new(),
            format!("{hex} x"),
            format!("{hex} *x"),
            format!("{hex}  "),
            format!("{}  x", &hex[..63]),
            format!("{hex}0  x"),
            format!("{}g  x", &hex[..63]),
            format!("{hex}  x\ty"),
            format!("{hex}  x\u{7f}"),
            format!("{hex}  x\u{9b}"),
            format!("{hex}  x\r\r"),
        ] {
            let text = format!("{good}\n{bad}\n{good}\n");
            assert_eq!(
                parse_check_list(text.as_bytes()),
                Err(CheckListError::Malformed(2)),
                "{bad:?}"
            );
        }
        let mut not_utf8 = format!("{hex}  x").into_bytes();
        not_utf8.push(0xff);
        assert_eq!(
            parse_check_list(&not_utf8),
            Err(CheckListError::Malformed(1))
        );
    }

    #[test]
    fn parse_hash_args_rejects_unknown_flag() {
        assert_eq!(
            parse_hash_args(&["--variant".to_string(), "256".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--variant".to_string(),
                suggestion: None,
            })
        );
    }

    #[test]
    fn parse_keygen_args_happy_path() {
        let args = vec!["--out".to_string(), "key.bin".to_string()];
        assert_eq!(
            parse_keygen_args(&args),
            Ok(KeygenArgs {
                out_path: PathBuf::from("key.bin"),
            })
        );
    }

    #[test]
    fn parse_keygen_args_requires_out() {
        assert_eq!(parse_keygen_args(&[]), Err(CliError::MissingFlag("out")));
    }

    #[test]
    fn parse_keygen_args_rejects_unknown_flag() {
        assert_eq!(
            parse_keygen_args(&["--variant".to_string(), "256".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--variant".to_string(),
                suggestion: None,
            })
        );
    }

    /// Returns one byte per `read`, as a pipe or a slow device may.
    struct Trickle<'a>(&'a [u8]);

    impl std::io::Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.0[0];
            self.0 = &self.0[1..];
            Ok(1)
        }
    }

    /// D-208: short reads must not produce short non-`Final` records.
    #[test]
    fn short_reads_still_produce_full_non_final_records() {
        let key = dstu_core::crypto_secretstream::Key::from_bytes([7; 32]);
        let plaintext = vec![0xab; 2 * SECRETSTREAM_CHUNK_BYTES + 3];
        let mut file = Vec::new();
        write_secretstream_file(
            &key,
            &mut Trickle(&plaintext),
            std::path::Path::new("in"),
            &mut file,
            std::path::Path::new("out"),
        )
        .expect("encrypt");

        assert_eq!(file[0], dstu_core::crypto_secretstream::FORMAT_VERSION);
        let mut pos = 1 + SECRETSTREAM_HEADER_LEN;
        let mut lengths = Vec::new();
        while pos < file.len() {
            let len = u32::from_le_bytes(file[pos + 1..pos + 5].try_into().unwrap()) as usize;
            lengths.push((file[pos], len));
            pos += 5 + len + SECRETSTREAM_TAG_LEN;
        }
        assert_eq!(
            lengths,
            [
                (0x00, SECRETSTREAM_CHUNK_BYTES),
                (0x00, SECRETSTREAM_CHUNK_BYTES),
                (0x03, 3)
            ]
        );
    }

    #[test]
    fn run_keygen_command_writes_a_typed_key_usable_by_encrypt() {
        let dir = TempDir::new("keygen");
        let args = KeygenArgs {
            out_path: dir.file("key.bin"),
        };
        run_keygen_command(&args).expect("keygen should succeed");

        let key_text = std::fs::read(dir.file("key.bin")).expect("read generated key");
        let (kind, key_bytes) = keyfile::decode(&key_text).expect("a typed key line");
        assert_eq!((kind, key_bytes.len()), (KeyKind::Symmetric, 32));

        // The generated key is a real, usable crypto_secretstream key, not just 32 arbitrary
        // bytes - round-trip it through encrypt/decrypt to prove it, rather than only checking
        // the length.
        std::fs::write(dir.file("msg.bin"), b"keygen output must actually work").expect("write");
        let enc_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.enc"),
            force: false,
        };
        run_secretstream_command(false, &enc_args).expect("encrypt with generated key");
        let dec_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("msg.enc"),
            out_path: dir.file("msg.dec"),
            force: false,
        };
        run_secretstream_command(true, &dec_args).expect("decrypt with generated key");
        assert_eq!(
            std::fs::read(dir.file("msg.dec")).expect("read decrypted"),
            b"keygen output must actually work"
        );
    }

    #[test]
    fn run_keygen_command_produces_distinct_keys_each_call() {
        let dir = TempDir::new("keygen_distinct");
        run_keygen_command(&KeygenArgs {
            out_path: dir.file("key1.bin"),
        })
        .expect("first keygen should succeed");
        run_keygen_command(&KeygenArgs {
            out_path: dir.file("key2.bin"),
        })
        .expect("second keygen should succeed");

        let key1 = std::fs::read(dir.file("key1.bin")).expect("read key1");
        let key2 = std::fs::read(dir.file("key2.bin")).expect("read key2");
        assert_ne!(key1, key2, "two keygen calls must not produce the same key");
    }

    /// "Fool" test - pointing `--out` at a directory (an easy copy-paste mistake) must be a clean
    /// error, not a panic, same convention as `run_secretstream_command`'s directory tests. Which
    /// error is OS-specific: on Unix `O_CREAT | O_EXCL` on an existing directory is `EEXIST`, so
    /// T-241's refusal (`KeyFileExists`) fires; Windows reports access denied (`Io`). Found by the
    /// first Unix run of these tests (Pi, 2026-09-24).
    #[test]
    fn run_keygen_command_directory_as_out_is_io_error_not_panic() {
        let dir = TempDir::new("keygen_dir_out");
        std::fs::create_dir_all(dir.file("a_directory")).expect("create sub-directory");

        let args = KeygenArgs {
            out_path: dir.file("a_directory"),
        };
        let result = run_keygen_command(&args);
        #[cfg(unix)]
        assert!(matches!(result, Err(CliError::KeyFileExists(_))));
        #[cfg(not(unix))]
        assert!(matches!(result, Err(CliError::Io { .. })));
    }

    #[test]
    fn run_keygen_dispatches_through_top_level_run() {
        let dir = TempDir::new("keygen_dispatch");
        let args: Vec<String> = [
            "keygen",
            "--out",
            dir.file("key.bin").to_str().expect("valid utf-8 path"),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&args).expect("keygen dispatch should succeed");
        let key_text = std::fs::read(dir.file("key.bin")).expect("read");
        assert_eq!(
            keyfile::decode(&key_text).map(|(kind, _)| kind),
            Ok(KeyKind::Symmetric)
        );
    }

    /// Writes a one-line check file for `message` (stored at `msg.bin`) with `digest` listed.
    fn write_check_list(dir: &TempDir, message: &[u8], digest: &[u8]) -> PathBuf {
        std::fs::write(dir.file("msg.bin"), message).expect("write message");
        let path = dir.file("msg.bin");
        let line = check_line(digest, path.to_str().expect("valid utf-8 path"));
        std::fs::write(dir.file("SUMS"), format!("{line}\n")).expect("write check list");
        dir.file("SUMS")
    }

    /// `hash` is fixed to Kupyna-256 and must genuinely stream a multi-chunk, non-chunk-aligned
    /// message from disk: the check passes against `dstu-core`'s one-shot digest and fails against
    /// any other digest.
    #[test]
    fn run_hash_command_matches_dstu_core_kupyna256_directly() {
        let dir = TempDir::new("hash_multichunk");
        let len = SIGN_STREAM_CHUNK_BYTES * 2 + 513;
        let message: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(53)).collect();
        let list = write_check_list(&dir, &message, &Kupyna256::digest(&message));
        run_hash_command(&HashArgs::Check(list)).expect("the listed digest must match");

        let mut wrong = Kupyna256::digest(&message);
        wrong[31] ^= 1;
        let list = write_check_list(&dir, &message, &wrong);
        assert_eq!(
            run_hash_command(&HashArgs::Check(list)),
            Err(CliError::HashCheckFailed {
                failed: 1,
                total: 1
            })
        );
    }

    #[test]
    fn run_dispatches_hash_command_correctly() {
        let dir = TempDir::new("hash_dispatch");
        let list = write_check_list(&dir, b"dispatch me", &Kupyna256::digest(b"dispatch me"));
        let list = list.to_str().expect("valid utf-8 path");
        let args: Vec<String> = ["hash", "--check", list]
            .into_iter()
            .map(String::from)
            .collect();
        run(&args).expect("hash dispatch should succeed");
    }

    #[test]
    fn parse_ccm_args_requires_nonce_and_tag() {
        let args = vec![
            "--variant".to_string(),
            "128-128".to_string(),
            "--key".to_string(),
            "k".to_string(),
        ];
        assert_eq!(parse_ccm_args(&args), Err(CliError::MissingFlag("nonce")));
    }

    #[test]
    fn parse_ccm_args_happy_path_with_optional_aad() {
        let args = vec![
            "--variant".to_string(),
            "256-256".to_string(),
            "--key".to_string(),
            "key.bin".to_string(),
            "--nonce".to_string(),
            "nonce.bin".to_string(),
            "--aad".to_string(),
            "aad.bin".to_string(),
            "--in".to_string(),
            "in.bin".to_string(),
            "--out".to_string(),
            "out.bin".to_string(),
            "--tag".to_string(),
            "tag.bin".to_string(),
        ];
        let parsed = parse_ccm_args(&args).expect("valid args should parse");
        assert_eq!(parsed.variant, KalynaVariant::K256_256);
        assert_eq!(parsed.aad_path, Some(PathBuf::from("aad.bin")));
        assert_eq!(parsed.tag_path, PathBuf::from("tag.bin"));
    }

    #[test]
    fn parse_ccm_args_aad_defaults_to_none() {
        let args = vec![
            "--variant".to_string(),
            "128-128".to_string(),
            "--key".to_string(),
            "key.bin".to_string(),
            "--nonce".to_string(),
            "nonce.bin".to_string(),
            "--in".to_string(),
            "in.bin".to_string(),
            "--out".to_string(),
            "out.bin".to_string(),
            "--tag".to_string(),
            "tag.bin".to_string(),
        ];
        let parsed = parse_ccm_args(&args).expect("valid args should parse");
        assert_eq!(parsed.aad_path, None);
    }

    #[test]
    fn run_ccm_command_round_trip_matches_dstu_core_directly() {
        // Encrypt no longer takes `--nonce` as an input (T-82/D-40: the CLI generates a fresh
        // random nonce itself and writes it to `--nonce`, so there is nothing for a caller to
        // misconfigure) - so this can no longer compare against a fixed-nonce direct `hazmat`
        // call. It instead round-trips purely through the CLI and separately checks the nonce
        // file that came out was actually used (by re-deriving the tag/ciphertext from it).
        let dir = TempDir::new("kalyna_ccm");
        let key = [0x11u8; 16];
        let aad = b"header".to_vec();
        let plaintext = b"short message".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("aad.bin"), &aad).expect("write aad");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = CcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: Some(dir.file("aad.bin")),
            in_path: dir.file("in.bin"),
            out_path: dir.file("ct.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        run_ccm_command(false, &encrypt_args).expect("encrypt should succeed");

        let generated_nonce = std::fs::read(dir.file("nonce.bin")).expect("read generated nonce");
        assert_eq!(generated_nonce.len(), 16);

        let mut nonce_arr = [0u8; 16];
        nonce_arr.copy_from_slice(&generated_nonce);
        let expected_cipher = Kalyna128_128Ccm::new(&key);
        let mut expected_buf = plaintext.clone();
        let expected_tag = expected_cipher
            .seal_in_place(&nonce_arr, &aad, &mut expected_buf)
            .expect("direct seal with the generated nonce should succeed");
        assert_eq!(
            std::fs::read(dir.file("ct.bin")).expect("read"),
            expected_buf
        );
        assert_eq!(
            std::fs::read(dir.file("tag.bin")).expect("read"),
            expected_tag.to_vec()
        );

        let decrypt_args = CcmArgs {
            in_path: dir.file("ct.bin"),
            out_path: dir.file("pt.bin"),
            ..encrypt_args
        };
        run_ccm_command(true, &decrypt_args).expect("decrypt should succeed");
        assert_eq!(std::fs::read(dir.file("pt.bin")).expect("read"), plaintext);
    }

    /// "Fool" test (T-234/D-205): DSTU 7624:2014 §13.1 requires a non-empty plaintext, so an empty
    /// `--in` is rejected before anything is written.
    #[test]
    fn run_ccm_command_empty_input_is_rejected() {
        let dir = TempDir::new("kalyna_ccm_empty");
        std::fs::write(dir.file("key.bin"), [0x55u8; 16]).expect("write key");
        std::fs::write(dir.file("in.bin"), []).expect("write empty input");
        let args = CcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_ccm_command(false, &args),
            Err(CliError::EmptyInput("kalyna-ccm"))
        );
        assert!(!dir.file("out.bin").exists());
        assert!(!dir.file("tag.bin").exists());
    }

    #[test]
    fn run_ccm_command_encrypt_generates_a_fresh_nonce_each_call() {
        let dir = TempDir::new("kalyna_ccm_fresh_nonce");
        let key = [0x55u8; 16];
        let plaintext = b"same input twice".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let base_args = CcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce1.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("ct1.bin"),
            tag_path: dir.file("tag1.bin"),
            iterations: 1,
            force: false,
        };
        run_ccm_command(false, &base_args).expect("first encrypt should succeed");

        let second_args = CcmArgs {
            nonce_path: dir.file("nonce2.bin"),
            out_path: dir.file("ct2.bin"),
            tag_path: dir.file("tag2.bin"),
            ..base_args
        };
        run_ccm_command(false, &second_args).expect("second encrypt should succeed");

        let nonce1 = std::fs::read(dir.file("nonce1.bin")).expect("read nonce1");
        let nonce2 = std::fs::read(dir.file("nonce2.bin")).expect("read nonce2");
        assert_ne!(
            nonce1, nonce2,
            "two encrypt calls with the same key/plaintext must not reuse a nonce"
        );
    }

    #[test]
    fn run_ccm_command_decrypt_rejects_tampered_ciphertext_without_writing_out() {
        let dir = TempDir::new("kalyna_ccm_tamper");
        let key = [0x33u8; 16];
        let plaintext = b"do not trust me".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = CcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("ct.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        run_ccm_command(false, &encrypt_args).expect("encrypt should succeed");

        let mut tampered = std::fs::read(dir.file("ct.bin")).expect("read ciphertext");
        tampered[0] ^= 0x01;
        std::fs::write(dir.file("ct.bin"), &tampered).expect("write tampered ciphertext");

        let decrypt_args = CcmArgs {
            in_path: dir.file("ct.bin"),
            out_path: dir.file("pt.bin"),
            ..encrypt_args
        };
        let result = run_ccm_command(true, &decrypt_args);
        assert_eq!(result, Err(CliError::CcmVerifyFailed));
        assert!(!dir.file("pt.bin").exists());
    }

    #[test]
    fn parse_secretstream_args_happy_path() {
        let args = vec![
            "--key".to_string(),
            "key.bin".to_string(),
            "--in".to_string(),
            "msg.bin".to_string(),
            "--out".to_string(),
            "sealed.bin".to_string(),
        ];
        assert_eq!(
            parse_secretstream_args(&args),
            Ok(SecretstreamArgs {
                key_path: PathBuf::from("key.bin"),
                in_path: PathBuf::from("msg.bin"),
                out_path: PathBuf::from("sealed.bin"),
                force: false,
            })
        );
    }

    #[test]
    fn parse_secretstream_args_requires_key_in_out() {
        assert_eq!(
            parse_secretstream_args(&["--in".to_string(), "m".to_string()]),
            Err(CliError::MissingFlag("key"))
        );
        assert_eq!(
            parse_secretstream_args(&["--key".to_string(), "k".to_string()]),
            Err(CliError::MissingFlag("in"))
        );
        assert_eq!(
            parse_secretstream_args(&[
                "--key".to_string(),
                "k".to_string(),
                "--in".to_string(),
                "m".to_string(),
            ]),
            Err(CliError::MissingFlag("out"))
        );
    }

    #[test]
    fn parse_secretstream_args_rejects_unknown_flag() {
        assert_eq!(
            parse_secretstream_args(&["--nonce".to_string(), "n.bin".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--nonce".to_string(),
                suggestion: None,
            })
        );
    }

    #[test]
    fn run_secretstream_command_round_trip_matches_dstu_core_directly() {
        let dir = TempDir::new("secretstream_roundtrip");
        let key_bytes = [0x22u8; 32];
        let plaintext = b"short message".to_vec();
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key_bytes);
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
            force: false,
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let decrypt_args = SecretstreamArgs {
            in_path: dir.file("sealed.bin"),
            out_path: dir.file("pt.bin"),
            ..encrypt_args
        };
        run_secretstream_command(true, &decrypt_args).expect("decrypt should succeed");
        assert_eq!(std::fs::read(dir.file("pt.bin")).expect("read"), plaintext);
    }

    #[test]
    fn run_secretstream_command_encrypt_generates_a_fresh_header_each_call() {
        let dir = TempDir::new("secretstream_fresh_header");
        let key = [0x44u8; 32];
        let plaintext = b"same input twice".to_vec();
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key);
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let base_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed1.bin"),
            force: false,
        };
        run_secretstream_command(false, &base_args).expect("first encrypt should succeed");

        let second_args = SecretstreamArgs {
            out_path: dir.file("sealed2.bin"),
            ..base_args
        };
        run_secretstream_command(false, &second_args).expect("second encrypt should succeed");

        let sealed1 = std::fs::read(dir.file("sealed1.bin")).expect("read sealed1");
        let sealed2 = std::fs::read(dir.file("sealed2.bin")).expect("read sealed2");
        assert_ne!(
            &sealed1[1..=SECRETSTREAM_HEADER_LEN],
            &sealed2[1..=SECRETSTREAM_HEADER_LEN],
            "two encrypt calls with the same key/plaintext must not reuse a header"
        );
    }

    #[test]
    fn run_secretstream_command_decrypt_rejects_tampered_ciphertext_without_writing_out() {
        let dir = TempDir::new("secretstream_tamper");
        let key = [0x66u8; 32];
        let plaintext = b"do not trust me".to_vec();
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key);
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
            force: false,
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let mut tampered = std::fs::read(dir.file("sealed.bin")).expect("read sealed");
        // First ciphertext byte: after the version byte, the header and the record's tag+length.
        tampered[1 + SECRETSTREAM_HEADER_LEN + 5] ^= 0x01;
        std::fs::write(dir.file("sealed.bin"), &tampered).expect("write tampered output");

        let decrypt_args = SecretstreamArgs {
            in_path: dir.file("sealed.bin"),
            out_path: dir.file("pt.bin"),
            ..encrypt_args
        };
        let result = run_secretstream_command(true, &decrypt_args);
        assert_eq!(result, Err(CliError::SecretstreamVerifyFailed));
        assert!(!dir.file("pt.bin").exists());
    }

    /// A file several chunks long (`SECRETSTREAM_CHUNK_BYTES` = 8 KiB) round-trips end to end -
    /// proving the chunked framing actually reaches multiple records, not just a single-chunk
    /// happy path.
    #[test]
    fn run_secretstream_command_multi_chunk_message_round_trips() {
        let dir = TempDir::new("secretstream_large");
        let key = [0x77u8; 32];
        let large: Vec<u8> = (0..SECRETSTREAM_CHUNK_BYTES * 3 + 777)
            .map(|i| (i % 256) as u8)
            .collect();
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key);
        std::fs::write(dir.file("in.bin"), &large).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
            force: false,
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("sealed.bin"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        run_secretstream_command(true, &decrypt_args).expect("decrypt should succeed");

        let round_tripped = std::fs::read(dir.file("out.bin")).expect("read output");
        assert_eq!(round_tripped, large);
    }

    /// "Fool" test - an empty `--in` is a degenerate but entirely legal input: a single
    /// zero-length `Final` chunk, not an error.
    #[test]
    fn run_secretstream_command_empty_file_round_trips() {
        let dir = TempDir::new("secretstream_empty");
        let key = [0x11u8; 32];
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key);
        std::fs::write(dir.file("in.bin"), []).expect("write empty input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
            force: false,
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("sealed.bin"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        run_secretstream_command(true, &decrypt_args).expect("decrypt should succeed");
        assert_eq!(std::fs::read(dir.file("out.bin")).expect("read output"), []);
    }

    /// "Fool" test - a key file that's the wrong length (a common real mistake: a truncated
    /// download, a copy-paste that dropped bytes) must be a clean, typed error, not a panic or a
    /// silently-zero-padded key.
    #[test]
    fn run_secretstream_command_raw_key_file_is_rejected() {
        let dir = TempDir::new("secretstream_wrong_key_len");
        std::fs::write(dir.file("key.bin"), [0u8; 31]).expect("write short key");
        std::fs::write(dir.file("in.bin"), b"data").expect("write input");

        let args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        assert_eq!(
            run_secretstream_command(false, &args),
            Err(CliError::KeyFileNotTyped(dir.file("key.bin")))
        );
        assert!(!dir.file("out.bin").exists());
    }

    /// "Fool" test - pointing `--in` at a path that doesn't exist at all (typo'd filename) must be
    /// a clean `Io` error, not a panic.
    #[test]
    fn run_secretstream_command_nonexistent_input_is_io_error_not_panic() {
        let dir = TempDir::new("secretstream_no_input");
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &[0u8; 32]);

        let args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("does_not_exist.bin"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        assert!(matches!(
            run_secretstream_command(false, &args),
            Err(CliError::Io { .. })
        ));
        assert!(!dir.file("out.bin").exists());
    }

    /// "Fool" test - pointing `--in` at a directory instead of a file (an easy copy-paste mistake
    /// with a path variable) must be a clean `Io` error, not a panic.
    #[test]
    fn run_secretstream_command_directory_as_input_is_io_error_not_panic() {
        let dir = TempDir::new("secretstream_dir_input");
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &[0u8; 32]);
        std::fs::create_dir_all(dir.file("a_directory")).expect("create sub-directory");

        let args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("a_directory"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        assert!(matches!(
            run_secretstream_command(false, &args),
            Err(CliError::Io { .. })
        ));
        assert!(!dir.file("out.bin").exists());
    }

    /// "Fool" test - passing the same path for `--in` and `--out` (an easy mistake when scripting
    /// "encrypt this file in place"): refused without `--force` (T-258, D-214), round-trips with
    /// it. The temp-file-then-rename atomicity (module doc) is what
    /// keeps this safe under genuine streaming I/O, not a whole-buffer read like the old
    /// `crypto_secretbox`-backed command relied on.
    #[test]
    fn run_secretstream_command_in_and_out_same_path_round_trips() {
        let dir = TempDir::new("secretstream_same_path");
        let key = [0x55u8; 32];
        let plaintext = b"overwrite me in place".to_vec();
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key);
        std::fs::write(dir.file("data.bin"), &plaintext).expect("write input");

        let refused = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("data.bin"),
            out_path: dir.file("data.bin"),
            force: false,
        };
        assert!(matches!(
            run_secretstream_command(false, &refused),
            Err(CliError::OutputExists {
                same_as_input: true,
                ..
            })
        ));
        assert_eq!(
            std::fs::read(dir.file("data.bin")).expect("read"),
            plaintext
        );

        let encrypt_args = SecretstreamArgs {
            force: true,
            ..refused
        };
        run_secretstream_command(false, &encrypt_args).expect("in-place encrypt should succeed");
        assert_ne!(
            std::fs::read(dir.file("data.bin")).expect("read"),
            plaintext,
            "the file must now hold sealed output, not the original plaintext"
        );

        run_secretstream_command(true, &encrypt_args).expect("in-place decrypt should succeed");
        assert_eq!(
            std::fs::read(dir.file("data.bin")).expect("read"),
            plaintext
        );
    }

    /// "Fool" test - decrypting a file that was never produced by `encrypt` at all (random garbage
    /// of plausible length, not a tampered-but-otherwise-real sealed file) must fail cleanly and
    /// must not write `--out` - a distinct code path from
    /// `run_secretstream_command_decrypt_rejects_tampered_ciphertext_without_writing_out`, which
    /// starts from real `encrypt` output.
    #[test]
    fn run_secretstream_command_decrypt_rejects_never_sealed_garbage_without_writing_out() {
        let dir = TempDir::new("secretstream_garbage");
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &[0x88u8; 32]);
        std::fs::write(dir.file("garbage.bin"), [0x99u8; 64]).expect("write garbage");

        let args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("garbage.bin"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        // 64 bytes of garbage: the first byte is read as the format version (D-208), and 0x99 is
        // not one, so this fails before any key material is used.
        assert_eq!(
            run_secretstream_command(true, &args),
            Err(CliError::SecretstreamUnsupportedVersion(0x99))
        );
        assert!(!dir.file("out.bin").exists());
    }

    /// "Attack" test (D-64) - `--in` cut off before a `Final` chunk was ever written must be
    /// rejected as truncated, not silently accepted as a shorter message.
    #[test]
    fn run_secretstream_command_decrypt_rejects_truncated_stream_without_writing_out() {
        let dir = TempDir::new("secretstream_truncated");
        let key = [0x33u8; 32];
        let plaintext = b"a message that gets cut short".to_vec();
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key);
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
            force: false,
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let sealed = std::fs::read(dir.file("sealed.bin")).expect("read sealed");
        let cut = &sealed[..sealed.len() - 1];
        std::fs::write(dir.file("truncated.bin"), cut).expect("write truncated output");

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("truncated.bin"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        assert_eq!(
            run_secretstream_command(true, &decrypt_args),
            Err(CliError::SecretstreamTruncated)
        );
        assert!(!dir.file("out.bin").exists());
    }

    /// "Attack" test (D-64) - extra bytes appended after a legitimate `Final` chunk (an extension/
    /// append attack) must be rejected, not silently ignored.
    #[test]
    fn run_secretstream_command_decrypt_rejects_trailing_data_without_writing_out() {
        let dir = TempDir::new("secretstream_trailing");
        let key = [0x99u8; 32];
        let plaintext = b"legit message".to_vec();
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key);
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
            force: false,
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let mut extended = std::fs::read(dir.file("sealed.bin")).expect("read sealed");
        extended.push(0xAA);
        std::fs::write(dir.file("extended.bin"), &extended).expect("write extended output");

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("extended.bin"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        assert_eq!(
            run_secretstream_command(true, &decrypt_args),
            Err(CliError::SecretstreamTrailingData)
        );
        assert!(!dir.file("out.bin").exists());
    }

    /// "Fool" test - hashing an empty file must succeed and produce Kupyna-256's real empty-input
    /// digest, not an error - an empty file is a degenerate but entirely legal input.
    #[test]
    fn run_hash_command_empty_file_produces_the_empty_input_digest() {
        let dir = TempDir::new("hash_empty");
        let list = write_check_list(&dir, &[], &Kupyna256::digest(&[]));
        run_hash_command(&HashArgs::Check(list)).expect("hashing an empty file must succeed");
    }

    /// "Fool" test - `--iterations 0` (a plausible off-by-one from a user expecting "0 extra
    /// iterations") must behave exactly like `--iterations 1`, not silently skip hashing and write
    /// an empty/missing digest.
    #[test]
    fn run_digest_command_iterations_zero_behaves_like_one() {
        let dir = TempDir::new("digest_iterations_zero");
        let message = b"same input, different iterations value";
        std::fs::write(dir.file("msg.bin"), message).expect("write message");

        run_digest_command(&DigestArgs {
            variant: HashBits::B256,
            in_path: dir.file("msg.bin"),
            out_path: dir.file("digest_zero.bin"),
            iterations: 0,
            force: false,
        })
        .expect("iterations=0 must still hash successfully");
        run_digest_command(&DigestArgs {
            variant: HashBits::B256,
            in_path: dir.file("msg.bin"),
            out_path: dir.file("digest_one.bin"),
            iterations: 1,
            force: false,
        })
        .expect("iterations=1 baseline");

        assert_eq!(
            std::fs::read(dir.file("digest_zero.bin")).expect("read"),
            std::fs::read(dir.file("digest_one.bin")).expect("read")
        );
    }

    /// "Fool" test - a key file that's the wrong length for the chosen Kalyna variant must be a
    /// clean typed error, not a panic - the `kalyna-ccm` counterpart to the `encrypt`/`decrypt`
    /// version of this test above.
    #[test]
    fn run_ccm_command_wrong_key_length_is_rejected() {
        let dir = TempDir::new("ccm_wrong_key_len");
        std::fs::write(dir.file("key.bin"), [0u8; 15]).expect("write short key"); // K128_128 wants 16
        std::fs::write(dir.file("in.bin"), b"data").expect("write input");

        let args = CcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_ccm_command(false, &args),
            Err(CliError::WrongLength {
                what: LengthOf::Key,
                expected: 16,
                actual: 15,
            })
        );
        assert!(!dir.file("out.bin").exists());
    }

    /// "Fool" test - on `decrypt`, a `--nonce` file of the wrong length (e.g. hand-edited or copied
    /// from a different variant) must be a clean typed error, not a panic or silent truncation.
    #[test]
    fn run_ccm_command_wrong_nonce_length_on_decrypt_is_rejected() {
        let dir = TempDir::new("ccm_wrong_nonce_len");
        std::fs::write(dir.file("key.bin"), [0u8; 16]).expect("write key");
        std::fs::write(dir.file("nonce.bin"), [0u8; 15]).expect("write short nonce"); // wants 16
        std::fs::write(dir.file("tag.bin"), [0u8; 16]).expect("write tag");
        std::fs::write(dir.file("in.bin"), b"ciphertext-ish!!").expect("write input");

        let args = CcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_ccm_command(true, &args),
            Err(CliError::WrongLength {
                what: LengthOf::Nonce,
                expected: 16,
                actual: 15,
            })
        );
        assert!(!dir.file("out.bin").exists());
    }

    #[test]
    fn run_dispatches_encrypt_and_decrypt_correctly() {
        let dir = TempDir::new("secretbox_dispatch");
        let key = [0x88u8; 32];
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &key);
        std::fs::write(dir.file("in.bin"), b"dispatch me").expect("write input");

        let key_str = dir
            .file("key.bin")
            .to_str()
            .expect("valid utf-8 path")
            .to_string();
        let encrypt_args: Vec<String> = [
            "encrypt",
            "--key",
            key_str.as_str(),
            "--in",
            dir.file("in.bin").to_str().expect("valid utf-8 path"),
            "--out",
            dir.file("sealed.bin").to_str().expect("valid utf-8 path"),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&encrypt_args).expect("encrypt dispatch should succeed");

        let decrypt_args: Vec<String> = [
            "decrypt",
            "--key",
            key_str.as_str(),
            "--in",
            dir.file("sealed.bin").to_str().expect("valid utf-8 path"),
            "--out",
            dir.file("pt.bin").to_str().expect("valid utf-8 path"),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&decrypt_args).expect("decrypt dispatch should succeed");

        assert_eq!(
            std::fs::read(dir.file("pt.bin")).expect("read"),
            b"dispatch me"
        );
    }

    #[test]
    fn parse_strumok_args_requires_key_and_iv() {
        let args = vec![
            "--variant".to_string(),
            "256".to_string(),
            "--key".to_string(),
            "k".to_string(),
        ];
        assert_eq!(parse_strumok_args(&args), Err(CliError::MissingFlag("iv")));
    }

    #[test]
    fn run_strumok_command_matches_dstu_core_directly() {
        let dir = TempDir::new("strumok");
        let key = [0x44u8; 32];
        let iv = [0x55u8; 32];
        let plaintext = b"hello stream cipher world!".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("iv.bin"), iv).expect("write iv");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let args = StrumokArgs {
            variant: HashBits::B256,
            key_path: dir.file("key.bin"),
            iv_path: dir.file("iv.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            iterations: 1,
            raw_schedule: false,
            force: false,
        };
        run_strumok_command(&args).expect("strumok command should succeed");

        let mut expected = plaintext.clone();
        Strumok256::new(&key, &iv).apply_keystream(&mut expected);
        assert_eq!(std::fs::read(dir.file("out.bin")).expect("read"), expected);
    }

    #[test]
    fn run_strumok_command_is_its_own_inverse() {
        let dir = TempDir::new("strumok_roundtrip");
        let key = [0x66u8; 64];
        let iv = [0x77u8; 32];
        let plaintext = b"round trip me please".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("iv.bin"), iv).expect("write iv");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = StrumokArgs {
            variant: HashBits::B512,
            key_path: dir.file("key.bin"),
            iv_path: dir.file("iv.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("ct.bin"),
            iterations: 1,
            raw_schedule: false,
            force: false,
        };
        run_strumok_command(&encrypt_args).expect("encrypt should succeed");

        let decrypt_args = StrumokArgs {
            in_path: dir.file("ct.bin"),
            out_path: dir.file("pt.bin"),
            ..encrypt_args
        };
        run_strumok_command(&decrypt_args).expect("decrypt should succeed");

        assert_eq!(std::fs::read(dir.file("pt.bin")).expect("read"), plaintext);
    }

    /// `run_strumok_command` streams `--in` to `--out` in fixed-size chunks for real (`iterations
    /// <= 1`) usage rather than reading the whole file (D-42's policy, applied here after
    /// `kupyna-digest`). Every test above uses a message far smaller than one chunk, which never
    /// exercises the multi-chunk read/apply/write loop or a chunk boundary falling mid-keystream
    /// (the exact case T-24's `apply_keystream` chunk-invariance property test already covers at
    /// the `hazmat` level - this checks the CLI wiring puts it to use correctly end to end).
    #[test]
    fn run_strumok_command_streams_multi_chunk_input_correctly() {
        let dir = TempDir::new("strumok_multichunk");
        let key = [0x22u8; 64];
        let iv = [0x33u8; 32];
        let len = STRUMOK_STREAM_CHUNK_BYTES * 2 + 555; // deliberately not chunk-aligned
        let plaintext: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(61)).collect();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("iv.bin"), iv).expect("write iv");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let args = StrumokArgs {
            variant: HashBits::B512,
            key_path: dir.file("key.bin"),
            iv_path: dir.file("iv.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            iterations: 1,
            raw_schedule: false,
            force: false,
        };
        run_strumok_command(&args).expect("strumok command should succeed");

        let mut expected = plaintext.clone();
        Strumok512::new(&key, &iv).apply_keystream(&mut expected);
        assert_eq!(std::fs::read(dir.file("out.bin")).expect("read"), expected);
    }

    /// Regression test for a real data-destruction bug (T-200, found by an empirical `--in`==
    /// `--out` smoke-test probe of the real binary, not by inspection): the streaming
    /// (`iterations <= 1`) path used to open `--out` via `File::create` - truncating it - before
    /// finishing reading `--in`, so "encrypt this file in place" silently produced a 0-byte file
    /// (exit code 0, no error). Fixed via the same temp-file-then-rename discipline
    /// `run_secretstream_command` already used (`temp_path_beside`). Strumok is its own inverse
    /// (XOR keystream), so applying the same command twice in place must recover the plaintext.
    #[test]
    fn run_strumok_command_in_and_out_same_path_round_trips() {
        let dir = TempDir::new("strumok_same_path");
        let key = [0x11u8; 32];
        let iv = [0x22u8; 32];
        let plaintext = vec![b'A'; STRUMOK_STREAM_CHUNK_BYTES * 3 + 17]; // multi-chunk, unaligned
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("iv.bin"), iv).expect("write iv");
        std::fs::write(dir.file("data.bin"), &plaintext).expect("write input");

        let args = StrumokArgs {
            variant: HashBits::B256,
            key_path: dir.file("key.bin"),
            iv_path: dir.file("iv.bin"),
            in_path: dir.file("data.bin"),
            out_path: dir.file("data.bin"),
            iterations: 1,
            raw_schedule: false,
            force: true,
        };
        run_strumok_command(&args).expect("in-place apply should succeed");
        let after_first = std::fs::read(dir.file("data.bin")).expect("read");
        assert_eq!(
            after_first.len(),
            plaintext.len(),
            "output must not be truncated/destroyed"
        );
        assert_ne!(after_first, plaintext, "must actually be keystream-applied");

        run_strumok_command(&args).expect("second in-place apply should succeed");
        assert_eq!(
            std::fs::read(dir.file("data.bin")).expect("read"),
            plaintext,
            "applying the keystream twice must recover the original plaintext"
        );

        assert_eq!(
            std::fs::read_dir(&dir.0).expect("list dir").count(),
            3,
            "no leftover temp file after a successful run (only key, iv, data)"
        );
    }

    // T-108: `--help`/`-h` handling. These call the public `run()` dispatcher directly (not just
    // the parser/runner functions) since the help check happens in `run()` itself, before any
    // `parse_*_args` call - a missing required flag alongside `--help` must still print help and
    // succeed, not fail on the missing flag.

    #[test]
    fn run_no_args_prints_top_level_help_and_succeeds() {
        assert!(run(&[]).is_ok());
    }

    #[test]
    fn run_top_level_help_flag_succeeds() {
        assert!(run(&["--help".to_string()]).is_ok());
        assert!(run(&["-h".to_string()]).is_ok());
    }

    #[test]
    fn run_version_flag_succeeds() {
        assert!(run(&["--version".to_string()]).is_ok());
        assert!(run(&["-V".to_string()]).is_ok());
    }

    #[test]
    fn help_texts_describe_formats_and_warn_on_raw_gcm_gmac() {
        assert!(TOP_LEVEL_HELP.contains("FILE FORMATS"));
        assert!(ENCRYPT_HELP.contains("OUTPUT FORMAT"));
        assert!(BOX_SEAL_HELP.contains("OUTPUT FORMAT"));
        assert!(KALYNA_GCM_HELP.contains("does not cover the nonce"));
        assert!(KALYNA_GCM_HELP.contains("An empty --in"));
        assert!(KALYNA_GMAC_HELP.contains("An empty --in is rejected"));
    }

    #[test]
    fn is_version_flag_matches_only_the_two_known_forms() {
        assert!(is_version_flag("--version"));
        assert!(is_version_flag("-V"));
        assert!(!is_version_flag("-v"));
        assert!(!is_version_flag("version"));
    }

    #[test]
    fn run_unknown_command_is_still_an_error() {
        assert_eq!(
            run(&["bogus".to_string()]),
            Err(CliError::UnknownCommand {
                command: "bogus".to_string(),
                suggestion: None,
            })
        );
    }

    #[test]
    fn run_per_command_help_succeeds_without_other_required_flags() {
        for command in [
            "keygen",
            "encrypt",
            "decrypt",
            "hash",
            "sign-keygen",
            "sign-pubkey",
            "sign",
            "verify",
            "kalyna-block",
            "kalyna-ccm",
            "kupyna-digest",
            "strumok-crypt",
        ] {
            assert!(
                run(&[command.to_string(), "--help".to_string()]).is_ok(),
                "{command} --help should succeed"
            );
        }
    }

    #[test]
    fn run_kalyna_subcommand_help_succeeds_before_and_after_encrypt_decrypt() {
        assert!(run(&["kalyna-block".to_string(), "--help".to_string()]).is_ok());
        assert!(run(&[
            "kalyna-block".to_string(),
            "encrypt".to_string(),
            "--help".to_string()
        ])
        .is_ok());
        assert!(run(&[
            "kalyna-ccm".to_string(),
            "decrypt".to_string(),
            "-h".to_string()
        ])
        .is_ok());
    }

    #[test]
    fn run_help_flag_takes_priority_over_missing_required_flags() {
        // `--key k` alone is missing --in/--out, which would normally error - --help must still
        // win and print help instead of surfacing that MissingFlag error.
        assert!(run(&[
            "kalyna-block".to_string(),
            "encrypt".to_string(),
            "--key".to_string(),
            "k".to_string(),
            "--help".to_string()
        ])
        .is_ok());
    }

    #[test]
    fn print_command_help_falls_back_to_top_level_for_unrecognized_name() {
        // Not a behavior a real caller can trigger through `run()` (every call site passes a
        // literal it just matched), but documents the fallback explicitly rather than leaving it
        // an untested assumption.
        print_command_help("not-a-real-command");
    }

    // --- kalyna-gcm (T-120/D-71) ---

    #[test]
    fn run_gcm_command_round_trip_matches_dstu_core_directly() {
        let dir = TempDir::new("kalyna_gcm");
        let key = [0x11u8; 16];
        let aad = b"header".to_vec();
        let plaintext = b"a message of any length, unlike kalyna-ccm".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("aad.bin"), &aad).expect("write aad");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = GcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: Some(dir.file("aad.bin")),
            in_path: dir.file("in.bin"),
            out_path: dir.file("ct.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        run_gcm_command(false, &encrypt_args).expect("encrypt should succeed");

        let generated_nonce = std::fs::read(dir.file("nonce.bin")).expect("read generated nonce");
        let mut nonce_arr = [0u8; 16];
        nonce_arr.copy_from_slice(&generated_nonce);
        let expected_cipher = Kalyna128_128Gcm::new(&key);
        let mut expected_ct = vec![0u8; plaintext.len()];
        let expected_tag = expected_cipher
            .encrypt(&nonce_arr, &aad, &plaintext, &mut expected_ct)
            .expect("direct encrypt with the generated nonce should succeed");
        assert_eq!(
            std::fs::read(dir.file("ct.bin")).expect("read"),
            expected_ct
        );
        assert_eq!(
            std::fs::read(dir.file("tag.bin")).expect("read"),
            expected_tag.to_vec()
        );

        let decrypt_args = GcmArgs {
            in_path: dir.file("ct.bin"),
            out_path: dir.file("pt.bin"),
            ..encrypt_args
        };
        run_gcm_command(true, &decrypt_args).expect("decrypt should succeed");
        assert_eq!(std::fs::read(dir.file("pt.bin")).expect("read"), plaintext);
    }

    #[test]
    fn run_gcm_command_iterations_greater_than_one_still_decrypts_correctly() {
        // "Correctness" for the benchmark loop itself: repeating encrypt N times over the same
        // nonce/plaintext must still leave a valid, decryptable final ciphertext/tag on disk -
        // not just "doesn't crash". `run_gcm_command`'s loop re-encrypts the same plaintext under
        // the same (call-local) nonce every iteration, so the final result is deterministic and
        // must round-trip through `decrypt` exactly like the `iterations: 1` case does.
        let dir = TempDir::new("kalyna_gcm_iterations");
        let key = [0x22u8; 32];
        let plaintext = b"benchmark me a few times".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = GcmArgs {
            variant: KalynaVariant::K256_256,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("ct.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 5,
            force: false,
        };
        run_gcm_command(false, &encrypt_args).expect("iterated encrypt should succeed");

        let decrypt_args = GcmArgs {
            in_path: dir.file("ct.bin"),
            out_path: dir.file("pt.bin"),
            iterations: 1,
            ..encrypt_args
        };
        run_gcm_command(true, &decrypt_args).expect("decrypt should succeed");
        assert_eq!(std::fs::read(dir.file("pt.bin")).expect("read"), plaintext);
    }

    #[test]
    fn run_gcm_command_decrypt_rejects_tampered_ciphertext_without_writing_out() {
        let dir = TempDir::new("kalyna_gcm_tamper");
        let key = [0x33u8; 16];
        let plaintext = b"do not trust me either".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = GcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("ct.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        run_gcm_command(false, &encrypt_args).expect("encrypt should succeed");

        let mut tampered = std::fs::read(dir.file("ct.bin")).expect("read ciphertext");
        tampered[0] ^= 0x01;
        std::fs::write(dir.file("ct.bin"), &tampered).expect("write tampered ciphertext");

        let decrypt_args = GcmArgs {
            in_path: dir.file("ct.bin"),
            out_path: dir.file("pt.bin"),
            ..encrypt_args
        };
        let result = run_gcm_command(true, &decrypt_args);
        assert_eq!(result, Err(CliError::GcmVerifyFailed));
        assert!(!dir.file("pt.bin").exists());
    }

    /// "Fool" test (T-234/D-207): DSTU 7624:2014 §12.1 needs `|O| + |M| >= 1`; with no `--aad`
    /// and an empty `--in` the tag would be the GHASH key itself, so the command refuses.
    #[test]
    fn run_gcm_command_empty_aad_and_input_is_rejected() {
        let dir = TempDir::new("gcm_empty");
        std::fs::write(dir.file("key.bin"), [0u8; 16]).expect("write key");
        std::fs::write(dir.file("in.bin"), []).expect("write empty input");
        let args = GcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_gcm_command(false, &args),
            Err(CliError::EmptyInput("kalyna-gcm"))
        );
        assert!(!dir.file("tag.bin").exists());
    }

    /// Same rule for `kalyna-gmac` (§12.1/§12.5): an empty message would yield the GHASH key.
    #[test]
    fn run_gmac_command_empty_input_is_rejected() {
        let dir = TempDir::new("gmac_empty");
        std::fs::write(dir.file("key.bin"), [0u8; 16]).expect("write key");
        std::fs::write(dir.file("in.bin"), []).expect("write empty input");
        let args = GmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: Some(dir.file("tag.bin")),
            tag_path: None,
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_gmac_command(false, &args),
            Err(CliError::EmptyInput("kalyna-gmac"))
        );
        assert!(!dir.file("tag.bin").exists());
    }

    #[test]
    fn run_gcm_command_wrong_key_length_is_rejected() {
        let dir = TempDir::new("gcm_wrong_key_len");
        std::fs::write(dir.file("key.bin"), [0u8; 15]).expect("write short key"); // K128_128 wants 16
        std::fs::write(dir.file("in.bin"), b"data").expect("write input");

        let args = GcmArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            nonce_path: dir.file("nonce.bin"),
            aad_path: None,
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            tag_path: dir.file("tag.bin"),
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_gcm_command(false, &args),
            Err(CliError::WrongLength {
                what: LengthOf::Key,
                expected: 16,
                actual: 15,
            })
        );
        assert!(!dir.file("out.bin").exists());
    }

    // --- kalyna-cmac (T-120/D-71) ---

    #[test]
    fn run_cmac_command_round_trip_matches_dstu_core_directly() {
        let dir = TempDir::new("kalyna_cmac");
        let key = [0x44u8; 16];
        let message = b"authenticate me".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &message).expect("write message");

        let compute_args = CmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: Some(dir.file("tag.bin")),
            tag_path: None,
            iterations: 1,
            force: false,
        };
        run_cmac_command(false, &compute_args).expect("compute should succeed");

        let expected_tag = Kalyna128_128Cmac::mac(&key, &message).expect("non-empty message");
        assert_eq!(
            std::fs::read(dir.file("tag.bin")).expect("read"),
            expected_tag.to_vec()
        );

        let verify_args = CmacArgs {
            out_path: None,
            tag_path: Some(dir.file("tag.bin")),
            ..compute_args
        };
        run_cmac_command(true, &verify_args).expect("verify should succeed against its own tag");
    }

    /// "Fool" test (T-236/D-206): DSTU 7624:2014 §9 does not define CMAC for an empty message, so an
    /// empty `--in` is rejected on both compute and verify instead of producing `MAC(0^l)`.
    #[test]
    fn run_cmac_command_empty_input_is_rejected() {
        let dir = TempDir::new("kalyna_cmac_empty");
        std::fs::write(dir.file("key.bin"), [0x55u8; 16]).expect("write key");
        std::fs::write(dir.file("in.bin"), []).expect("write empty input");
        std::fs::write(dir.file("tag_in.bin"), [0u8; 16]).expect("write tag");
        let compute_args = CmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: Some(dir.file("tag.bin")),
            tag_path: None,
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_cmac_command(false, &compute_args),
            Err(CliError::EmptyInput("kalyna-cmac"))
        );
        assert!(!dir.file("tag.bin").exists());

        let verify_args = CmacArgs {
            out_path: None,
            tag_path: Some(dir.file("tag_in.bin")),
            ..compute_args
        };
        assert_eq!(
            run_cmac_command(true, &verify_args),
            Err(CliError::EmptyInput("kalyna-cmac"))
        );
    }

    #[test]
    fn run_cmac_command_verify_rejects_tampered_tag() {
        let dir = TempDir::new("kalyna_cmac_tamper");
        let key = [0x55u8; 16];
        let message = b"do not forge me".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &message).expect("write message");

        let mut tag = Kalyna128_128Cmac::mac(&key, &message).expect("non-empty message");
        tag[0] ^= 0x01;
        std::fs::write(dir.file("tag.bin"), tag).expect("write tampered tag");

        let verify_args = CmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: None,
            tag_path: Some(dir.file("tag.bin")),
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_cmac_command(true, &verify_args),
            Err(CliError::CmacVerifyFailed)
        );
    }

    #[test]
    fn run_cmac_command_verify_without_tag_flag_is_rejected() {
        let dir = TempDir::new("kalyna_cmac_missing_tag");
        std::fs::write(dir.file("key.bin"), [0u8; 16]).expect("write key");
        std::fs::write(dir.file("in.bin"), b"data").expect("write message");

        let args = CmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: None,
            tag_path: None,
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_cmac_command(true, &args),
            Err(CliError::MissingFlag("tag"))
        );
    }

    // --- kalyna-gmac (T-120/D-71) ---

    #[test]
    fn run_gmac_command_round_trip_matches_dstu_core_directly() {
        let dir = TempDir::new("kalyna_gmac");
        let key = [0x66u8; 16];
        let message = b"authenticate me, no nonce needed".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &message).expect("write message");

        let compute_args = GmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: Some(dir.file("tag.bin")),
            tag_path: None,
            iterations: 1,
            force: false,
        };
        run_gmac_command(false, &compute_args).expect("compute should succeed");

        let expected_tag = Kalyna128_128Gmac::mac(&key, &message).expect("non-empty message");
        assert_eq!(
            std::fs::read(dir.file("tag.bin")).expect("read"),
            expected_tag.to_vec()
        );

        let verify_args = GmacArgs {
            out_path: None,
            tag_path: Some(dir.file("tag.bin")),
            ..compute_args
        };
        run_gmac_command(true, &verify_args).expect("verify should succeed against its own tag");
    }

    #[test]
    fn run_gmac_command_verify_rejects_tampered_tag() {
        let dir = TempDir::new("kalyna_gmac_tamper");
        let key = [0x77u8; 16];
        let message = b"do not forge me either".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &message).expect("write message");

        let mut tag = Kalyna128_128Gmac::mac(&key, &message).expect("non-empty message");
        tag[0] ^= 0x01;
        std::fs::write(dir.file("tag.bin"), tag).expect("write tampered tag");

        let verify_args = GmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: None,
            tag_path: Some(dir.file("tag.bin")),
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_gmac_command(true, &verify_args),
            Err(CliError::GmacVerifyFailed)
        );
    }

    // --- kalyna-kw (T-120/D-71) ---

    #[test]
    fn run_kw_command_round_trip_matches_dstu_core_directly() {
        let dir = TempDir::new("kalyna_kw");
        let key = [0x88u8; 16];
        let key_material = [0x99u8; 32]; // 2 blocks, block-aligned
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), key_material).expect("write key material");

        let wrap_args = KwArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("wrapped.bin"),
            iterations: 1,
            force: false,
        };
        run_kw_command(false, &wrap_args).expect("wrap should succeed");

        let mut expected_wrapped = [0u8; 48];
        Kalyna128_128Kw::wrap(&key, &key_material, &mut expected_wrapped)
            .expect("direct wrap should succeed");
        assert_eq!(
            std::fs::read(dir.file("wrapped.bin")).expect("read"),
            expected_wrapped.to_vec()
        );

        let unwrap_args = KwArgs {
            in_path: dir.file("wrapped.bin"),
            out_path: dir.file("unwrapped.bin"),
            ..wrap_args
        };
        run_kw_command(true, &unwrap_args).expect("unwrap should succeed");
        assert_eq!(
            std::fs::read(dir.file("unwrapped.bin")).expect("read"),
            key_material.to_vec()
        );
    }

    #[test]
    fn run_kw_command_unwrap_rejects_tampered_wrapped_blob() {
        let dir = TempDir::new("kalyna_kw_tamper");
        let key = [0xAAu8; 16];
        let key_material = [0xBBu8; 16];
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), key_material).expect("write key material");

        let wrap_args = KwArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("wrapped.bin"),
            iterations: 1,
            force: false,
        };
        run_kw_command(false, &wrap_args).expect("wrap should succeed");

        let mut tampered = std::fs::read(dir.file("wrapped.bin")).expect("read wrapped");
        tampered[0] ^= 0x01;
        std::fs::write(dir.file("wrapped.bin"), &tampered).expect("write tampered blob");

        let unwrap_args = KwArgs {
            in_path: dir.file("wrapped.bin"),
            out_path: dir.file("unwrapped.bin"),
            ..wrap_args
        };
        let result = run_kw_command(true, &unwrap_args);
        assert!(
            result == Err(CliError::KwChecksumMismatch)
                || matches!(result, Err(CliError::KwInvalidLength)),
            "tampering must be rejected, got {result:?}"
        );
        assert!(!dir.file("unwrapped.bin").exists());
    }

    #[test]
    fn run_kw_command_non_block_aligned_input_is_rejected() {
        let dir = TempDir::new("kalyna_kw_misaligned");
        std::fs::write(dir.file("key.bin"), [0u8; 16]).expect("write key");
        std::fs::write(dir.file("in.bin"), [0u8; 17]).expect("write misaligned key material"); // not a multiple of 16

        let args = KwArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            iterations: 1,
            force: false,
        };
        assert_eq!(run_kw_command(false, &args), Err(CliError::KwInvalidLength));
        assert!(!dir.file("out.bin").exists());
    }

    // --- kalyna-xts (T-120/D-71) ---

    #[test]
    fn run_xts_command_round_trip_matches_dstu_core_directly() {
        let dir = TempDir::new("kalyna_xts");
        let key = [0xCCu8; 16];
        let tweak = [0xDDu8; 16];
        let sector = [0xEEu8; 40]; // not block-aligned - exercises ciphertext stealing
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("tweak.bin"), tweak).expect("write tweak");
        std::fs::write(dir.file("in.bin"), sector).expect("write sector");

        let encrypt_args = XtsArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            tweak_path: dir.file("tweak.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("ct.bin"),
            iterations: 1,
            force: false,
        };
        run_xts_command(false, &encrypt_args).expect("encrypt should succeed");

        let cipher = Kalyna128_128Xts::new(&key);
        let mut expected = sector.to_vec();
        cipher
            .encrypt_in_place(&tweak, &mut expected)
            .expect("direct encrypt should succeed");
        assert_eq!(std::fs::read(dir.file("ct.bin")).expect("read"), expected);

        let decrypt_args = XtsArgs {
            in_path: dir.file("ct.bin"),
            out_path: dir.file("pt.bin"),
            ..encrypt_args
        };
        run_xts_command(true, &decrypt_args).expect("decrypt should succeed");
        assert_eq!(
            std::fs::read(dir.file("pt.bin")).expect("read"),
            sector.to_vec()
        );
    }

    #[test]
    fn run_xts_command_input_shorter_than_one_block_is_rejected() {
        // No rejection/tamper-tag test exists for XTS - by design, it is confidentiality-only
        // (see hazmat::kalyna_xts's module doc comment), so there is no tag to tamper with. This
        // is the one "fool" category that IS reachable: an input too short for even one block.
        let dir = TempDir::new("kalyna_xts_short");
        std::fs::write(dir.file("key.bin"), [0u8; 16]).expect("write key");
        std::fs::write(dir.file("tweak.bin"), [0u8; 16]).expect("write tweak");
        std::fs::write(dir.file("in.bin"), [0u8; 8]).expect("write short sector"); // < 16-byte block

        let args = XtsArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            tweak_path: dir.file("tweak.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
            iterations: 1,
            force: false,
        };
        assert_eq!(
            run_xts_command(false, &args),
            Err(CliError::XtsInvalidLength)
        );
        assert!(!dir.file("out.bin").exists());
    }

    // --- dispatch smoke tests for the five new commands (T-120/D-71) ---

    #[test]
    fn run_dispatches_all_five_new_kalyna_mode_commands_help() {
        for cmd in [
            "kalyna-gcm",
            "kalyna-cmac",
            "kalyna-gmac",
            "kalyna-kw",
            "kalyna-xts",
        ] {
            assert!(
                run(&[cmd.to_string(), "--help".to_string()]).is_ok(),
                "{cmd} --help should succeed"
            );
        }
    }

    #[test]
    fn run_kalyna_gcm_dispatch_round_trips_through_the_top_level_command() {
        let dir = TempDir::new("dispatch_gcm");
        std::fs::write(dir.file("key.bin"), [0u8; 16]).expect("write key");
        std::fs::write(dir.file("in.bin"), b"dispatch me").expect("write input");

        let path = |p: &std::path::Path| p.to_str().expect("valid utf-8 path").to_string();
        let encrypt: Vec<String> = [
            "kalyna-gcm",
            "encrypt",
            "--variant",
            "128-128",
            "--key",
            &path(&dir.file("key.bin")),
            "--nonce",
            &path(&dir.file("nonce.bin")),
            "--in",
            &path(&dir.file("in.bin")),
            "--out",
            &path(&dir.file("ct.bin")),
            "--tag",
            &path(&dir.file("tag.bin")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&encrypt).expect("encrypt dispatch should succeed");

        let decrypt: Vec<String> = [
            "kalyna-gcm",
            "decrypt",
            "--variant",
            "128-128",
            "--key",
            &path(&dir.file("key.bin")),
            "--nonce",
            &path(&dir.file("nonce.bin")),
            "--in",
            &path(&dir.file("ct.bin")),
            "--out",
            &path(&dir.file("pt.bin")),
            "--tag",
            &path(&dir.file("tag.bin")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&decrypt).expect("decrypt dispatch should succeed");
        assert_eq!(
            std::fs::read(dir.file("pt.bin")).expect("read"),
            b"dispatch me".to_vec()
        );
    }

    #[test]
    fn run_unknown_subcommand_for_each_new_mode_is_rejected() {
        for cmd in [
            "kalyna-gcm",
            "kalyna-cmac",
            "kalyna-gmac",
            "kalyna-kw",
            "kalyna-xts",
        ] {
            let result = run(&[cmd.to_string(), "not-a-real-subcommand".to_string()]);
            assert!(
                matches!(result, Err(CliError::UnknownCommand { .. })),
                "{cmd} with an unknown subcommand should be rejected, got {result:?}"
            );
        }
    }

    // T-124: `sign-keygen`/`sign-pubkey`/`sign`/`verify` - a libsodium/misuse-resistant CLI over
    // `dstu_core::crypto_sign` (T-48/D-46, keypair generation T-122/D-72).

    #[test]
    fn parse_sign_keygen_args_happy_path() {
        let args = vec!["--out".to_string(), "signing.key".to_string()];
        assert_eq!(
            parse_sign_keygen_args(&args),
            Ok(SignKeygenArgs {
                out_path: PathBuf::from("signing.key"),
            })
        );
    }

    #[test]
    fn parse_sign_keygen_args_requires_out() {
        assert_eq!(
            parse_sign_keygen_args(&[]),
            Err(CliError::MissingFlag("out"))
        );
    }

    #[test]
    fn parse_sign_keygen_args_rejects_unknown_flag() {
        assert_eq!(
            parse_sign_keygen_args(&["--variant".to_string(), "256".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--variant".to_string(),
                suggestion: None,
            })
        );
    }

    #[test]
    fn parse_sign_pubkey_args_happy_path() {
        let args = vec![
            "--key".to_string(),
            "signing.key".to_string(),
            "--out".to_string(),
            "verifying.key".to_string(),
        ];
        assert_eq!(
            parse_sign_pubkey_args(&args),
            Ok(SignPubkeyArgs {
                key_path: PathBuf::from("signing.key"),
                out_path: PathBuf::from("verifying.key"),
            })
        );
    }

    #[test]
    fn parse_sign_pubkey_args_requires_key_and_out() {
        assert_eq!(
            parse_sign_pubkey_args(&[]),
            Err(CliError::MissingFlag("key"))
        );
        assert_eq!(
            parse_sign_pubkey_args(&["--key".to_string(), "k".to_string()]),
            Err(CliError::MissingFlag("out"))
        );
    }

    #[test]
    fn parse_sign_pubkey_args_rejects_unknown_flag() {
        assert_eq!(
            parse_sign_pubkey_args(&["--variant".to_string(), "256".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--variant".to_string(),
                suggestion: None,
            })
        );
    }

    #[test]
    fn parse_sign_args_happy_path() {
        let args = vec![
            "--key".to_string(),
            "signing.key".to_string(),
            "--in".to_string(),
            "msg.bin".to_string(),
            "--out".to_string(),
            "msg.sig".to_string(),
        ];
        assert_eq!(
            parse_sign_args(&args),
            Ok(SignArgs {
                key_path: PathBuf::from("signing.key"),
                in_path: PathBuf::from("msg.bin"),
                out_path: PathBuf::from("msg.sig"),
                iterations: 1,
                force: false,
            })
        );
    }

    #[test]
    fn parse_sign_args_happy_path_with_iterations() {
        let args = vec![
            "--key".to_string(),
            "signing.key".to_string(),
            "--in".to_string(),
            "msg.bin".to_string(),
            "--out".to_string(),
            "msg.sig".to_string(),
            "--iterations".to_string(),
            "42".to_string(),
        ];
        let parsed = parse_sign_args(&args).expect("valid args should parse");
        assert_eq!(parsed.iterations, 42);
    }

    #[test]
    fn parse_sign_args_rejects_invalid_iterations() {
        assert_eq!(
            parse_sign_args(&[
                "--key".to_string(),
                "k".to_string(),
                "--in".to_string(),
                "i".to_string(),
                "--out".to_string(),
                "o".to_string(),
                "--iterations".to_string(),
                "not-a-number".to_string(),
            ]),
            Err(CliError::InvalidIterations("not-a-number".to_string()))
        );
    }

    #[test]
    fn parse_sign_args_requires_all_of_key_in_out() {
        assert_eq!(parse_sign_args(&[]), Err(CliError::MissingFlag("key")));
        assert_eq!(
            parse_sign_args(&["--key".to_string(), "k".to_string()]),
            Err(CliError::MissingFlag("in"))
        );
        assert_eq!(
            parse_sign_args(&[
                "--key".to_string(),
                "k".to_string(),
                "--in".to_string(),
                "i".to_string(),
            ]),
            Err(CliError::MissingFlag("out"))
        );
    }

    #[test]
    fn parse_sign_args_rejects_unknown_flag() {
        assert_eq!(
            parse_sign_args(&["--variant".to_string(), "256".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--variant".to_string(),
                suggestion: None,
            })
        );
    }

    #[test]
    fn parse_verify_args_happy_path() {
        let args = vec![
            "--key".to_string(),
            "verifying.key".to_string(),
            "--in".to_string(),
            "msg.bin".to_string(),
            "--sig".to_string(),
            "msg.sig".to_string(),
        ];
        assert_eq!(
            parse_verify_args(&args),
            Ok(VerifyArgs {
                key_path: PathBuf::from("verifying.key"),
                in_path: PathBuf::from("msg.bin"),
                sig_path: PathBuf::from("msg.sig"),
                iterations: 1,
            })
        );
    }

    #[test]
    fn parse_verify_args_happy_path_with_iterations() {
        let args = vec![
            "--key".to_string(),
            "verifying.key".to_string(),
            "--in".to_string(),
            "msg.bin".to_string(),
            "--sig".to_string(),
            "msg.sig".to_string(),
            "--iterations".to_string(),
            "17".to_string(),
        ];
        let parsed = parse_verify_args(&args).expect("valid args should parse");
        assert_eq!(parsed.iterations, 17);
    }

    #[test]
    fn parse_verify_args_rejects_invalid_iterations() {
        assert_eq!(
            parse_verify_args(&[
                "--key".to_string(),
                "k".to_string(),
                "--in".to_string(),
                "i".to_string(),
                "--sig".to_string(),
                "s".to_string(),
                "--iterations".to_string(),
                "nope".to_string(),
            ]),
            Err(CliError::InvalidIterations("nope".to_string()))
        );
    }

    #[test]
    fn parse_verify_args_requires_all_of_key_in_sig() {
        assert_eq!(parse_verify_args(&[]), Err(CliError::MissingFlag("key")));
        assert_eq!(
            parse_verify_args(&["--key".to_string(), "k".to_string()]),
            Err(CliError::MissingFlag("in"))
        );
        assert_eq!(
            parse_verify_args(&[
                "--key".to_string(),
                "k".to_string(),
                "--in".to_string(),
                "i".to_string(),
            ]),
            Err(CliError::MissingFlag("sig"))
        );
    }

    #[test]
    fn parse_verify_args_rejects_unknown_flag() {
        assert_eq!(
            parse_verify_args(&["--variant".to_string(), "256".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--variant".to_string(),
                suggestion: None,
            })
        );
    }

    /// Full golden path: `sign-keygen` -> `sign-pubkey` -> `sign` -> `verify`, entirely through
    /// the CLI layer, matching how a real user would actually use this feature.
    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn sign_verify_golden_path_round_trips() {
        let dir = TempDir::new("sign_golden_path");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("signing.key"),
        })
        .expect("sign-keygen should succeed");
        run_sign_pubkey_command(&SignPubkeyArgs {
            key_path: dir.file("signing.key"),
            out_path: dir.file("verifying.key"),
        })
        .expect("sign-pubkey should succeed");
        std::fs::write(dir.file("msg.bin"), b"a real message to sign").expect("write message");
        run_sign_command(&SignArgs {
            key_path: dir.file("signing.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig"),
            iterations: 1,
            force: false,
        })
        .expect("sign should succeed");

        let sig_bytes = std::fs::read(dir.file("msg.sig")).expect("read signature");
        assert_eq!(sig_bytes.len(), 42);
        let key_text = std::fs::read(dir.file("verifying.key")).expect("read verifying key");
        let (kind, key_bytes) = keyfile::decode(&key_text).expect("a typed key line");
        assert_eq!((kind, key_bytes.len()), (KeyKind::Sign163Public, 42));

        run_verify_command(&VerifyArgs {
            key_path: dir.file("verifying.key"),
            in_path: dir.file("msg.bin"),
            sig_path: dir.file("msg.sig"),
            iterations: 1,
        })
        .expect("verify should succeed on the real signature");
    }

    /// `m=257` sibling of `sign_verify_golden_path_round_trips`: `sign-keygen257` -> the same
    /// `sign-pubkey` -> `sign` -> `verify` commands (T-257) - proves each one's key-kind dispatch
    /// actually reaches the `crypto_sign257` path, not just that it compiles.
    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn sign_verify_golden_path_round_trips_m257() {
        let dir = TempDir::new("sign_golden_path_257");
        run_sign_keygen257_command(&SignKeygenArgs {
            out_path: dir.file("signing.key"),
        })
        .expect("sign-keygen257 should succeed");
        run_sign_pubkey_command(&SignPubkeyArgs {
            key_path: dir.file("signing.key"),
            out_path: dir.file("verifying.key"),
        })
        .expect("sign-pubkey should succeed on an m=257 key");
        std::fs::write(dir.file("msg.bin"), b"a real message to sign, m=257")
            .expect("write message");
        run_sign_command(&SignArgs {
            key_path: dir.file("signing.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig"),
            iterations: 1,
            force: false,
        })
        .expect("sign should succeed on an m=257 key");

        let sig_bytes = std::fs::read(dir.file("msg.sig")).expect("read signature");
        assert_eq!(sig_bytes.len(), 66);
        let key_text = std::fs::read(dir.file("verifying.key")).expect("read verifying key");
        let (kind, key_bytes) = keyfile::decode(&key_text).expect("a typed key line");
        assert_eq!((kind, key_bytes.len()), (KeyKind::Sign257Public, 66));

        run_verify_command(&VerifyArgs {
            key_path: dir.file("verifying.key"),
            in_path: dir.file("msg.bin"),
            sig_path: dir.file("msg.sig"),
            iterations: 1,
        })
        .expect("verify should succeed on the real m=257 signature via the shared verify command");
    }

    /// An `m=257` signature checked against an `m=163` key (mismatched curve, both individually
    /// well-formed) must fail cleanly - `verify` dispatches purely on `--key`'s own tag, so a
    /// wrong-curve signature just fails length validation inside that branch, same as any other
    /// malformed signature. Not a downgrade risk (`docs/DECISIONS.md` D-186 Decision 2's concern):
    /// there is no code path where a weaker curve's signature is silently accepted as if it were
    /// the stronger one, because the two curves' signatures are different byte lengths (42 vs 66)
    /// and `verify` never tries to reinterpret one as the other.
    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn verify_rejects_m257_signature_against_m163_key() {
        let dir = TempDir::new("verify_cross_curve");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("signing163.key"),
        })
        .expect("sign-keygen should succeed");
        run_sign_pubkey_command(&SignPubkeyArgs {
            key_path: dir.file("signing163.key"),
            out_path: dir.file("verifying163.key"),
        })
        .expect("sign-pubkey should succeed");
        run_sign_keygen257_command(&SignKeygenArgs {
            out_path: dir.file("signing257.key"),
        })
        .expect("sign-keygen257 should succeed");
        std::fs::write(dir.file("msg.bin"), b"cross-curve test message").expect("write message");
        run_sign_command(&SignArgs {
            key_path: dir.file("signing257.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig257"),
            iterations: 1,
            force: false,
        })
        .expect("sign should succeed on an m=257 key");

        assert!(matches!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying163.key"), // m=163 key
                in_path: dir.file("msg.bin"),
                sig_path: dir.file("msg.sig257"), // m=257 signature, wrong length for m=163
                iterations: 1,
            }),
            Err(CliError::WrongLength {
                what: LengthOf::Signature,
                expected: 42,
                ..
            })
        ));
    }

    /// `--iterations > 1` is the D-34 benchmark path (T-150) - the signature it actually writes
    /// must still be the real, verifiable one, not a placeholder from the timed loop. Deterministic
    /// signing (D-46) means every iteration produces the identical signature anyway, but this
    /// checks the written output end-to-end through `verify`, not just that signing didn't panic.
    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn sign_verify_with_iterations_still_round_trips() {
        let dir = TempDir::new("sign_verify_iterations");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("signing.key"),
        })
        .expect("sign-keygen should succeed");
        run_sign_pubkey_command(&SignPubkeyArgs {
            key_path: dir.file("signing.key"),
            out_path: dir.file("verifying.key"),
        })
        .expect("sign-pubkey should succeed");
        std::fs::write(dir.file("msg.bin"), b"benchmarked message").expect("write message");

        run_sign_command(&SignArgs {
            key_path: dir.file("signing.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig"),
            iterations: 25,
            force: false,
        })
        .expect("sign with iterations should succeed");

        run_verify_command(&VerifyArgs {
            key_path: dir.file("verifying.key"),
            in_path: dir.file("msg.bin"),
            sig_path: dir.file("msg.sig"),
            iterations: 25,
        })
        .expect("verify with iterations should succeed on the real signature");
    }

    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn run_sign_command_matches_dstu_core_directly() {
        let dir = TempDir::new("sign_matches_dstu_core");
        let signing_key = dstu_core::crypto_sign::SigningKey::generate()
            .expect("OS CSPRNG available in test environment");
        write_typed_key(
            &dir.file("signing.key"),
            KeyKind::Sign163Secret,
            &signing_key.to_bytes(),
        );
        std::fs::write(dir.file("msg.bin"), b"cross-check me").expect("write message");

        run_sign_command(&SignArgs {
            key_path: dir.file("signing.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig"),
            iterations: 1,
            force: false,
        })
        .expect("sign should succeed");

        let expected = signing_key.sign(b"cross-check me").to_bytes();
        let actual = std::fs::read(dir.file("msg.sig")).expect("read signature");
        assert_eq!(actual, expected);
    }

    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn run_sign_keygen_command_produces_distinct_keys_each_call() {
        let dir = TempDir::new("sign_keygen_distinct");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("key1.bin"),
        })
        .expect("first sign-keygen should succeed");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("key2.bin"),
        })
        .expect("second sign-keygen should succeed");

        let key1 = std::fs::read(dir.file("key1.bin")).expect("read key1");
        let key2 = std::fs::read(dir.file("key2.bin")).expect("read key2");
        assert_ne!(
            key1, key2,
            "two sign-keygen calls must not produce the same key"
        );
    }

    #[test]
    fn run_sign_keygen_command_directory_as_out_is_io_error_not_panic() {
        let dir = TempDir::new("sign_keygen_dir_out");
        std::fs::create_dir_all(dir.file("a_directory")).expect("create sub-directory");
        // OS-specific error, see run_keygen_command_directory_as_out_is_io_error_not_panic.
        let result = run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("a_directory"),
        });
        #[cfg(unix)]
        assert!(matches!(result, Err(CliError::KeyFileExists(_))));
        #[cfg(not(unix))]
        assert!(matches!(result, Err(CliError::Io { .. })));
    }

    #[test]
    fn run_sign_pubkey_command_directory_as_out_is_io_error_not_panic() {
        let dir = TempDir::new("sign_pubkey_dir_out");
        std::fs::create_dir_all(dir.file("a_directory")).expect("create sub-directory");
        write_typed_key(
            &dir.file("signing.key"),
            KeyKind::Sign163Secret,
            &small_signing_key(0x11),
        );
        // Written like a keygen since T-258 (D-214), so the same OS-specific error.
        let result = run_sign_pubkey_command(&SignPubkeyArgs {
            key_path: dir.file("signing.key"),
            out_path: dir.file("a_directory"),
        });
        #[cfg(unix)]
        assert!(matches!(result, Err(CliError::KeyFileExists(_))));
        #[cfg(not(unix))]
        assert!(matches!(result, Err(CliError::Io { .. })));
    }

    #[test]
    fn run_sign_pubkey_command_raw_key_file_is_rejected() {
        let dir = TempDir::new("sign_pubkey_wrong_len");
        std::fs::write(dir.file("signing.key"), [0x11u8; 20]).expect("write short key");
        assert_eq!(
            run_sign_pubkey_command(&SignPubkeyArgs {
                key_path: dir.file("signing.key"),
                out_path: dir.file("verifying.key"),
            }),
            Err(CliError::KeyFileNotTyped(dir.file("signing.key")))
        );
    }

    #[test]
    fn run_sign_command_raw_key_file_is_rejected() {
        let dir = TempDir::new("sign_wrong_len");
        std::fs::write(dir.file("signing.key"), [0x11u8; 20]).expect("write short key");
        std::fs::write(dir.file("msg.bin"), b"hello").expect("write message");
        assert_eq!(
            run_sign_command(&SignArgs {
                key_path: dir.file("signing.key"),
                in_path: dir.file("msg.bin"),
                out_path: dir.file("msg.sig"),
                iterations: 1,
                force: false,
            }),
            Err(CliError::KeyFileNotTyped(dir.file("signing.key")))
        );
    }

    /// A zero scalar is the right length (21 bytes) but not a valid private key - a distinct
    /// misuse case from the wrong-length one above, and one only `SignKeyInvalid` (not
    /// `WrongLength`) can report.
    #[test]
    fn run_sign_command_zero_key_is_rejected() {
        let dir = TempDir::new("sign_zero_key");
        write_typed_key(&dir.file("signing.key"), KeyKind::Sign163Secret, &[0u8; 21]);
        std::fs::write(dir.file("msg.bin"), b"hello").expect("write message");
        assert_eq!(
            run_sign_command(&SignArgs {
                key_path: dir.file("signing.key"),
                in_path: dir.file("msg.bin"),
                out_path: dir.file("msg.sig"),
                iterations: 1,
                force: false,
            }),
            Err(CliError::SignKeyInvalid)
        );
    }

    #[test]
    fn run_sign_command_nonexistent_input_is_io_error_not_panic() {
        let dir = TempDir::new("sign_missing_in");
        write_typed_key(
            &dir.file("signing.key"),
            KeyKind::Sign163Secret,
            &small_signing_key(0x11),
        );
        assert!(matches!(
            run_sign_command(&SignArgs {
                key_path: dir.file("signing.key"),
                in_path: dir.file("does_not_exist.bin"),
                out_path: dir.file("msg.sig"),
                iterations: 1,
                force: false,
            }),
            Err(CliError::Io { .. })
        ));
    }

    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn run_verify_command_rejects_tampered_message() {
        let dir = TempDir::new("verify_tampered_message");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("signing.key"),
        })
        .expect("sign-keygen should succeed");
        run_sign_pubkey_command(&SignPubkeyArgs {
            key_path: dir.file("signing.key"),
            out_path: dir.file("verifying.key"),
        })
        .expect("sign-pubkey should succeed");
        std::fs::write(dir.file("msg.bin"), b"original message").expect("write message");
        run_sign_command(&SignArgs {
            key_path: dir.file("signing.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig"),
            iterations: 1,
            force: false,
        })
        .expect("sign should succeed");

        std::fs::write(dir.file("msg.bin"), b"tampered message").expect("tamper the message");
        assert_eq!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying.key"),
                in_path: dir.file("msg.bin"),
                sig_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::SignVerifyFailed)
        );
    }

    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn run_verify_command_rejects_tampered_signature() {
        let dir = TempDir::new("verify_tampered_sig");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("signing.key"),
        })
        .expect("sign-keygen should succeed");
        run_sign_pubkey_command(&SignPubkeyArgs {
            key_path: dir.file("signing.key"),
            out_path: dir.file("verifying.key"),
        })
        .expect("sign-pubkey should succeed");
        std::fs::write(dir.file("msg.bin"), b"a message").expect("write message");
        run_sign_command(&SignArgs {
            key_path: dir.file("signing.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig"),
            iterations: 1,
            force: false,
        })
        .expect("sign should succeed");

        let mut sig = std::fs::read(dir.file("msg.sig")).expect("read signature");
        sig[41] ^= 1;
        std::fs::write(dir.file("msg.sig"), &sig).expect("tamper the signature");

        assert_eq!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying.key"),
                in_path: dir.file("msg.bin"),
                sig_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::SignVerifyFailed)
        );
    }

    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn run_verify_command_rejects_wrong_key() {
        let dir = TempDir::new("verify_wrong_key");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("signing_a.key"),
        })
        .expect("sign-keygen a should succeed");
        run_sign_keygen_command(&SignKeygenArgs {
            out_path: dir.file("signing_b.key"),
        })
        .expect("sign-keygen b should succeed");
        run_sign_pubkey_command(&SignPubkeyArgs {
            key_path: dir.file("signing_b.key"),
            out_path: dir.file("verifying_b.key"),
        })
        .expect("sign-pubkey b should succeed");
        std::fs::write(dir.file("msg.bin"), b"a message").expect("write message");
        run_sign_command(&SignArgs {
            key_path: dir.file("signing_a.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig"),
            iterations: 1,
            force: false,
        })
        .expect("sign with key a should succeed");

        assert_eq!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying_b.key"),
                in_path: dir.file("msg.bin"),
                sig_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::SignVerifyFailed)
        );
    }

    #[test]
    fn run_verify_command_raw_key_file_is_rejected() {
        let dir = TempDir::new("verify_wrong_key_len");
        let mut key = vec![dstu_core::crypto_sign::CurveId::M163.to_byte()];
        key.extend_from_slice(&[0x11u8; 41]); // one short of the 42 bytes m=163 needs
        std::fs::write(dir.file("verifying.key"), &key).expect("write short key");
        std::fs::write(dir.file("msg.bin"), b"hello").expect("write message");
        std::fs::write(dir.file("msg.sig"), [0x22u8; 42]).expect("write signature");
        assert_eq!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying.key"),
                in_path: dir.file("msg.bin"),
                sig_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::KeyFileNotTyped(dir.file("verifying.key")))
        );
    }

    #[test]
    fn run_verify_command_rejects_a_signing_key_by_kind() {
        let dir = TempDir::new("verify_signing_key");
        let signing = keyfile::encode(KeyKind::Sign163Secret, &small_signing_key(0x11));
        std::fs::write(dir.file("verifying.key"), signing.as_slice()).expect("write key");
        std::fs::write(dir.file("msg.bin"), b"hello").expect("write message");
        std::fs::write(dir.file("msg.sig"), [0x22u8; 42]).expect("write signature");
        assert_eq!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying.key"),
                in_path: dir.file("msg.bin"),
                sig_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::KeyKindMismatch {
                path: dir.file("verifying.key"),
                command: "verify",
                found: KeyKind::Sign163Secret,
                expected: &[KeyKind::Sign163Public, KeyKind::Sign257Public],
            })
        );
    }

    #[test]
    fn run_verify_command_wrong_signature_length_is_rejected() {
        let dir = TempDir::new("verify_wrong_sig_len");
        write_typed_key(
            &dir.file("verifying.key"),
            KeyKind::Sign163Public,
            &[0x11u8; 42],
        );
        std::fs::write(dir.file("msg.bin"), b"hello").expect("write message");
        std::fs::write(dir.file("msg.sig"), [0x22u8; 41]).expect("write short signature");
        assert_eq!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying.key"),
                in_path: dir.file("msg.bin"),
                sig_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::WrongLength {
                what: LengthOf::Signature,
                expected: 42,
                actual: 41,
            })
        );
    }

    #[test]
    fn run_verify_command_nonexistent_input_is_io_error_not_panic() {
        let dir = TempDir::new("verify_missing_in");
        write_typed_key(
            &dir.file("verifying.key"),
            KeyKind::Sign163Public,
            &[0x11u8; 42],
        );
        std::fs::write(dir.file("msg.sig"), [0x22u8; 42]).expect("write signature");
        assert!(matches!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying.key"),
                in_path: dir.file("does_not_exist.bin"),
                sig_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::Io { .. })
        ));
    }

    #[test]
    fn parse_box_keygen_args_happy_path() {
        let args = vec!["--out".to_string(), "box.key".to_string()];
        assert_eq!(
            parse_box_keygen_args(&args),
            Ok(BoxKeygenArgs {
                out_path: PathBuf::from("box.key"),
            })
        );
    }

    #[test]
    fn parse_box_keygen_args_requires_out() {
        assert_eq!(
            parse_box_keygen_args(&[]),
            Err(CliError::MissingFlag("out"))
        );
    }

    #[test]
    fn parse_box_pubkey_args_happy_path() {
        let args = vec![
            "--key".to_string(),
            "box.key".to_string(),
            "--out".to_string(),
            "box.pub".to_string(),
        ];
        assert_eq!(
            parse_box_pubkey_args(&args),
            Ok(BoxPubkeyArgs {
                key_path: PathBuf::from("box.key"),
                out_path: PathBuf::from("box.pub"),
            })
        );
    }

    #[test]
    fn parse_box_pubkey_args_requires_all_of_key_out() {
        assert_eq!(
            parse_box_pubkey_args(&[]),
            Err(CliError::MissingFlag("key"))
        );
        assert_eq!(
            parse_box_pubkey_args(&["--key".to_string(), "k".to_string()]),
            Err(CliError::MissingFlag("out"))
        );
    }

    #[test]
    fn parse_box_seal_args_happy_path() {
        let args = vec![
            "--key".to_string(),
            "recipient.pub".to_string(),
            "--in".to_string(),
            "msg.txt".to_string(),
            "--out".to_string(),
            "msg.box".to_string(),
        ];
        assert_eq!(
            parse_box_seal_args(&args),
            Ok(BoxSealArgs {
                key_path: PathBuf::from("recipient.pub"),
                in_path: PathBuf::from("msg.txt"),
                out_path: PathBuf::from("msg.box"),
                iterations: 1,
                force: false,
            })
        );
    }

    #[test]
    fn parse_box_seal_args_happy_path_with_iterations() {
        let args = vec![
            "--key".to_string(),
            "recipient.pub".to_string(),
            "--in".to_string(),
            "msg.txt".to_string(),
            "--out".to_string(),
            "msg.box".to_string(),
            "--iterations".to_string(),
            "17".to_string(),
        ];
        let parsed = parse_box_seal_args(&args).expect("valid args should parse");
        assert_eq!(parsed.iterations, 17);
    }

    #[test]
    fn parse_box_seal_args_rejects_invalid_iterations() {
        assert_eq!(
            parse_box_seal_args(&[
                "--key".to_string(),
                "k".to_string(),
                "--in".to_string(),
                "i".to_string(),
                "--out".to_string(),
                "o".to_string(),
                "--iterations".to_string(),
                "nope".to_string(),
            ]),
            Err(CliError::InvalidIterations("nope".to_string()))
        );
    }

    #[test]
    fn parse_box_seal_args_requires_all_of_key_in_out() {
        assert_eq!(parse_box_seal_args(&[]), Err(CliError::MissingFlag("key")));
        assert_eq!(
            parse_box_seal_args(&["--key".to_string(), "k".to_string()]),
            Err(CliError::MissingFlag("in"))
        );
        assert_eq!(
            parse_box_seal_args(&[
                "--key".to_string(),
                "k".to_string(),
                "--in".to_string(),
                "i".to_string(),
            ]),
            Err(CliError::MissingFlag("out"))
        );
    }

    #[test]
    fn parse_box_seal_args_rejects_unknown_flag() {
        assert_eq!(
            parse_box_seal_args(&["--variant".to_string(), "256".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--variant".to_string(),
                suggestion: None,
            })
        );
    }

    #[test]
    fn parse_box_open_args_happy_path() {
        let args = vec![
            "--key".to_string(),
            "box.key".to_string(),
            "--in".to_string(),
            "msg.box".to_string(),
            "--out".to_string(),
            "msg.txt".to_string(),
        ];
        assert_eq!(
            parse_box_open_args(&args),
            Ok(BoxOpenArgs {
                key_path: PathBuf::from("box.key"),
                in_path: PathBuf::from("msg.box"),
                out_path: PathBuf::from("msg.txt"),
                iterations: 1,
                force: false,
            })
        );
    }

    #[test]
    fn parse_box_open_args_requires_all_of_key_in_out() {
        assert_eq!(parse_box_open_args(&[]), Err(CliError::MissingFlag("key")));
    }

    /// Full golden path: `box-keygen` -> `box-pubkey` -> `box-seal` -> `box-open`, entirely
    /// through the CLI layer, matching how a real user would actually use this feature.
    #[cfg_attr(
        miri,
        ignore = "dstu9041's 256-iteration scalar-multiply ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177"
    )]
    #[test]
    fn box_seal_open_golden_path_round_trips() {
        let dir = TempDir::new("box_golden_path");
        run_box_keygen_command(&BoxKeygenArgs {
            out_path: dir.file("box.key"),
        })
        .expect("box-keygen should succeed");
        run_box_pubkey_command(&BoxPubkeyArgs {
            key_path: dir.file("box.key"),
            out_path: dir.file("box.pub"),
        })
        .expect("box-pubkey should succeed");
        std::fs::write(dir.file("msg.txt"), b"a message for the recipient only")
            .expect("write message");

        run_box_seal_command(&BoxSealArgs {
            key_path: dir.file("box.pub"),
            in_path: dir.file("msg.txt"),
            out_path: dir.file("msg.box"),
            iterations: 1,
            force: false,
        })
        .expect("box-seal should succeed");

        let sealed_bytes = std::fs::read(dir.file("msg.box")).expect("read sealed output");
        assert_eq!(sealed_bytes.len(), 1 + 128 + 32 + 32 + 16); // version + KEM + header + message + tag
        assert_eq!(sealed_bytes[0], CONTAINER_FORMAT_VERSION);
        let pub_text = std::fs::read(dir.file("box.pub")).expect("read public key");
        assert_eq!(
            keyfile::decode(&pub_text).map(|(kind, _)| kind),
            Ok(KeyKind::Box256Public)
        );

        run_box_open_command(&BoxOpenArgs {
            key_path: dir.file("box.key"),
            in_path: dir.file("msg.box"),
            out_path: dir.file("msg.out"),
            iterations: 1,
            force: false,
        })
        .expect("box-open should succeed on the real sealed output");

        let opened = std::fs::read(dir.file("msg.out")).expect("read opened output");
        assert_eq!(opened, b"a message for the recipient only");
    }

    /// `--iterations > 1` is the D-34/T-179 benchmark path - the sealed/opened output it actually
    /// writes must still be the real, round-trippable one, not a placeholder from the timed loop.
    #[cfg_attr(
        miri,
        ignore = "dstu9041's 256-iteration scalar-multiply ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177"
    )]
    #[test]
    fn box_seal_open_with_iterations_still_round_trips() {
        let dir = TempDir::new("box_iterations");
        run_box_keygen_command(&BoxKeygenArgs {
            out_path: dir.file("box.key"),
        })
        .expect("box-keygen should succeed");
        run_box_pubkey_command(&BoxPubkeyArgs {
            key_path: dir.file("box.key"),
            out_path: dir.file("box.pub"),
        })
        .expect("box-pubkey should succeed");
        std::fs::write(dir.file("msg.txt"), b"benchmarked message").expect("write message");

        run_box_seal_command(&BoxSealArgs {
            key_path: dir.file("box.pub"),
            in_path: dir.file("msg.txt"),
            out_path: dir.file("msg.box"),
            iterations: 5,
            force: false,
        })
        .expect("box-seal with iterations should succeed");

        run_box_open_command(&BoxOpenArgs {
            key_path: dir.file("box.key"),
            in_path: dir.file("msg.box"),
            out_path: dir.file("msg.out"),
            iterations: 5,
            force: false,
        })
        .expect("box-open with iterations should succeed on the real sealed output");

        let opened = std::fs::read(dir.file("msg.out")).expect("read opened output");
        assert_eq!(opened, b"benchmarked message");
    }

    #[cfg_attr(
        miri,
        ignore = "dstu9041's 256-iteration scalar-multiply ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177"
    )]
    #[test]
    fn run_box_open_command_rejects_wrong_secret_key() {
        let dir = TempDir::new("box_wrong_key");
        run_box_keygen_command(&BoxKeygenArgs {
            out_path: dir.file("box.key"),
        })
        .expect("box-keygen should succeed");
        run_box_keygen_command(&BoxKeygenArgs {
            out_path: dir.file("other.key"),
        })
        .expect("box-keygen should succeed");
        run_box_pubkey_command(&BoxPubkeyArgs {
            key_path: dir.file("box.key"),
            out_path: dir.file("box.pub"),
        })
        .expect("box-pubkey should succeed");
        std::fs::write(dir.file("msg.txt"), b"secret").expect("write message");
        run_box_seal_command(&BoxSealArgs {
            key_path: dir.file("box.pub"),
            in_path: dir.file("msg.txt"),
            out_path: dir.file("msg.box"),
            iterations: 1,
            force: false,
        })
        .expect("box-seal should succeed");

        assert_eq!(
            run_box_open_command(&BoxOpenArgs {
                key_path: dir.file("other.key"),
                in_path: dir.file("msg.box"),
                out_path: dir.file("msg.out"),
                iterations: 1,
                force: false,
            }),
            Err(CliError::BoxOpenFailed("l(p)=256"))
        );
    }

    #[cfg_attr(
        miri,
        ignore = "dstu9041's 256-iteration scalar-multiply ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177"
    )]
    #[test]
    fn run_box_open_command_rejects_tampered_sealed_file() {
        let dir = TempDir::new("box_tampered");
        run_box_keygen_command(&BoxKeygenArgs {
            out_path: dir.file("box.key"),
        })
        .expect("box-keygen should succeed");
        run_box_pubkey_command(&BoxPubkeyArgs {
            key_path: dir.file("box.key"),
            out_path: dir.file("box.pub"),
        })
        .expect("box-pubkey should succeed");
        std::fs::write(dir.file("msg.txt"), b"secret").expect("write message");
        run_box_seal_command(&BoxSealArgs {
            key_path: dir.file("box.pub"),
            in_path: dir.file("msg.txt"),
            out_path: dir.file("msg.box"),
            iterations: 1,
            force: false,
        })
        .expect("box-seal should succeed");

        let mut sealed = std::fs::read(dir.file("msg.box")).expect("read sealed output");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        std::fs::write(dir.file("msg.box"), &sealed).expect("write tampered output");

        assert_eq!(
            run_box_open_command(&BoxOpenArgs {
                key_path: dir.file("box.key"),
                in_path: dir.file("msg.box"),
                out_path: dir.file("msg.out"),
                iterations: 1,
                force: false,
            }),
            Err(CliError::BoxOpenFailed("l(p)=256"))
        );
    }

    #[test]
    fn run_box_open_command_truncated_input_is_rejected() {
        let dir = TempDir::new("box_truncated");
        run_box_keygen_command(&BoxKeygenArgs {
            out_path: dir.file("box.key"),
        })
        .expect("box-keygen should succeed");
        std::fs::write(dir.file("msg.box"), [0u8; 10]).expect("write short input");

        assert_eq!(
            run_box_open_command(&BoxOpenArgs {
                key_path: dir.file("box.key"),
                in_path: dir.file("msg.box"),
                out_path: dir.file("msg.out"),
                iterations: 1,
                force: false,
            }),
            Err(CliError::BoxOpenTruncated("l(p)=256"))
        );
    }

    #[test]
    fn run_box_pubkey_command_raw_key_file_is_rejected() {
        let dir = TempDir::new("box_pubkey_wrong_len");
        std::fs::write(dir.file("box.key"), [0x11u8; 31]).expect("write short key");
        assert_eq!(
            run_box_pubkey_command(&BoxPubkeyArgs {
                key_path: dir.file("box.key"),
                out_path: dir.file("box.pub"),
            }),
            Err(CliError::KeyFileNotTyped(dir.file("box.key")))
        );
    }

    #[test]
    fn run_box_pubkey_command_zero_key_is_rejected() {
        let dir = TempDir::new("box_pubkey_zero_key");
        write_typed_key(&dir.file("box.key"), KeyKind::Box256Secret, &[0u8; 32]);
        assert_eq!(
            run_box_pubkey_command(&BoxPubkeyArgs {
                key_path: dir.file("box.key"),
                out_path: dir.file("box.pub"),
            }),
            Err(CliError::BoxKeyInvalid)
        );
    }

    #[test]
    fn run_box_keygen_command_produces_distinct_keys_each_call() {
        let dir = TempDir::new("box_keygen_distinct");
        run_box_keygen_command(&BoxKeygenArgs {
            out_path: dir.file("key1.bin"),
        })
        .expect("first box-keygen should succeed");
        run_box_keygen_command(&BoxKeygenArgs {
            out_path: dir.file("key2.bin"),
        })
        .expect("second box-keygen should succeed");

        let key1 = std::fs::read(dir.file("key1.bin")).expect("read key1");
        let key2 = std::fs::read(dir.file("key2.bin")).expect("read key2");
        assert_ne!(
            key1, key2,
            "two box-keygen calls must not produce the same key"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "dstu9041's 256-iteration scalar-multiply ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177"
    )]
    #[test]
    fn box_dispatch_through_top_level_run() {
        let dir = TempDir::new("box_dispatch");
        let path = |p: &std::path::Path| p.to_str().expect("valid utf-8 path").to_string();

        let keygen: Vec<String> = ["box-keygen", "--out", &path(&dir.file("box.key"))]
            .into_iter()
            .map(String::from)
            .collect();
        run(&keygen).expect("box-keygen dispatch should succeed");

        let pubkey: Vec<String> = [
            "box-pubkey",
            "--key",
            &path(&dir.file("box.key")),
            "--out",
            &path(&dir.file("box.pub")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&pubkey).expect("box-pubkey dispatch should succeed");

        std::fs::write(dir.file("msg.txt"), b"dispatch me").expect("write message");
        let seal: Vec<String> = [
            "box-seal",
            "--key",
            &path(&dir.file("box.pub")),
            "--in",
            &path(&dir.file("msg.txt")),
            "--out",
            &path(&dir.file("msg.box")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&seal).expect("box-seal dispatch should succeed");

        let open: Vec<String> = [
            "box-open",
            "--key",
            &path(&dir.file("box.key")),
            "--in",
            &path(&dir.file("msg.box")),
            "--out",
            &path(&dir.file("msg.out")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&open).expect("box-open dispatch should succeed");

        let opened = std::fs::read(dir.file("msg.out")).expect("read opened output");
        assert_eq!(opened, b"dispatch me");
    }

    #[cfg_attr(
        miri,
        ignore = "dstu9041's 512-iteration scalar-multiply ladders are too slow to interpret under Miri - see docs/TASKS.md T-100/T-177/T-193"
    )]
    #[test]
    fn box512_dispatch_through_top_level_run() {
        let dir = TempDir::new("box512_dispatch");
        let path = |p: &std::path::Path| p.to_str().expect("valid utf-8 path").to_string();

        let keygen: Vec<String> = ["box-keygen512", "--out", &path(&dir.file("box.key"))]
            .into_iter()
            .map(String::from)
            .collect();
        run(&keygen).expect("box-keygen512 dispatch should succeed");

        let pubkey: Vec<String> = [
            "box-pubkey",
            "--key",
            &path(&dir.file("box.key")),
            "--out",
            &path(&dir.file("box.pub")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&pubkey).expect("box-pubkey dispatch should succeed on the other curve's key");

        std::fs::write(dir.file("msg.txt"), b"dispatch me 512").expect("write message");
        let seal: Vec<String> = [
            "box-seal",
            "--key",
            &path(&dir.file("box.pub")),
            "--in",
            &path(&dir.file("msg.txt")),
            "--out",
            &path(&dir.file("msg.box")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&seal).expect("box-seal dispatch should succeed on the other curve's key");

        let open: Vec<String> = [
            "box-open",
            "--key",
            &path(&dir.file("box.key")),
            "--in",
            &path(&dir.file("msg.box")),
            "--out",
            &path(&dir.file("msg.out")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&open).expect("box-open dispatch should succeed on the other curve's key");

        let opened = std::fs::read(dir.file("msg.out")).expect("read opened output");
        assert_eq!(opened, b"dispatch me 512");
    }

    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn sign_verify_dispatch_through_top_level_run() {
        let dir = TempDir::new("sign_verify_dispatch");
        let path = |p: &std::path::Path| p.to_str().expect("valid utf-8 path").to_string();

        let keygen: Vec<String> = ["sign-keygen", "--out", &path(&dir.file("signing.key"))]
            .into_iter()
            .map(String::from)
            .collect();
        run(&keygen).expect("sign-keygen dispatch should succeed");

        let pubkey: Vec<String> = [
            "sign-pubkey",
            "--key",
            &path(&dir.file("signing.key")),
            "--out",
            &path(&dir.file("verifying.key")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&pubkey).expect("sign-pubkey dispatch should succeed");

        std::fs::write(dir.file("msg.bin"), b"dispatch me").expect("write message");
        let sign: Vec<String> = [
            "sign",
            "--key",
            &path(&dir.file("signing.key")),
            "--in",
            &path(&dir.file("msg.bin")),
            "--out",
            &path(&dir.file("msg.sig")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&sign).expect("sign dispatch should succeed");

        let verify: Vec<String> = [
            "verify",
            "--key",
            &path(&dir.file("verifying.key")),
            "--in",
            &path(&dir.file("msg.bin")),
            "--sig",
            &path(&dir.file("msg.sig")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&verify).expect("verify dispatch should succeed on a real signature");
    }

    /// `m=257` sibling of `sign_verify_dispatch_through_top_level_run`, through `run()` itself
    /// (real command-line tokens, not the internal `run_*_command` functions directly) - proves
    /// `sign-keygen257` is reachable and that the *same* `sign-pubkey`/`sign`/`verify` tokens used
    /// for `m=163` above also handle an `m=257` key (T-257).
    #[cfg_attr(
        miri,
        ignore = "Point::scalar_multiply's 257-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn sign_verify_dispatch_through_top_level_run_m257() {
        let dir = TempDir::new("sign_verify_dispatch_257");
        let path = |p: &std::path::Path| p.to_str().expect("valid utf-8 path").to_string();

        let keygen: Vec<String> = ["sign-keygen257", "--out", &path(&dir.file("signing.key"))]
            .into_iter()
            .map(String::from)
            .collect();
        run(&keygen).expect("sign-keygen257 dispatch should succeed");

        let pubkey: Vec<String> = [
            "sign-pubkey",
            "--key",
            &path(&dir.file("signing.key")),
            "--out",
            &path(&dir.file("verifying.key")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&pubkey).expect("sign-pubkey dispatch should succeed on the other curve's key");

        std::fs::write(dir.file("msg.bin"), b"dispatch me, m=257").expect("write message");
        let sign: Vec<String> = [
            "sign",
            "--key",
            &path(&dir.file("signing.key")),
            "--in",
            &path(&dir.file("msg.bin")),
            "--out",
            &path(&dir.file("msg.sig")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&sign).expect("sign dispatch should succeed on an m=257 key");

        let verify: Vec<String> = [
            "verify",
            "--key",
            &path(&dir.file("verifying.key")),
            "--in",
            &path(&dir.file("msg.bin")),
            "--sig",
            &path(&dir.file("msg.sig")),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&verify).expect("verify dispatch should succeed on a real m=257 signature");
    }

    #[test]
    fn run_unknown_sign_family_subcommand_is_rejected() {
        // Unlike `kalyna-gcm`/etc., `sign`/`verify`/`sign-keygen`/`sign-pubkey` are flat top-level
        // commands with no sub-subcommand - an unrecognized flag surfaces as `UnknownFlag`, not
        // `UnknownCommand`, since `dispatch_sign_command` hands `rest` straight to `parse_*_args`.
        assert_eq!(
            run(&["sign".to_string(), "--bogus".to_string()]),
            Err(CliError::UnknownFlag {
                flag: "--bogus".to_string(),
                suggestion: None,
            })
        );
    }

    // T-241: every secret-key command, as (label, run-with-this-out-path).
    fn secret_keygens() -> Vec<(&'static str, Box<dyn Fn(PathBuf) -> Result<(), CliError>>)> {
        vec![
            (
                "keygen",
                Box::new(|out_path| run_keygen_command(&KeygenArgs { out_path })),
            ),
            (
                "sign-keygen",
                Box::new(|out_path| run_sign_keygen_command(&SignKeygenArgs { out_path })),
            ),
            (
                "sign-keygen257",
                Box::new(|out_path| run_sign_keygen257_command(&SignKeygenArgs { out_path })),
            ),
            (
                "box-keygen",
                Box::new(|out_path| run_box_keygen_command(&BoxKeygenArgs { out_path })),
            ),
            (
                "box-keygen512",
                Box::new(|out_path| run_box512_keygen_command(&BoxKeygenArgs { out_path })),
            ),
        ]
    }

    // T-241 (owner decision 2026-09-23): a keygen run must never destroy an existing key file.
    #[test]
    fn every_keygen_refuses_an_existing_out_and_leaves_it_untouched() {
        let dir = TempDir::new("t241_keygen_exists");
        for (label, keygen) in secret_keygens() {
            let out = dir.file(&format!("{label}.key"));
            std::fs::write(&out, b"an existing key").expect("write existing key");
            assert_eq!(
                keygen(out.clone()),
                Err(CliError::KeyFileExists(out.clone())),
                "{label}"
            );
            assert_eq!(
                std::fs::read(&out).expect("read"),
                b"an existing key",
                "{label}"
            );
        }
        let names: Vec<_> = std::fs::read_dir(&dir.0)
            .expect("list dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            names.len(),
            secret_keygens().len(),
            "no stray files: {names:?}"
        );
    }

    #[test]
    fn temp_path_beside_is_unpredictable_and_stays_in_the_same_directory() {
        let dir = TempDir::new("t241_temp_name");
        let out = dir.file("out.bin");
        let a = temp_path_beside(&out).expect("temp path");
        let b = temp_path_beside(&out).expect("temp path");
        assert_ne!(a, b);
        assert_eq!(a.parent(), out.parent());
        assert_eq!(b.parent(), out.parent());
    }

    #[test]
    fn create_private_new_refuses_an_existing_path() {
        let dir = TempDir::new("t241_create_new");
        let path = dir.file("taken.bin");
        std::fs::write(&path, b"keep me").expect("write");
        let err = create_private_new(&path).expect_err("must not open an existing path");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read"), b"keep me");
    }

    #[cfg(unix)]
    #[test]
    fn every_keygen_writes_its_key_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("t241_keygen_mode");
        for (label, keygen) in secret_keygens() {
            let out = dir.file(&format!("{label}.key"));
            keygen(out.clone()).expect("keygen");
            let mode = std::fs::metadata(&out).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{label}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn keygen_refuses_a_symlink_at_out_and_leaves_its_target_untouched() {
        let dir = TempDir::new("t241_keygen_symlink");
        let target = dir.file("victim.txt");
        std::fs::write(&target, b"not a key").expect("write target");
        let link = dir.file("key.bin");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(run_keygen_command(&KeygenArgs {
            out_path: link.clone()
        })
        .is_err());
        assert_eq!(std::fs::read(&target).expect("read"), b"not a key");
    }

    #[cfg(unix)]
    #[test]
    fn decrypt_output_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("t241_decrypt_mode");
        write_typed_key(&dir.file("key.bin"), KeyKind::Symmetric, &[0x42u8; 32]);
        std::fs::write(dir.file("pt.bin"), b"secret plaintext").expect("write input");
        let enc = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("pt.bin"),
            out_path: dir.file("ct.bin"),
            force: false,
        };
        run_secretstream_command(false, &enc).expect("encrypt");
        let dec = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("ct.bin"),
            out_path: dir.file("out.bin"),
            force: false,
        };
        run_secretstream_command(true, &dec).expect("decrypt");
        let mode = std::fs::metadata(dir.file("out.bin"))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // T-255: strict parsing, help, exit codes.

    #[test]
    fn wrong_length_exit_class_pins_every_length_kind() {
        let class = |what| {
            CliError::WrongLength {
                what,
                expected: 1,
                actual: 0,
            }
            .exit_code()
        };
        for what in [
            LengthOf::Key,
            LengthOf::Nonce,
            LengthOf::Tweak,
            LengthOf::Iv,
            LengthOf::SigningKey,
            LengthOf::VerifyingKey,
            LengthOf::BoxSecretKey,
            LengthOf::BoxPublicKey,
            LengthOf::Box512SecretKey,
            LengthOf::Box512PublicKey,
        ] {
            assert_eq!(class(what), 3, "{what}");
        }
        for what in [LengthOf::InputBlock, LengthOf::Signature, LengthOf::Tag] {
            assert_eq!(class(what), 1, "{what}");
        }
    }

    #[test]
    fn edit_distance_counts_a_transposition_as_one_edit() {
        assert_eq!(edit_distance("encrypt", "encrypt"), 0);
        assert_eq!(edit_distance("encrpyt", "encrypt"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", ""), 3);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn suggest_needs_a_plausible_typo() {
        let names = ["encrypt", "decrypt", "hash"];
        assert_eq!(suggest("encrpyt", names), Some("encrypt"));
        assert_eq!(suggest("hsah", names), Some("hash"));
        assert_eq!(suggest("foo", names), None);
        assert_eq!(suggest("--kye", ["--key", "--in"]), Some("--key"));
        assert_eq!(suggest("--zzzzzz", ["--key", "--in", "--help"]), None);
    }

    #[test]
    fn scan_rejects_repeats_missing_values_and_positionals() {
        let args = |v: &[&str]| v.iter().map(ToString::to_string).collect::<Vec<_>>();
        let scan = |v: &[&str]| ArgScanner::scan(&args(v), &["--in", "--out"], &["--raw"]).err();
        assert_eq!(
            scan(&["--in", "a", "--in=b"]),
            Some(CliError::RepeatedFlag("--in"))
        );
        assert_eq!(
            scan(&["--raw", "--raw"]),
            Some(CliError::RepeatedFlag("--raw"))
        );
        assert_eq!(scan(&["--in"]), Some(CliError::MissingValue("--in")));
        assert_eq!(
            scan(&["--in", "--out", "x"]),
            Some(CliError::MissingValue("--in"))
        );
        assert_eq!(scan(&["--in="]), Some(CliError::MissingValue("--in")));
        assert_eq!(
            scan(&["--raw=yes"]),
            Some(CliError::FlagTakesNoValue("--raw"))
        );
        assert_eq!(
            scan(&["file.txt"]),
            Some(CliError::UnexpectedArgument("file.txt".to_string()))
        );
        assert_eq!(
            scan(&["--otu", "x"]),
            Some(CliError::UnknownFlag {
                flag: "--otu".to_string(),
                suggestion: Some("--out"),
            })
        );
        let ok = ArgScanner::scan(
            &args(&["--in=--odd", "--out", "o"]),
            &["--in", "--out"],
            &[],
        )
        .expect("scan");
        assert_eq!(ok.path("--in"), Ok(PathBuf::from("--odd")));
    }

    #[test]
    fn every_command_in_the_table_has_its_own_help_and_dispatches() {
        for (name, help) in COMMANDS {
            assert_ne!(*help, TOP_LEVEL_HELP, "{name}");
            assert!(help.starts_with(&format!("uacrypt {name} ")), "{name}");
            assert_eq!(
                run(&[(*name).to_string(), "--help".to_string()]),
                Ok(()),
                "{name}"
            );
        }
    }

    #[test]
    fn every_command_run_dispatches_is_in_the_table() {
        let src = include_str!("lib.rs");
        let start = src.find("pub fn run(args: &[String])").expect("run");
        let body = &src[start
            ..start
                + src[start..]
                    .find(
                        "
}
",
                    )
                    .expect("end of run")];
        // Top-level arms only (8-space indent); deeper `Some("encrypt")` lines are subcommands.
        let mut found = Vec::new();
        for line in body.lines() {
            let Some(arm) = line.strip_prefix("        Some(") else {
                continue;
            };
            let head = arm.split("=>").next().unwrap_or_default();
            found.extend(head.split('"').skip(1).step_by(2).map(str::to_string));
        }
        assert!(found.len() > 20, "{found:?}");
        for name in found.iter().filter(|n| *n != "help") {
            assert!(
                COMMANDS.iter().any(|(n, _)| n == name),
                "`{name}` is dispatched by run but missing from COMMANDS"
            );
        }
    }

    #[test]
    fn help_texts_carry_no_internal_references_or_benchmark_flags() {
        let has_ref = |text: &str| {
            text.as_bytes()
                .windows(3)
                .any(|w| (w[0] == b'D' || w[0] == b'T') && w[1] == b'-' && w[2].is_ascii_digit())
        };
        assert!(!has_ref(TOP_LEVEL_HELP));
        for help in [
            KEYGEN_HELP,
            ENCRYPT_HELP,
            DECRYPT_HELP,
            HASH_HELP,
            SIGN_KEYGEN_HELP,
            SIGN_PUBKEY_HELP,
            SIGN_HELP,
            VERIFY_HELP,
            SIGN_KEYGEN257_HELP,
            BOX_KEYGEN_HELP,
            BOX_PUBKEY_HELP,
            BOX_SEAL_HELP,
            BOX_OPEN_HELP,
            BOX_KEYGEN512_HELP,
        ] {
            assert!(!has_ref(help), "{help}");
            assert!(!help.contains("--iterations"), "{help}");
        }
    }

    #[test]
    fn removed_commands_point_to_real_commands_and_are_not_commands_themselves() {
        for (old, replacement) in REMOVED_COMMANDS {
            assert!(command_help(replacement).is_some(), "{replacement}");
            assert!(command_help(old).is_none(), "{old}");
            assert_eq!(
                unknown_command(old).exit_code(),
                2,
                "{old} must be a usage error"
            );
            assert!(unknown_command(old)
                .to_string()
                .contains(&format!("`uacrypt {replacement}`")));
        }
    }

    #[test]
    fn key_file_exists_message_has_no_run_of_spaces() {
        let msg = CliError::KeyFileExists(PathBuf::from("k.bin")).to_string();
        assert!(!msg.contains("  "), "{msg}");
    }
}
