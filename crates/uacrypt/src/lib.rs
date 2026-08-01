#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `uacrypt`'s testable logic - `main.rs` is a thin wrapper that calls [`run`] and maps the
//! result to a process exit code.
//!
//! **Pre-release and provisional - not independently audited.** The Kalyna-alone mode of
//! operation backing `encrypt`/`decrypt`/`kalyna-ccm` rests on an adopted assumption, not a
//! confirmation against the primary DSTU 7624:2014 text (`docs/DECISIONS.md` D-05). `strumok-crypt` is
//! UAPKI-attributed only, not confirmed against the primary DSTU 8845:2019 text (`docs/DECISIONS.md`
//! D-15). See `docs/SECURITY.md`/`docs/DECISIONS.md` in the project repository for the full threat model,
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
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    UnknownCommand(String),
    UnknownVariant(String),
    MissingFlag(&'static str),
    UnknownFlag(String),
    InvalidIterations(String),
    Io {
        path: PathBuf,
        message: String,
    },
    WrongLength {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
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
    SecretstreamTruncated,
    SecretstreamVerifyFailed,
    SecretstreamUnknownTag,
    SecretstreamTrailingData,
    SecretstreamChunkTooLarge,
    SignKeyInvalid,
    SignVerifyFailed,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::UnknownCommand(c) => write!(f, "unknown command: {c}"),
            CliError::UnknownVariant(v) => write!(
                f,
                "unknown variant: {v} (expected one of 128-128, 128-256, 256-256, 256-512, 512-512)"
            ),
            CliError::MissingFlag(name) => write!(f, "missing required flag: --{name}"),
            CliError::UnknownFlag(f2) => write!(f, "unknown flag: {f2}"),
            CliError::InvalidIterations(v) => write!(f, "invalid --iterations value: {v}"),
            CliError::Io { path, message } => {
                write!(f, "{}: {message}", path.display())
            }
            CliError::WrongLength {
                what,
                expected,
                actual,
            } => write!(f, "{what} must be exactly {expected} bytes, got {actual}"),
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
            CliError::SignKeyInvalid => write!(
                f,
                "--key is not a valid signing key (must be nonzero and less than the curve order - see uacrypt sign-keygen)"
            ),
            CliError::SignVerifyFailed => write!(
                f,
                "verify: signature does not verify - message, signature, or key do not match"
            ),
        }
    }
}

impl From<dstu_core::hazmat::kalyna_ccm::CcmError> for CliError {
    fn from(err: dstu_core::hazmat::kalyna_ccm::CcmError) -> Self {
        match err {
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
            SecretstreamError::InvalidLength | SecretstreamError::StreamFinalized => unreachable!(
                "uacrypt always supplies matching buffer lengths and never calls push/pull \
                 again after a Final chunk"
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

#[derive(Debug, PartialEq, Eq)]
pub struct BlockArgs {
    pub variant: KalynaVariant,
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
    pub raw_schedule: bool,
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
    let mut variant = None;
    let mut key_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut iterations = 1u32;
    let mut raw_schedule = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant = Some(
                    KalynaVariant::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?,
                );
                i += 2;
            }
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            "--raw-schedule" => {
                raw_schedule = true;
                i += 1;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(BlockArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
        iterations,
        raw_schedule,
    })
}

fn read_exact_file(
    path: &PathBuf,
    what: &'static str,
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
    let key = read_exact_file(&args.key_path, "key", args.variant.key_len())?;
    let expected_in_len = args.variant.block_len();
    let input = read_exact_file(&args.in_path, "input block", expected_in_len)?;

    let (output, elapsed) = run_block_op(
        args.variant,
        &key,
        &input,
        decrypt,
        args.iterations.max(1),
        args.raw_schedule,
    );

    std::fs::write(&args.out_path, &output).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })?;

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
    let mut variant = None;
    let mut key_path = None;
    let mut nonce_path = None;
    let mut aad_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut tag_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant = Some(
                    KalynaVariant::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?,
                );
                i += 2;
            }
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--nonce" => {
                nonce_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("nonce"))?,
                ));
                i += 2;
            }
            "--aad" => {
                aad_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("aad"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--tag" => {
                tag_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("tag"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(CcmArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        nonce_path: nonce_path.ok_or(CliError::MissingFlag("nonce"))?,
        aad_path,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
        tag_path: tag_path.ok_or(CliError::MissingFlag("tag"))?,
        iterations,
    })
}

/// Runs `kalyna-ccm encrypt`/`decrypt` - see `hazmat::kalyna_ccm`'s module doc comment for the
/// construction's provisional status and sourced 255-byte plaintext/AAD limit. Encrypt writes
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
    let key = read_exact_file(&args.key_path, "key", args.variant.key_len())?;
    let nonce = if decrypt {
        read_exact_file(&args.nonce_path, "nonce", args.variant.block_len())?
    } else {
        let mut generated = vec![0u8; args.variant.block_len()];
        dstu_core::randombytes::randombytes_buf(&mut generated)
            .map_err(|e| CliError::Random(e.to_string()))?;
        std::fs::write(&args.nonce_path, &generated).map_err(|e| CliError::Io {
            path: args.nonce_path.clone(),
            message: e.to_string(),
        })?;
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
                let tag = read_exact_file(&args.tag_path, "tag", $tag_len)?;
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

    std::fs::write(&args.out_path, &output).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })?;
    if let Some(tag) = tag {
        std::fs::write(&args.tag_path, &tag).map_err(|e| CliError::Io {
            path: args.tag_path.clone(),
            message: e.to_string(),
        })?;
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
}

/// Parses `kalyna-gcm encrypt`/`decrypt`'s flags - same shape as [`parse_ccm_args`].
///
/// # Errors
///
/// Same cases as [`parse_ccm_args`].
pub fn parse_gcm_args(args: &[String]) -> Result<GcmArgs, CliError> {
    let mut variant = None;
    let mut key_path = None;
    let mut nonce_path = None;
    let mut aad_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut tag_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant = Some(
                    KalynaVariant::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?,
                );
                i += 2;
            }
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--nonce" => {
                nonce_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("nonce"))?,
                ));
                i += 2;
            }
            "--aad" => {
                aad_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("aad"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--tag" => {
                tag_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("tag"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(GcmArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        nonce_path: nonce_path.ok_or(CliError::MissingFlag("nonce"))?,
        aad_path,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
        tag_path: tag_path.ok_or(CliError::MissingFlag("tag"))?,
        iterations,
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
    let key = read_exact_file(&args.key_path, "key", args.variant.key_len())?;
    let nonce = if decrypt {
        read_exact_file(&args.nonce_path, "nonce", args.variant.block_len())?
    } else {
        let mut generated = vec![0u8; args.variant.block_len()];
        dstu_core::randombytes::randombytes_buf(&mut generated)
            .map_err(|e| CliError::Random(e.to_string()))?;
        std::fs::write(&args.nonce_path, &generated).map_err(|e| CliError::Io {
            path: args.nonce_path.clone(),
            message: e.to_string(),
        })?;
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
                Some(read_exact_file(&args.tag_path, "tag", $block_len)?)
            } else {
                None
            };

            let start = std::time::Instant::now();
            let mut buf = vec![0u8; input.len()];
            let mut tag_out = [0u8; $block_len];
            for _ in 0..iterations {
                if decrypt {
                    cipher
                        .decrypt(&nonce_arr, &aad, &input, tag_in.as_ref().unwrap(), &mut buf)
                        .map_err(|_| CliError::GcmVerifyFailed)?;
                } else {
                    tag_out = cipher
                        .encrypt(&nonce_arr, &aad, &input, &mut buf)
                        .expect("ciphertext_out.len() == plaintext.len() by construction");
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

    std::fs::write(&args.out_path, &output).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })?;
    if let Some(tag) = tag {
        std::fs::write(&args.tag_path, &tag).map_err(|e| CliError::Io {
            path: args.tag_path.clone(),
            message: e.to_string(),
        })?;
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
    let mut variant = None;
    let mut key_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut tag_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant = Some(
                    KalynaVariant::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?,
                );
                i += 2;
            }
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--tag" => {
                tag_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("tag"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(CmacArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path,
        tag_path,
        iterations,
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
    let key = read_exact_file(&args.key_path, "key", args.variant.key_len())?;
    let message = std::fs::read(&args.in_path).map_err(|e| CliError::Io {
        path: args.in_path.clone(),
        message: e.to_string(),
    })?;
    let tag_in = if verify {
        Some(read_exact_file(
            args.tag_path.as_ref().ok_or(CliError::MissingFlag("tag"))?,
            "tag",
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
                    <$mac>::verify_with_cipher(&cipher, &message, &expected)
                        .map_err(|_| CliError::CmacVerifyFailed)?;
                } else {
                    tag = <$mac>::mac_with_cipher(&cipher, &message);
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

    if !verify {
        let out_path = args.out_path.as_ref().ok_or(CliError::MissingFlag("out"))?;
        std::fs::write(out_path, tag).map_err(|e| CliError::Io {
            path: out_path.clone(),
            message: e.to_string(),
        })?;
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
    let mut variant = None;
    let mut key_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut tag_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant = Some(
                    KalynaVariant::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?,
                );
                i += 2;
            }
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--tag" => {
                tag_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("tag"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(GmacArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path,
        tag_path,
        iterations,
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
    let key = read_exact_file(&args.key_path, "key", args.variant.key_len())?;
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
                    <$mac>::verify_with_cipher(&cipher, &message, tag_in.as_ref().unwrap())
                        .map_err(|_| CliError::GmacVerifyFailed)?;
                } else {
                    tag = <$mac>::mac_with_cipher(&cipher, &message);
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

    if !verify {
        let out_path = args.out_path.as_ref().ok_or(CliError::MissingFlag("out"))?;
        std::fs::write(out_path, tag).map_err(|e| CliError::Io {
            path: out_path.clone(),
            message: e.to_string(),
        })?;
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
}

/// Parses `kalyna-kw wrap`/`unwrap`'s flags: `--variant`/`--key`/`--in`/`--out` required,
/// `--iterations` optional - same shape as [`parse_block_args`] minus `--raw-schedule` (KW has no
/// cached-vs-raw distinction to expose, same reason [`kupyna-digest`](parse_digest_args) doesn't).
///
/// # Errors
///
/// Same cases as [`parse_block_args`].
pub fn parse_kw_args(args: &[String]) -> Result<KwArgs, CliError> {
    let mut variant = None;
    let mut key_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant = Some(
                    KalynaVariant::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?,
                );
                i += 2;
            }
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(KwArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
        iterations,
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
    let key = read_exact_file(&args.key_path, "key", args.variant.key_len())?;
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

    std::fs::write(&args.out_path, &output).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })?;

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
}

/// Parses `kalyna-xts encrypt`/`decrypt`'s flags: `--variant`/`--key`/`--tweak`/`--in`/`--out`
/// required, `--iterations` optional.
///
/// # Errors
///
/// Same cases as [`parse_block_args`], plus `--tweak` sharing `--key`'s missing-flag handling.
pub fn parse_xts_args(args: &[String]) -> Result<XtsArgs, CliError> {
    let mut variant = None;
    let mut key_path = None;
    let mut tweak_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant = Some(
                    KalynaVariant::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?,
                );
                i += 2;
            }
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--tweak" => {
                tweak_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("tweak"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(XtsArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        tweak_path: tweak_path.ok_or(CliError::MissingFlag("tweak"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
        iterations,
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
    let key = read_exact_file(&args.key_path, "key", args.variant.key_len())?;
    let tweak = read_exact_file(&args.tweak_path, "tweak", args.variant.block_len())?;
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

    std::fs::write(&args.out_path, &output).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })?;

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

/// Read/write chunk size for `encrypt`'s real streaming path - same rationale and size as
/// `kupyna-digest`/`strumok-crypt`'s own constants (D-42): small enough that peak memory stays
/// bounded by this constant rather than `--in`'s size. `decrypt` also uses this same constant as
/// the on-disk record-length ceiling it enforces on every chunk it parses (see
/// [`run_secretstream_decrypt`]) - correct only because encoder and decoder share one binary and
/// therefore one build of this constant; a `decrypt` reading a file from a build with a *larger*
/// `SECRETSTREAM_CHUNK_BYTES` would wrongly reject its legitimately-larger chunks as
/// [`CliError::SecretstreamChunkTooLarge`]. Not a concern while this value has never changed
/// across a release, but worth a real `SECRETSTREAM_MAX_CHUNK_BYTES` split (distinct from the
/// encoder's own chunk size) the day it ever does.
const SECRETSTREAM_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct SecretstreamArgs {
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
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
    let mut key_path = None;
    let mut in_path = None;
    let mut out_path = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(SecretstreamArgs {
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
    })
}

/// Appends a fixed suffix to `path` rather than using `Path::with_extension` (which would replace
/// an existing extension) or `format!("{}", path.display())` (lossy on non-UTF-8 paths) - an
/// `OsString` append is correct for both cases and still lands next to `out_path`, which
/// [`run_secretstream_command`] needs so the final `std::fs::rename` stays on the same filesystem.
fn secretstream_temp_path(out_path: &std::path::Path) -> PathBuf {
    let mut name = out_path.as_os_str().to_os_string();
    name.push(".secretstream-tmp");
    PathBuf::from(name)
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
fn run_secretstream_encrypt(
    key: &dstu_core::crypto_secretstream::Key,
    in_path: &PathBuf,
    tmp_path: &PathBuf,
) -> Result<(), CliError> {
    use dstu_core::crypto_secretstream::{PushState, Tag};
    use std::io::{Read, Write};

    let (mut push, header) = PushState::init(key)?;

    let mut in_file = std::fs::File::open(in_path).map_err(|e| CliError::Io {
        path: in_path.clone(),
        message: e.to_string(),
    })?;
    let mut out_file = std::fs::File::create(tmp_path).map_err(|e| CliError::Io {
        path: tmp_path.clone(),
        message: e.to_string(),
    })?;
    out_file.write_all(&header).map_err(|e| CliError::Io {
        path: tmp_path.clone(),
        message: e.to_string(),
    })?;

    let read_chunk = |file: &mut std::fs::File, buf: &mut [u8]| -> Result<usize, CliError> {
        file.read(buf).map_err(|e| CliError::Io {
            path: in_path.clone(),
            message: e.to_string(),
        })
    };

    let mut cur = vec![0u8; SECRETSTREAM_CHUNK_BYTES];
    let mut cur_len = read_chunk(&mut in_file, &mut cur)?;
    loop {
        let mut next = vec![0u8; SECRETSTREAM_CHUNK_BYTES];
        let next_len = read_chunk(&mut in_file, &mut next)?;
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
                path: tmp_path.clone(),
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

/// Decrypts `in_path` into `tmp_path` (the caller renames onto the real `--out` only after this
/// returns `Ok`) using [`dstu_core::crypto_secretstream::PullState`]. Stops as soon as a
/// [`Tag::Final`](dstu_core::crypto_secretstream::Tag::Final) chunk verifies, then checks for
/// trailing bytes - both an early EOF (no `Final` ever seen, via [`read_exact_or_truncated`]) and
/// leftover bytes after `Final` are rejected, not silently accepted.
fn run_secretstream_decrypt(
    key: &dstu_core::crypto_secretstream::Key,
    in_path: &PathBuf,
    tmp_path: &PathBuf,
) -> Result<(), CliError> {
    use dstu_core::crypto_secretstream::{PullState, Tag};
    use std::io::{Read, Write};

    let mut in_file = std::fs::File::open(in_path).map_err(|e| CliError::Io {
        path: in_path.clone(),
        message: e.to_string(),
    })?;
    let mut out_file = std::fs::File::create(tmp_path).map_err(|e| CliError::Io {
        path: tmp_path.clone(),
        message: e.to_string(),
    })?;

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

        let mut ciphertext = vec![0u8; chunk_len];
        read_exact_or_truncated(&mut in_file, &mut ciphertext, in_path)?;
        let mut auth_tag = [0u8; SECRETSTREAM_TAG_LEN];
        read_exact_or_truncated(&mut in_file, &mut auth_tag, in_path)?;

        let mut plaintext = vec![0u8; chunk_len];
        let tag = pull.pull(tag_byte, &ciphertext, &auth_tag, &mut plaintext)?;
        out_file.write_all(&plaintext).map_err(|e| CliError::Io {
            path: tmp_path.clone(),
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
/// [`CliError::SecretstreamUnknownTag`]/[`CliError::SecretstreamChunkTooLarge`] for a malformed
/// chunk record, [`CliError::SecretstreamTrailingData`] if bytes remain after `Final`, or
/// [`CliError::Io`] for file read/write failures - `--out` is left untouched on every error path.
pub fn run_secretstream_command(decrypt: bool, args: &SecretstreamArgs) -> Result<(), CliError> {
    let key_bytes = read_exact_file(&args.key_path, "key", SECRETSTREAM_KEY_LEN)?;
    let mut key_arr = [0u8; SECRETSTREAM_KEY_LEN];
    key_arr.copy_from_slice(&key_bytes);
    let key = dstu_core::crypto_secretstream::Key::from_bytes(key_arr);

    let tmp_path = secretstream_temp_path(&args.out_path);
    let result = if decrypt {
        run_secretstream_decrypt(&key, &args.in_path, &tmp_path)
    } else {
        run_secretstream_encrypt(&key, &args.in_path, &tmp_path)
    };

    match result {
        Ok(()) => std::fs::rename(&tmp_path, &args.out_path).map_err(|e| CliError::Io {
            path: args.out_path.clone(),
            message: e.to_string(),
        }),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
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
}

/// Parses `kupyna-digest`'s flags (`--variant`/`--in`/`--out` required, `--iterations` optional).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`], [`CliError::UnknownVariant`], [`CliError::InvalidIterations`],
/// or [`CliError::UnknownFlag`] - same cases as [`parse_block_args`], minus the key/raw-schedule
/// flags Kupyna (unkeyed) has no use for.
pub fn parse_digest_args(args: &[String]) -> Result<DigestArgs, CliError> {
    let mut variant = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant =
                    Some(HashBits::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?);
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(DigestArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
        iterations,
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

    std::fs::write(&args.out_path, &digest).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })?;

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

#[derive(Debug, PartialEq, Eq)]
pub struct HashArgs {
    pub in_path: PathBuf,
    pub out_path: PathBuf,
}

/// Parses `hash`'s flags (`--in`/`--out`, both required). No `--variant` (fixed to Kupyna-256, see
/// [`run_hash_command`]'s doc comment) and no `--iterations` (that's `kupyna-digest`'s D-34
/// benchmark-only flag, not something a real user of `hash` needs).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`] or [`CliError::UnknownFlag`].
pub fn parse_hash_args(args: &[String]) -> Result<HashArgs, CliError> {
    let mut in_path = None;
    let mut out_path = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(HashArgs {
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
    })
}

/// Runs `hash`: hashes `--in` with Kupyna-256, writes the 32-byte digest to `--out`. Fixed to
/// Kupyna-256 - no `--variant` knob (D-47's "no knob when a safe default exists"; `crypto_sign`
/// already established Kupyna-256 as this project's own default message-hash choice, `docs/DECISIONS.md`
/// D-46). Delegates to [`run_digest_command`] with `iterations: 1` rather than duplicating its
/// streaming loop - this reuses `kupyna-digest`'s already-tested, genuinely-streaming-from-disk
/// (D-42, 8 KiB chunks) implementation directly, so `hash` inherits its memory-bounded property
/// without new code to verify it. Unlike `encrypt`/`decrypt`, `hash` has no message-length cap.
///
/// # Errors
///
/// Returns [`CliError::Io`] if `--in` can't be read or `--out` can't be written.
pub fn run_hash_command(args: &HashArgs) -> Result<(), CliError> {
    run_digest_command(&DigestArgs {
        variant: HashBits::B256,
        in_path: args.in_path.clone(),
        out_path: args.out_path.clone(),
        iterations: 1,
    })
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
    let mut out_path = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(KeygenArgs {
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
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
    std::fs::write(&args.out_path, key.as_bytes()).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })
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

/// Reads a 21-byte signing-key file and validates it via
/// [`dstu_core::crypto_sign::SigningKey::from_bytes`].
fn read_signing_key(path: &PathBuf) -> Result<dstu_core::crypto_sign::SigningKey, CliError> {
    let bytes = read_exact_file(path, "signing key", 21)?;
    let mut d = [0u8; 21];
    d.copy_from_slice(&bytes);
    dstu_core::crypto_sign::SigningKey::from_bytes(&d).ok_or(CliError::SignKeyInvalid)
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
    let mut out_path = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(SignKeygenArgs {
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
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
    std::fs::write(&args.out_path, key.to_bytes()).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })
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
    let mut key_path = None;
    let mut out_path = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(SignPubkeyArgs {
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
    })
}

/// Runs `sign-pubkey`: reads a 21-byte signing key from `--key`, derives `Q = -d*G`
/// ([`dstu_core::crypto_sign::SigningKey::verifying_key`]), and writes its 42-byte uncompressed
/// `x || y` encoding to `--out` - the file format `verify --key` expects.
///
/// # Errors
///
/// Returns [`CliError::Io`]/[`CliError::WrongLength`] for file problems, or
/// [`CliError::SignKeyInvalid`] if `--key` isn't a valid signing key.
pub fn run_sign_pubkey_command(args: &SignPubkeyArgs) -> Result<(), CliError> {
    let signing_key = read_signing_key(&args.key_path)?;
    let verifying_key = signing_key.verifying_key();
    std::fs::write(&args.out_path, verifying_key.to_uncompressed_bytes()).map_err(|e| {
        CliError::Io {
            path: args.out_path.clone(),
            message: e.to_string(),
        }
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignArgs {
    pub key_path: PathBuf,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub iterations: u32,
}

/// Parses `sign`'s flags (`--key`/`--in`/`--out` required, `--iterations` optional - benchmarking
/// only, same shape as [`parse_digest_args`]: no `--raw-schedule`, since signing has no key-
/// schedule step to cache/redo, the same reason `kupyna-digest`/`kalyna-kw` don't have one either).
///
/// # Errors
///
/// Returns [`CliError::MissingFlag`], [`CliError::InvalidIterations`], or [`CliError::UnknownFlag`].
pub fn parse_sign_args(args: &[String]) -> Result<SignArgs, CliError> {
    let mut key_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(SignArgs {
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
        iterations,
    })
}

/// Runs `sign`: hashes `--in` with Kupyna-256 in bounded-memory chunks
/// ([`hash_file_streamed`], D-42), signs the digest with `--key`
/// ([`dstu_core::crypto_sign::SigningKey::sign_digest`], deterministic nonce - D-46), and writes
/// the 42-byte `r || s` signature to `--out`. `iterations > 1` is the D-34 benchmark path: the
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
    let signing_key = read_signing_key(&args.key_path)?;
    let digest = hash_file_streamed(&args.in_path)?;
    let iterations = args.iterations.max(1);

    let start = Instant::now();
    let mut sig = signing_key.sign_digest(&digest);
    for _ in 1..iterations {
        sig = signing_key.sign_digest(&digest);
    }
    let elapsed = start.elapsed();

    std::fs::write(&args.out_path, sig.to_bytes()).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })?;

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
    let mut key_path = None;
    let mut in_path = None;
    let mut sig_path = None;
    let mut iterations = 1u32;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--sig" => {
                sig_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("sig"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(VerifyArgs {
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        sig_path: sig_path.ok_or(CliError::MissingFlag("sig"))?,
        iterations,
    })
}

/// Runs `verify`: hashes `--in` with Kupyna-256 in bounded-memory chunks
/// ([`hash_file_streamed`], D-42), and checks `--sig` against `--key` (a 42-byte uncompressed
/// verifying key - [`dstu_core::crypto_sign::VerifyingKey::from_uncompressed_bytes`]) via
/// [`dstu_core::crypto_sign::VerifyingKey::verify_digest`]. Succeeds silently (`Ok(())`, exit 0)
/// on a valid signature, matching `kalyna-cmac verify`/`kalyna-gmac verify`'s own convention -
/// there is nothing to write to disk on success, unlike `decrypt`. `iterations > 1` is the D-34
/// benchmark path, same shape as [`run_sign_command`]: hash/key/signature parsed once, only
/// `verify_digest` itself timed in a loop.
///
/// # Errors
///
/// Returns [`CliError::Io`]/[`CliError::WrongLength`] for file problems, or
/// [`CliError::SignVerifyFailed`] if the signature does not verify.
#[allow(clippy::cast_precision_loss)] // human-readable ops/s diagnostic, not exact at any realistic count
pub fn run_verify_command(args: &VerifyArgs) -> Result<(), CliError> {
    let key_bytes = read_exact_file(&args.key_path, "verifying key", 42)?;
    let mut q = [0u8; 42];
    q.copy_from_slice(&key_bytes);
    let verifying_key = dstu_core::crypto_sign::VerifyingKey::from_uncompressed_bytes(&q);

    let sig_bytes = read_exact_file(&args.sig_path, "signature", 42)?;
    let mut sig_arr = [0u8; 42];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = dstu_core::crypto_sign::Signature::from_bytes(&sig_arr);

    let digest = hash_file_streamed(&args.in_path)?;
    let iterations = args.iterations.max(1);

    let start = Instant::now();
    let mut ok = verifying_key.verify_digest(&digest, &sig);
    for _ in 1..iterations {
        ok = verifying_key.verify_digest(&digest, &sig);
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
        Ok(())
    } else {
        Err(CliError::SignVerifyFailed)
    }
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
}

/// Parses `strumok-crypt`'s flags (`--variant`/`--key`/`--iv`/`--in`/`--out` required,
/// `--iterations`/`--raw-schedule` optional).
///
/// # Errors
///
/// Same cases as [`parse_block_args`], plus `--iv` sharing `--key`'s missing-flag/IO handling.
pub fn parse_strumok_args(args: &[String]) -> Result<StrumokArgs, CliError> {
    let mut variant = None;
    let mut key_path = None;
    let mut iv_path = None;
    let mut in_path = None;
    let mut out_path = None;
    let mut iterations = 1u32;
    let mut raw_schedule = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--variant" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("variant"))?;
                variant =
                    Some(HashBits::parse(v).ok_or_else(|| CliError::UnknownVariant(v.clone()))?);
                i += 2;
            }
            "--key" => {
                key_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("key"))?,
                ));
                i += 2;
            }
            "--iv" => {
                iv_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("iv"))?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("in"))?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or(CliError::MissingFlag("out"))?,
                ));
                i += 2;
            }
            "--iterations" => {
                let v = args.get(i + 1).ok_or(CliError::MissingFlag("iterations"))?;
                iterations = v
                    .parse()
                    .map_err(|_| CliError::InvalidIterations(v.clone()))?;
                i += 2;
            }
            "--raw-schedule" => {
                raw_schedule = true;
                i += 1;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(StrumokArgs {
        variant: variant.ok_or(CliError::MissingFlag("variant"))?,
        key_path: key_path.ok_or(CliError::MissingFlag("key"))?,
        iv_path: iv_path.ok_or(CliError::MissingFlag("iv"))?,
        in_path: in_path.ok_or(CliError::MissingFlag("in"))?,
        out_path: out_path.ok_or(CliError::MissingFlag("out"))?,
        iterations,
        raw_schedule,
    })
}

/// Read/write chunk size for `strumok-crypt`'s real (`iterations <= 1`) path - same rationale and
/// size as `kupyna-digest`'s [`DIGEST_STREAM_CHUNK_BYTES`] (D-42): small enough that peak memory
/// stays bounded by this constant rather than `--in`'s size, large enough that per-syscall
/// overhead (now on *both* the read and the write side, unlike a hash which only reads) stays
/// negligible. `Strumok::apply_keystream`'s own chunk-invariance (`docs/TASKS.md` T-24) is exactly what
/// makes feeding it one chunk at a time - instead of the whole file - safe to begin with.
const STRUMOK_STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// Runs `strumok-crypt`: applies the keystream to `--in` (arbitrary length).
///
/// `iterations <= 1` (real usage) streams `--in` to `--out` through [`STRUMOK_STREAM_CHUNK_BYTES`]-
/// sized chunks - read, `apply_keystream` in place, write, discard - so peak memory is bounded
/// regardless of file size (D-42, same treatment as `kupyna-digest`/T-83). `--raw-schedule` has no
/// effect here: with exactly one iteration, constructing the cipher fresh vs. once makes no
/// observable difference, so this path always constructs it once.
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
    use std::io::{Read, Write};

    let key_len = match args.variant {
        HashBits::B256 => 32,
        HashBits::B512 => 64,
    };
    let key = read_exact_file(&args.key_path, "key", key_len)?;
    let iv = read_exact_file(&args.iv_path, "IV", 32)?;
    let iterations = args.iterations.max(1);

    if iterations <= 1 {
        macro_rules! stream_variant {
            ($cipher:ty, $key_len:literal) => {{
                let mut key_arr = [0u8; $key_len];
                key_arr.copy_from_slice(&key);
                let mut iv_arr = [0u8; 32];
                iv_arr.copy_from_slice(&iv);

                let mut in_file = std::fs::File::open(&args.in_path).map_err(|e| CliError::Io {
                    path: args.in_path.clone(),
                    message: e.to_string(),
                })?;
                let mut out_file =
                    std::fs::File::create(&args.out_path).map_err(|e| CliError::Io {
                        path: args.out_path.clone(),
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
                        path: args.out_path.clone(),
                        message: e.to_string(),
                    })?;
                }
            }};
        }

        match args.variant {
            HashBits::B256 => stream_variant!(Strumok256, 32),
            HashBits::B512 => stream_variant!(Strumok512, 64),
        }
        return Ok(());
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

    std::fs::write(&args.out_path, &output).map_err(|e| CliError::Io {
        path: args.out_path.clone(),
        message: e.to_string(),
    })?;

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
fn is_version_flag(s: &str) -> bool {
    s == "--version" || s == "-V"
}

const TOP_LEVEL_HELP: &str = "\
uacrypt - a CLI over dstu-core, Ukrainian DSTU cryptographic standards (Kalyna, Kupyna, Strumok).

Pre-release, provisional, not independently audited - see docs/SECURITY.md/DECISIONS.md in the project
repository for the full threat model and citations (D-05: Kalyna's mode of operation is an adopted
assumption, not primary-text confirmed; D-15: Strumok is UAPKI-attributed, not primary-text
confirmed).

USAGE:
    uacrypt <command> [flags]
    uacrypt <command> --help    show that command's flags and an example invocation
    uacrypt --version           print the version and exit

EVERYDAY COMMANDS:
    keygen          Generate a fresh random 32-byte key for `encrypt`/`decrypt`.
    encrypt         Encrypt a file of any size with a 32-byte key (authenticated, streamed).
    decrypt         Decrypt a file produced by `encrypt`.
    hash            Compute a Kupyna-256 digest of a file of any size.
    sign-keygen     Generate a fresh signing key for `sign`.
    sign-pubkey     Derive the matching verifying key from a signing key, for `verify`.
    sign            Sign a file of any size with a signing key (DSTU 4145).
    verify          Check a `sign` signature against a verifying key.

LOWER-LEVEL COMMANDS (benchmarking/interop - most users want the three above instead):
    kalyna-block    Single Kalyna block encrypt/decrypt - exactly one block, no file support.
    kalyna-ccm      Kalyna-CCM authenticated encryption - messages/AAD capped at 255 bytes.
    kalyna-gcm      Kalyna-GCM authenticated encryption - no message-length cap.
    kalyna-cmac     Kalyna-CMAC message authentication (compute/verify a tag, no encryption).
    kalyna-gmac     Kalyna-GMAC message authentication (compute/verify a tag, no encryption).
    kalyna-kw       Kalyna key wrap/unwrap - wraps block-aligned key material, not a general cipher.
    kalyna-xts      Kalyna-XTS disk-sector mode - confidentiality only, no tag, by design.
    kupyna-digest   Kupyna hash with a selectable variant (256/512) and a benchmark --iterations flag.
    strumok-crypt   Strumok keystream cipher - NOT authenticated, tampering is never detected.

Run `uacrypt <command> --help` for that command's flags and an example.
";

const KEYGEN_HELP: &str = "\
uacrypt keygen - generate a fresh random 32-byte key for `encrypt`/`decrypt`.

Draws from the OS CSPRNG (dstu_core::randombytes, via crypto_secretstream::Key::generate) and
writes the raw 32 bytes to --out - the exact format `encrypt`/`decrypt --key` expect. Overwrites
--out if it already exists, same as every other command here that writes a file.

USAGE:
    uacrypt keygen --out <path>

FLAGS:
    --out <path>    where to write the 32-byte key

EXAMPLE:
    uacrypt keygen --out key.bin
";

const ENCRYPT_HELP: &str = "\
uacrypt encrypt - encrypt a file of any size with a 32-byte key.

Streamed in bounded memory chunks (no whole-file buffering) and authenticated: `decrypt` detects
any tampering with the output rather than silently returning wrong plaintext. Built on
dstu_core::crypto_secretstream (see docs/DECISIONS.md D-68).

USAGE:
    uacrypt encrypt --key <path> --in <path> --out <path>

FLAGS:
    --key <path>    a 32-byte binary key file (exactly 32 bytes, not a passphrase)
    --in <path>     file to encrypt
    --out <path>    where to write the encrypted output

EXAMPLE:
    uacrypt encrypt --key key.bin --in report.pdf --out report.pdf.enc

Notes:
    - --key must be exactly 32 raw bytes - generate one with `uacrypt keygen --out key.bin`.
    - --in and --out may be the same path (encrypts in place); --out is only replaced after the
      whole file is written and verified, so a failure never leaves partial output.
";

const DECRYPT_HELP: &str = "\
uacrypt decrypt - decrypt a file produced by `encrypt`, using the same 32-byte key.

Streamed in bounded memory chunks and authenticated: a wrong key or a tampered/truncated file is
rejected with an error before anything is written to --out, rather than producing wrong plaintext.

USAGE:
    uacrypt decrypt --key <path> --in <path> --out <path>

FLAGS:
    --key <path>    the same 32-byte binary key file used for `encrypt`
    --in <path>     the encrypted file (must be real `encrypt` output)
    --out <path>    where to write the decrypted output

EXAMPLE:
    uacrypt decrypt --key key.bin --in report.pdf.enc --out report.pdf

Notes:
    - --in and --out may be the same path (decrypts in place).
    - Fails loudly (no --out written) on a wrong key, a wrong/tampered file, or a file produced by
      an older uacrypt version - the on-disk format is not yet stable pre-1.0.
";

const HASH_HELP: &str = "\
uacrypt hash - compute a Kupyna-256 digest of a file of any size.

Fixed to Kupyna-256 (no --variant knob) - for the other Kupyna variant or benchmarking, see
`kupyna-digest --help`. Streams the input from disk in bounded chunks, so file size is not a
memory concern.

USAGE:
    uacrypt hash --in <path> --out <path>

FLAGS:
    --in <path>     file to hash
    --out <path>    where to write the 32-byte digest

EXAMPLE:
    uacrypt hash --in report.pdf --out report.pdf.kupyna256
";

const SIGN_KEYGEN_HELP: &str = "\
uacrypt sign-keygen - generate a fresh signing key for `sign`.

Draws from the OS CSPRNG via rejection sampling against the DSTU 4145 curve order (never a modulo
reduction, which would bias the result - docs/DECISIONS.md D-72) and writes the raw 21-byte private
scalar to --out. A separate command from `keygen` - a signing key and an `encrypt`/`decrypt` key
are different, incompatible things, not two settings of the same command.

USAGE:
    uacrypt sign-keygen --out <path>

FLAGS:
    --out <path>    where to write the 21-byte signing key

EXAMPLE:
    uacrypt sign-keygen --out signing.key

Notes:
    - Keep this file secret - anyone who has it can sign as you.
    - Derive the matching public verifying key with `uacrypt sign-pubkey`.
";

const SIGN_PUBKEY_HELP: &str = "\
uacrypt sign-pubkey - derive the matching verifying key from a signing key.

Reads --key (a `sign-keygen` output) and writes the 42-byte public verifying key that `verify`
needs - safe to share, unlike the signing key itself.

USAGE:
    uacrypt sign-pubkey --key <path> --out <path>

FLAGS:
    --key <path>    a signing key (from `uacrypt sign-keygen`)
    --out <path>    where to write the 42-byte verifying key

EXAMPLE:
    uacrypt sign-pubkey --key signing.key --out verifying.key
";

const SIGN_HELP: &str = "\
uacrypt sign - sign a file of any size with a signing key (DSTU 4145).

Hashes --in with Kupyna-256 in bounded memory chunks, then signs the digest (deterministic nonce -
no RNG involved in signing itself, only in `sign-keygen`). Writes the 42-byte signature to --out.

USAGE:
    uacrypt sign --key <path> --in <path> --out <path>

FLAGS:
    --key <path>        a signing key (from `uacrypt sign-keygen`)
    --in <path>         file to sign
    --out <path>        where to write the 42-byte signature
    --iterations <n>    (benchmarking only) repeat the sign call n times, print timing to stderr

EXAMPLE:
    uacrypt sign --key signing.key --in report.pdf --out report.pdf.sig
";

const VERIFY_HELP: &str = "\
uacrypt verify - check a `sign` signature against a verifying key.

Hashes --in the same way `sign` did, then checks --sig against --key (a `sign-pubkey` output).
Prints nothing and exits 0 on a valid signature; exits with an error (nothing written) if the
message, signature, or key do not match - a tampered file or a wrong key is detected, not silently
accepted.

USAGE:
    uacrypt verify --key <path> --in <path> --sig <path>

FLAGS:
    --key <path>        a verifying key (from `uacrypt sign-pubkey`)
    --in <path>         the file that was signed
    --sig <path>        the signature (from `uacrypt sign`)
    --iterations <n>    (benchmarking only) repeat the verify call n times, print timing to stderr

EXAMPLE:
    uacrypt verify --key verifying.key --in report.pdf --sig report.pdf.sig
";

const KALYNA_BLOCK_HELP: &str = "\
uacrypt kalyna-block - encrypt or decrypt exactly one Kalyna block, no mode of operation.

Low-level: this is a single block-cipher call, not a file-encryption tool - it does not chain
multiple blocks or add padding. For encrypting a whole file, use `encrypt`/`decrypt` instead.

USAGE:
    uacrypt kalyna-block encrypt --variant <v> --key <path> --in <path> --out <path>
    uacrypt kalyna-block decrypt --variant <v> --key <path> --in <path> --out <path>

FLAGS:
    --variant <v>      one of 128-128, 128-256, 256-256, 256-512, 512-512 (block/key size in bits)
    --key <path>       key file - must be exactly the variant's key length
    --in <path>        input file - must be exactly one block (the variant's block length)
    --out <path>       where to write the one-block result
    --iterations <n>   (benchmarking only) repeat the operation n times, print timing to stderr
    --raw-schedule     (benchmarking only) re-expand the key schedule on every iteration

EXAMPLE:
    uacrypt kalyna-block encrypt --variant 128-128 --key key.bin --in block.bin --out block.enc
";

const KALYNA_CCM_HELP: &str = "\
uacrypt kalyna-ccm - Kalyna-CCM authenticated encryption (provisional, docs/DECISIONS.md D-41).

Messages and AAD are capped at 255 bytes each (see hazmat::kalyna_ccm docs) - for larger files use
`encrypt`/`decrypt` instead, which have no such cap.

USAGE:
    uacrypt kalyna-ccm encrypt --variant <v> --key <path> --nonce <path> --in <path> --out <path> --tag <path> [--aad <path>]
    uacrypt kalyna-ccm decrypt --variant <v> --key <path> --nonce <path> --in <path> --out <path> --tag <path> [--aad <path>]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --nonce <path>   encrypt: OUTPUT, a fresh random nonce is generated and written here.
                     decrypt: INPUT, must be the nonce file `encrypt` produced.
    --aad <path>     optional - additional authenticated data (not encrypted, but tamper-checked)
    --in <path>      plaintext (encrypt) or ciphertext (decrypt), <=255 bytes
    --out <path>     ciphertext (encrypt) or plaintext (decrypt)
    --tag <path>     encrypt: OUTPUT auth tag. decrypt: INPUT, must be encrypt's tag.
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-ccm encrypt --variant 128-256 --key key.bin --nonce nonce.bin --in msg.bin \\
        --out msg.enc --tag tag.bin
";

const KALYNA_GCM_HELP: &str = "\
uacrypt kalyna-gcm - Kalyna-GCM authenticated encryption (provisional, docs/DECISIONS.md D-56).

Benchmarking/interop tool (docs/DECISIONS.md D-31/D-71), same shape as `kalyna-ccm` but with no
message-length cap - for everyday use, `encrypt`/`decrypt` (crypto_secretstream) are simpler and
already stream to disk.

USAGE:
    uacrypt kalyna-gcm encrypt --variant <v> --key <path> --nonce <path> --in <path> --out <path> --tag <path> [--aad <path>] [--iterations <n>]
    uacrypt kalyna-gcm decrypt --variant <v> --key <path> --nonce <path> --in <path> --out <path> --tag <path> [--aad <path>] [--iterations <n>]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --nonce <path>   encrypt: OUTPUT, a fresh random nonce is generated and written here.
                     decrypt: INPUT, must be the nonce file `encrypt` produced.
    --aad <path>     optional - additional authenticated data (not encrypted, but tamper-checked)
    --in <path>      plaintext (encrypt) or ciphertext (decrypt), any length
    --out <path>     ciphertext (encrypt) or plaintext (decrypt)
    --tag <path>     encrypt: OUTPUT auth tag (full block length). decrypt: INPUT, must be encrypt's tag.
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
    uacrypt kalyna-cmac compute --variant <v> --key <path> --in <path> --out <path> [--iterations <n>]
    uacrypt kalyna-cmac verify --variant <v> --key <path> --in <path> --tag <path> [--iterations <n>]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --in <path>      message to authenticate
    --out <path>     compute: OUTPUT, where to write the 16-byte tag
    --tag <path>     verify: INPUT, the tag to check against
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-cmac compute --variant 128-128 --key key.bin --in msg.bin --out tag.bin
";

const KALYNA_GMAC_HELP: &str = "\
uacrypt kalyna-gmac - Kalyna-GMAC message authentication, for benchmarking/interop (docs/DECISIONS.md D-31/D-71).

Computes or verifies a full-block-length tag over a message - no encryption, no nonce (unlike
kalyna-gcm, hazmat::kalyna_gmac takes none). Do not reuse this key for any encryption mode.

USAGE:
    uacrypt kalyna-gmac compute --variant <v> --key <path> --in <path> --out <path> [--iterations <n>]
    uacrypt kalyna-gmac verify --variant <v> --key <path> --in <path> --tag <path> [--iterations <n>]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --in <path>      message to authenticate
    --out <path>     compute: OUTPUT, where to write the tag (full block length)
    --tag <path>     verify: INPUT, the tag to check against
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-gmac compute --variant 128-128 --key key.bin --in msg.bin --out tag.bin
";

const KALYNA_KW_HELP: &str = "\
uacrypt kalyna-kw - Kalyna key wrap/unwrap, for benchmarking/interop (docs/DECISIONS.md D-31/D-71).

Wraps block-aligned key material (1..=20 blocks) into a blob one block longer, with a checksum
block for tamper-evidence - not a general-purpose cipher, see hazmat::kalyna_kw docs.

USAGE:
    uacrypt kalyna-kw wrap --variant <v> --key <path> --in <path> --out <path> [--iterations <n>]
    uacrypt kalyna-kw unwrap --variant <v> --key <path> --in <path> --out <path> [--iterations <n>]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --in <path>      key material to wrap (block-aligned) or a wrapped blob to unwrap
    --out <path>     wrapped blob (wrap) or recovered key material (unwrap)
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-kw wrap --variant 128-128 --key kek.bin --in key-to-wrap.bin --out wrapped.bin
";

const KALYNA_XTS_HELP: &str = "\
uacrypt kalyna-xts - Kalyna-XTS disk-sector mode, for benchmarking/interop (docs/DECISIONS.md D-31/D-71).

Confidentiality only, no tag - the correct design for disk-sector encryption, not a gap (see
hazmat::kalyna_xts docs). --in must be at least one block long.

USAGE:
    uacrypt kalyna-xts encrypt --variant <v> --key <path> --tweak <path> --in <path> --out <path> [--iterations <n>]
    uacrypt kalyna-xts decrypt --variant <v> --key <path> --tweak <path> --in <path> --out <path> [--iterations <n>]

FLAGS:
    --variant <v>    one of 128-128, 128-256, 256-256, 256-512, 512-512
    --key <path>     key file - must be exactly the variant's key length
    --tweak <path>   one block's worth of bytes - the data-unit tweak seed (e.g. a sector index
                     encoded into a block-length buffer by the caller; this CLI does not derive one)
    --in <path>      plaintext (encrypt) or ciphertext (decrypt), at least one block
    --out <path>     ciphertext (encrypt) or plaintext (decrypt)
    --iterations <n> (benchmarking only) repeat the operation n times, print timing to stderr

EXAMPLE:
    uacrypt kalyna-xts encrypt --variant 128-128 --key key.bin --tweak tweak.bin --in sector.bin \\
        --out sector.enc
";

const KUPYNA_DIGEST_HELP: &str = "\
uacrypt kupyna-digest - Kupyna hash with a selectable variant, for benchmarking/interop.

For everyday hashing, `hash` is simpler (fixed to Kupyna-256, no --variant flag needed).

USAGE:
    uacrypt kupyna-digest --variant <v> --in <path> --out <path> [--iterations <n>]

FLAGS:
    --variant <v>      256 or 512
    --in <path>        file to hash
    --out <path>       where to write the digest
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
        [--iterations <n>] [--raw-schedule]

FLAGS:
    --variant <v>      256 or 512 (key size in bits; IV is always 32 bytes)
    --key <path>       key file - must be exactly the variant's key length
    --iv <path>        IV file - must be exactly 32 bytes
    --in <path>        file to encrypt or decrypt (same operation either way - XOR keystream)
    --out <path>       where to write the result
    --iterations <n>   (benchmarking only) repeat n times, print timing/MB-per-s to stderr
    --raw-schedule     (benchmarking only) re-initialize the cipher fresh on every iteration

EXAMPLE:
    uacrypt strumok-crypt --variant 256 --key key.bin --iv iv.bin --in msg.bin --out msg.enc
";

/// Prints one command's `--help` text to stdout. `command` is expected to be one of the literal
/// top-level command names [`run`] matches on; anything else falls back to [`TOP_LEVEL_HELP`]
/// rather than panicking, since this is only ever called with a string [`run`] just matched.
fn print_command_help(command: &str) {
    let text = match command {
        "keygen" => KEYGEN_HELP,
        "encrypt" => ENCRYPT_HELP,
        "decrypt" => DECRYPT_HELP,
        "hash" => HASH_HELP,
        "sign-keygen" => SIGN_KEYGEN_HELP,
        "sign-pubkey" => SIGN_PUBKEY_HELP,
        "sign" => SIGN_HELP,
        "verify" => VERIFY_HELP,
        "kalyna-block" => KALYNA_BLOCK_HELP,
        "kalyna-ccm" => KALYNA_CCM_HELP,
        "kalyna-gcm" => KALYNA_GCM_HELP,
        "kalyna-cmac" => KALYNA_CMAC_HELP,
        "kalyna-gmac" => KALYNA_GMAC_HELP,
        "kalyna-kw" => KALYNA_KW_HELP,
        "kalyna-xts" => KALYNA_XTS_HELP,
        "kupyna-digest" => KUPYNA_DIGEST_HELP,
        "strumok-crypt" => STRUMOK_CRYPT_HELP,
        _ => TOP_LEVEL_HELP,
    };
    println!("{text}");
}

/// Dispatches `sign-keygen`/`sign-pubkey`/`sign`/`verify` - split out of [`run`] for the same
/// `clippy::pedantic` line-count reason as [`dispatch_kalyna_mode`] (`docs/DECISIONS.md` D-71's
/// precedent, `docs/TASKS.md` T-124); `cmd` is always one of the four literals [`run`]'s own match arm
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
        "sign-pubkey" => run_sign_pubkey_command(&parse_sign_pubkey_args(rest)?),
        "sign" => run_sign_command(&parse_sign_args(rest)?),
        _ => run_verify_command(&parse_verify_args(rest)?),
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
            Some(other) => Err(CliError::UnknownCommand(format!("kalyna-gcm {other}"))),
            None => Err(CliError::MissingFlag("encrypt|decrypt")),
        },
        "kalyna-cmac" => match sub {
            Some("compute") => run_cmac_command(false, &parse_cmac_args(&rest[1..])?),
            Some("verify") => run_cmac_command(true, &parse_cmac_args(&rest[1..])?),
            Some(other) => Err(CliError::UnknownCommand(format!("kalyna-cmac {other}"))),
            None => Err(CliError::MissingFlag("compute|verify")),
        },
        "kalyna-gmac" => match sub {
            Some("compute") => run_gmac_command(false, &parse_gmac_args(&rest[1..])?),
            Some("verify") => run_gmac_command(true, &parse_gmac_args(&rest[1..])?),
            Some(other) => Err(CliError::UnknownCommand(format!("kalyna-gmac {other}"))),
            None => Err(CliError::MissingFlag("compute|verify")),
        },
        "kalyna-kw" => match sub {
            Some("wrap") => run_kw_command(false, &parse_kw_args(&rest[1..])?),
            Some("unwrap") => run_kw_command(true, &parse_kw_args(&rest[1..])?),
            Some(other) => Err(CliError::UnknownCommand(format!("kalyna-kw {other}"))),
            None => Err(CliError::MissingFlag("wrap|unwrap")),
        },
        _ => match sub {
            Some("encrypt") => run_xts_command(false, &parse_xts_args(&rest[1..])?),
            Some("decrypt") => run_xts_command(true, &parse_xts_args(&rest[1..])?),
            Some(other) => Err(CliError::UnknownCommand(format!("kalyna-xts {other}"))),
            None => Err(CliError::MissingFlag("encrypt|decrypt")),
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
            println!("uacrypt {}", env!("CARGO_PKG_VERSION"));
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
                Some(other) => Err(CliError::UnknownCommand(format!("kalyna-block {other}"))),
                None => Err(CliError::MissingFlag("encrypt|decrypt")),
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
                Some(other) => Err(CliError::UnknownCommand(format!("kalyna-ccm {other}"))),
                None => Err(CliError::MissingFlag("encrypt|decrypt")),
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
        Some(cmd @ ("sign-keygen" | "sign-pubkey" | "sign" | "verify")) => {
            dispatch_sign_command(cmd, &args[1..])
        }
        Some(other) => Err(CliError::UnknownCommand(other.to_string())),
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
        let args = vec![
            "--in".to_string(),
            "msg.bin".to_string(),
            "--out".to_string(),
            "digest.bin".to_string(),
        ];
        assert_eq!(
            parse_hash_args(&args),
            Ok(HashArgs {
                in_path: PathBuf::from("msg.bin"),
                out_path: PathBuf::from("digest.bin"),
            })
        );
    }

    #[test]
    fn parse_hash_args_requires_in_and_out() {
        assert_eq!(
            parse_hash_args(&["--out".to_string(), "digest.bin".to_string()]),
            Err(CliError::MissingFlag("in"))
        );
        assert_eq!(
            parse_hash_args(&["--in".to_string(), "msg.bin".to_string()]),
            Err(CliError::MissingFlag("out"))
        );
    }

    #[test]
    fn parse_hash_args_rejects_unknown_flag() {
        assert_eq!(
            parse_hash_args(&["--variant".to_string(), "256".to_string()]),
            Err(CliError::UnknownFlag("--variant".to_string()))
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
            Err(CliError::UnknownFlag("--variant".to_string()))
        );
    }

    #[test]
    fn run_keygen_command_writes_a_32_byte_key_usable_by_encrypt() {
        let dir = TempDir::new("keygen");
        let args = KeygenArgs {
            out_path: dir.file("key.bin"),
        };
        run_keygen_command(&args).expect("keygen should succeed");

        let key_bytes = std::fs::read(dir.file("key.bin")).expect("read generated key");
        assert_eq!(key_bytes.len(), 32);

        // The generated key is a real, usable crypto_secretstream key, not just 32 arbitrary
        // bytes - round-trip it through encrypt/decrypt to prove it, rather than only checking
        // the length.
        std::fs::write(dir.file("msg.bin"), b"keygen output must actually work").expect("write");
        let enc_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.enc"),
        };
        run_secretstream_command(false, &enc_args).expect("encrypt with generated key");
        let dec_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("msg.enc"),
            out_path: dir.file("msg.dec"),
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
    /// `Io` error, not a panic, same convention as `run_secretstream_command`'s directory tests.
    #[test]
    fn run_keygen_command_directory_as_out_is_io_error_not_panic() {
        let dir = TempDir::new("keygen_dir_out");
        std::fs::create_dir_all(dir.file("a_directory")).expect("create sub-directory");

        let args = KeygenArgs {
            out_path: dir.file("a_directory"),
        };
        assert!(matches!(
            run_keygen_command(&args),
            Err(CliError::Io { .. })
        ));
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
        assert_eq!(std::fs::read(dir.file("key.bin")).expect("read").len(), 32);
    }

    /// `hash` is fixed to Kupyna-256 (no `--variant` knob) and must genuinely stream a multi-chunk,
    /// non-chunk-aligned message from disk - same shape as
    /// `run_digest_command_streams_multi_chunk_input_correctly`, but through `run_hash_command`'s own
    /// dispatch (it delegates to `run_digest_command` internally, this confirms the delegation is
    /// wired correctly, not just that `run_digest_command` itself works).
    #[test]
    fn run_hash_command_matches_dstu_core_kupyna256_directly() {
        let dir = TempDir::new("hash_multichunk");
        let len = DIGEST_STREAM_CHUNK_BYTES * 2 + 513;
        let message: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(53)).collect();
        std::fs::write(dir.file("msg.bin"), &message).expect("write message");

        let args = HashArgs {
            in_path: dir.file("msg.bin"),
            out_path: dir.file("digest.bin"),
        };
        run_hash_command(&args).expect("hash run should succeed");
        assert_eq!(
            std::fs::read(dir.file("digest.bin")).expect("read"),
            Kupyna256::digest(&message).to_vec()
        );
    }

    #[test]
    fn run_dispatches_hash_command_correctly() {
        let dir = TempDir::new("hash_dispatch");
        std::fs::write(dir.file("msg.bin"), b"dispatch me").expect("write message");

        let args: Vec<String> = [
            "hash",
            "--in",
            dir.file("msg.bin").to_str().expect("valid utf-8 path"),
            "--out",
            dir.file("digest.bin").to_str().expect("valid utf-8 path"),
        ]
        .into_iter()
        .map(String::from)
        .collect();
        run(&args).expect("hash dispatch should succeed");
        assert_eq!(
            std::fs::read(dir.file("digest.bin")).expect("read"),
            Kupyna256::digest(b"dispatch me").to_vec()
        );
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
            Err(CliError::UnknownFlag("--nonce".to_string()))
        );
    }

    #[test]
    fn run_secretstream_command_round_trip_matches_dstu_core_directly() {
        let dir = TempDir::new("secretstream_roundtrip");
        let key_bytes = [0x22u8; 32];
        let plaintext = b"short message".to_vec();
        std::fs::write(dir.file("key.bin"), key_bytes).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
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
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let base_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed1.bin"),
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
            &sealed1[..SECRETSTREAM_HEADER_LEN],
            &sealed2[..SECRETSTREAM_HEADER_LEN],
            "two encrypt calls with the same key/plaintext must not reuse a header"
        );
    }

    #[test]
    fn run_secretstream_command_decrypt_rejects_tampered_ciphertext_without_writing_out() {
        let dir = TempDir::new("secretstream_tamper");
        let key = [0x66u8; 32];
        let plaintext = b"do not trust me".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let mut tampered = std::fs::read(dir.file("sealed.bin")).expect("read sealed");
        // Byte just past the header - inside the single chunk's ciphertext.
        tampered[SECRETSTREAM_HEADER_LEN] ^= 0x01;
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
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &large).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("sealed.bin"),
            out_path: dir.file("out.bin"),
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
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), []).expect("write empty input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("sealed.bin"),
            out_path: dir.file("out.bin"),
        };
        run_secretstream_command(true, &decrypt_args).expect("decrypt should succeed");
        assert_eq!(std::fs::read(dir.file("out.bin")).expect("read output"), []);
    }

    /// "Fool" test - a key file that's the wrong length (a common real mistake: a truncated
    /// download, a copy-paste that dropped bytes) must be a clean, typed error, not a panic or a
    /// silently-zero-padded key.
    #[test]
    fn run_secretstream_command_wrong_key_length_is_rejected() {
        let dir = TempDir::new("secretstream_wrong_key_len");
        std::fs::write(dir.file("key.bin"), [0u8; 31]).expect("write short key");
        std::fs::write(dir.file("in.bin"), b"data").expect("write input");

        let args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("out.bin"),
        };
        assert_eq!(
            run_secretstream_command(false, &args),
            Err(CliError::WrongLength {
                what: "key",
                expected: 32,
                actual: 31,
            })
        );
        assert!(!dir.file("out.bin").exists());
    }

    /// "Fool" test - pointing `--in` at a path that doesn't exist at all (typo'd filename) must be
    /// a clean `Io` error, not a panic.
    #[test]
    fn run_secretstream_command_nonexistent_input_is_io_error_not_panic() {
        let dir = TempDir::new("secretstream_no_input");
        std::fs::write(dir.file("key.bin"), [0u8; 32]).expect("write key");

        let args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("does_not_exist.bin"),
            out_path: dir.file("out.bin"),
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
        std::fs::write(dir.file("key.bin"), [0u8; 32]).expect("write key");
        std::fs::create_dir_all(dir.file("a_directory")).expect("create sub-directory");

        let args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("a_directory"),
            out_path: dir.file("out.bin"),
        };
        assert!(matches!(
            run_secretstream_command(false, &args),
            Err(CliError::Io { .. })
        ));
        assert!(!dir.file("out.bin").exists());
    }

    /// "Fool" test - passing the same path for `--in` and `--out` (an easy mistake when scripting
    /// "encrypt this file in place"). The temp-file-then-rename atomicity (module doc) is what
    /// keeps this safe under genuine streaming I/O, not a whole-buffer read like the old
    /// `crypto_secretbox`-backed command relied on.
    #[test]
    fn run_secretstream_command_in_and_out_same_path_round_trips() {
        let dir = TempDir::new("secretstream_same_path");
        let key = [0x55u8; 32];
        let plaintext = b"overwrite me in place".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("data.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("data.bin"),
            out_path: dir.file("data.bin"),
        };
        run_secretstream_command(false, &encrypt_args).expect("in-place encrypt should succeed");
        assert_ne!(
            std::fs::read(dir.file("data.bin")).expect("read"),
            plaintext,
            "the file must now hold sealed output, not the original plaintext"
        );

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("data.bin"),
            out_path: dir.file("data.bin"),
        };
        run_secretstream_command(true, &decrypt_args).expect("in-place decrypt should succeed");
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
        std::fs::write(dir.file("key.bin"), [0x88u8; 32]).expect("write key");
        std::fs::write(dir.file("garbage.bin"), [0x99u8; 64]).expect("write garbage");

        let args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("garbage.bin"),
            out_path: dir.file("out.bin"),
        };
        // 64 bytes of garbage: the first 32 are read as a header (always succeeds - any bytes are
        // a valid header), then the next 5 bytes are read as a chunk prefix - the 0x99 length
        // bytes decode to a chunk_len far larger than SECRETSTREAM_CHUNK_BYTES, so this fails the
        // sanity bound before ever reaching authentication.
        assert_eq!(
            run_secretstream_command(true, &args),
            Err(CliError::SecretstreamChunkTooLarge)
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
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let sealed = std::fs::read(dir.file("sealed.bin")).expect("read sealed");
        let cut = &sealed[..sealed.len() - 1];
        std::fs::write(dir.file("truncated.bin"), cut).expect("write truncated output");

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("truncated.bin"),
            out_path: dir.file("out.bin"),
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
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &plaintext).expect("write input");

        let encrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: dir.file("sealed.bin"),
        };
        run_secretstream_command(false, &encrypt_args).expect("encrypt should succeed");

        let mut extended = std::fs::read(dir.file("sealed.bin")).expect("read sealed");
        extended.push(0xAA);
        std::fs::write(dir.file("extended.bin"), &extended).expect("write extended output");

        let decrypt_args = SecretstreamArgs {
            key_path: dir.file("key.bin"),
            in_path: dir.file("extended.bin"),
            out_path: dir.file("out.bin"),
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
        std::fs::write(dir.file("empty.bin"), []).expect("write empty file");

        let args = HashArgs {
            in_path: dir.file("empty.bin"),
            out_path: dir.file("digest.bin"),
        };
        run_hash_command(&args).expect("hashing an empty file must succeed");

        let digest = std::fs::read(dir.file("digest.bin")).expect("read digest");
        assert_eq!(
            digest,
            dstu_core::hazmat::kupyna::Kupyna256::digest(&[]).to_vec()
        );
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
        })
        .expect("iterations=0 must still hash successfully");
        run_digest_command(&DigestArgs {
            variant: HashBits::B256,
            in_path: dir.file("msg.bin"),
            out_path: dir.file("digest_one.bin"),
            iterations: 1,
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
        };
        assert_eq!(
            run_ccm_command(false, &args),
            Err(CliError::WrongLength {
                what: "key",
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
        };
        assert_eq!(
            run_ccm_command(true, &args),
            Err(CliError::WrongLength {
                what: "nonce",
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
        std::fs::write(dir.file("key.bin"), key).expect("write key");
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
        };
        run_strumok_command(&args).expect("strumok command should succeed");

        let mut expected = plaintext.clone();
        Strumok512::new(&key, &iv).apply_keystream(&mut expected);
        assert_eq!(std::fs::read(dir.file("out.bin")).expect("read"), expected);
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
            Err(CliError::UnknownCommand("bogus".to_string()))
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
        };
        assert_eq!(
            run_gcm_command(false, &args),
            Err(CliError::WrongLength {
                what: "key",
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
        };
        run_cmac_command(false, &compute_args).expect("compute should succeed");

        let expected_tag = Kalyna128_128Cmac::mac(&key, &message);
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

    #[test]
    fn run_cmac_command_verify_rejects_tampered_tag() {
        let dir = TempDir::new("kalyna_cmac_tamper");
        let key = [0x55u8; 16];
        let message = b"do not forge me".to_vec();
        std::fs::write(dir.file("key.bin"), key).expect("write key");
        std::fs::write(dir.file("in.bin"), &message).expect("write message");

        let mut tag = Kalyna128_128Cmac::mac(&key, &message);
        tag[0] ^= 0x01;
        std::fs::write(dir.file("tag.bin"), tag).expect("write tampered tag");

        let verify_args = CmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: None,
            tag_path: Some(dir.file("tag.bin")),
            iterations: 1,
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
        };
        run_gmac_command(false, &compute_args).expect("compute should succeed");

        let expected_tag = Kalyna128_128Gmac::mac(&key, &message);
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

        let mut tag = Kalyna128_128Gmac::mac(&key, &message);
        tag[0] ^= 0x01;
        std::fs::write(dir.file("tag.bin"), tag).expect("write tampered tag");

        let verify_args = GmacArgs {
            variant: KalynaVariant::K128_128,
            key_path: dir.file("key.bin"),
            in_path: dir.file("in.bin"),
            out_path: None,
            tag_path: Some(dir.file("tag.bin")),
            iterations: 1,
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
                matches!(result, Err(CliError::UnknownCommand(_))),
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
            Err(CliError::UnknownFlag("--variant".to_string()))
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
            Err(CliError::UnknownFlag("--variant".to_string()))
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
            Err(CliError::UnknownFlag("--variant".to_string()))
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
            Err(CliError::UnknownFlag("--variant".to_string()))
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
        })
        .expect("sign should succeed");

        let sig_bytes = std::fs::read(dir.file("msg.sig")).expect("read signature");
        assert_eq!(sig_bytes.len(), 42);
        let key_bytes = std::fs::read(dir.file("verifying.key")).expect("read verifying key");
        assert_eq!(key_bytes.len(), 42);

        run_verify_command(&VerifyArgs {
            key_path: dir.file("verifying.key"),
            in_path: dir.file("msg.bin"),
            sig_path: dir.file("msg.sig"),
            iterations: 1,
        })
        .expect("verify should succeed on the real signature");
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
        std::fs::write(dir.file("signing.key"), signing_key.to_bytes()).expect("write key");
        std::fs::write(dir.file("msg.bin"), b"cross-check me").expect("write message");

        run_sign_command(&SignArgs {
            key_path: dir.file("signing.key"),
            in_path: dir.file("msg.bin"),
            out_path: dir.file("msg.sig"),
            iterations: 1,
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
        assert!(matches!(
            run_sign_keygen_command(&SignKeygenArgs {
                out_path: dir.file("a_directory"),
            }),
            Err(CliError::Io { .. })
        ));
    }

    #[test]
    fn run_sign_pubkey_command_directory_as_out_is_io_error_not_panic() {
        let dir = TempDir::new("sign_pubkey_dir_out");
        std::fs::create_dir_all(dir.file("a_directory")).expect("create sub-directory");
        std::fs::write(dir.file("signing.key"), small_signing_key(0x11)).expect("write key");
        assert!(matches!(
            run_sign_pubkey_command(&SignPubkeyArgs {
                key_path: dir.file("signing.key"),
                out_path: dir.file("a_directory"),
            }),
            Err(CliError::Io { .. })
        ));
    }

    #[test]
    fn run_sign_pubkey_command_wrong_key_length_is_rejected() {
        let dir = TempDir::new("sign_pubkey_wrong_len");
        std::fs::write(dir.file("signing.key"), [0x11u8; 20]).expect("write short key");
        assert_eq!(
            run_sign_pubkey_command(&SignPubkeyArgs {
                key_path: dir.file("signing.key"),
                out_path: dir.file("verifying.key"),
            }),
            Err(CliError::WrongLength {
                what: "signing key",
                expected: 21,
                actual: 20,
            })
        );
    }

    #[test]
    fn run_sign_command_wrong_key_length_is_rejected() {
        let dir = TempDir::new("sign_wrong_len");
        std::fs::write(dir.file("signing.key"), [0x11u8; 20]).expect("write short key");
        std::fs::write(dir.file("msg.bin"), b"hello").expect("write message");
        assert_eq!(
            run_sign_command(&SignArgs {
                key_path: dir.file("signing.key"),
                in_path: dir.file("msg.bin"),
                out_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::WrongLength {
                what: "signing key",
                expected: 21,
                actual: 20,
            })
        );
    }

    /// A zero scalar is the right length (21 bytes) but not a valid private key - a distinct
    /// misuse case from the wrong-length one above, and one only `SignKeyInvalid` (not
    /// `WrongLength`) can report.
    #[test]
    fn run_sign_command_zero_key_is_rejected() {
        let dir = TempDir::new("sign_zero_key");
        std::fs::write(dir.file("signing.key"), [0u8; 21]).expect("write zero key");
        std::fs::write(dir.file("msg.bin"), b"hello").expect("write message");
        assert_eq!(
            run_sign_command(&SignArgs {
                key_path: dir.file("signing.key"),
                in_path: dir.file("msg.bin"),
                out_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::SignKeyInvalid)
        );
    }

    #[test]
    fn run_sign_command_nonexistent_input_is_io_error_not_panic() {
        let dir = TempDir::new("sign_missing_in");
        std::fs::write(dir.file("signing.key"), small_signing_key(0x11)).expect("write key");
        assert!(matches!(
            run_sign_command(&SignArgs {
                key_path: dir.file("signing.key"),
                in_path: dir.file("does_not_exist.bin"),
                out_path: dir.file("msg.sig"),
                iterations: 1,
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
    fn run_verify_command_wrong_key_length_is_rejected() {
        let dir = TempDir::new("verify_wrong_key_len");
        std::fs::write(dir.file("verifying.key"), [0x11u8; 41]).expect("write short key");
        std::fs::write(dir.file("msg.bin"), b"hello").expect("write message");
        std::fs::write(dir.file("msg.sig"), [0x22u8; 42]).expect("write signature");
        assert_eq!(
            run_verify_command(&VerifyArgs {
                key_path: dir.file("verifying.key"),
                in_path: dir.file("msg.bin"),
                sig_path: dir.file("msg.sig"),
                iterations: 1,
            }),
            Err(CliError::WrongLength {
                what: "verifying key",
                expected: 42,
                actual: 41,
            })
        );
    }

    #[test]
    fn run_verify_command_wrong_signature_length_is_rejected() {
        let dir = TempDir::new("verify_wrong_sig_len");
        std::fs::write(dir.file("verifying.key"), [0x11u8; 42]).expect("write key");
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
                what: "signature",
                expected: 42,
                actual: 41,
            })
        );
    }

    #[test]
    fn run_verify_command_nonexistent_input_is_io_error_not_panic() {
        let dir = TempDir::new("verify_missing_in");
        std::fs::write(dir.file("verifying.key"), [0x11u8; 42]).expect("write key");
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

    #[test]
    fn run_unknown_sign_family_subcommand_is_rejected() {
        // Unlike `kalyna-gcm`/etc., `sign`/`verify`/`sign-keygen`/`sign-pubkey` are flat top-level
        // commands with no sub-subcommand - an unrecognized flag surfaces as `UnknownFlag`, not
        // `UnknownCommand`, since `dispatch_sign_command` hands `rest` straight to `parse_*_args`.
        assert_eq!(
            run(&["sign".to_string(), "--bogus".to_string()]),
            Err(CliError::UnknownFlag("--bogus".to_string()))
        );
    }
}
