#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `uacrypt`'s testable logic - `main.rs` is a thin wrapper that calls [`run`] and maps the
//! result to a process exit code.
//!
//! **`kalyna-block` is deliberately not named `encrypt`/`decrypt`** - those names are reserved for
//! the future file-plus-mode-of-operation CLI (`CLAUDE.md` MVP scope: `uacrypt encrypt --key ...
//! --in file --out file`), which is blocked on `DECISIONS.md` D-05 (no mode of operation exists
//! yet - official DSTU 7624 text or another authoritative source needed first). This command only
//! does what `hazmat::kalyna` actually supports: exactly one block, no mode, no padding - so it
//! can't be mistaken for that future command.
//!
//! The `--iterations`/`--raw-schedule` flags exist for the binary-vs-binary performance comparison
//! in `PERFORMANCE.md` (`TASKS.md`, D-28/29/30 follow-up) - with `iterations <= 1` this is just a
//! single-block file operation.

use dstu_core::hazmat::kalyna::{
    Kalyna128_128, Kalyna128_128ExpandedKey, Kalyna128_256, Kalyna128_256ExpandedKey,
    Kalyna256_256, Kalyna256_256ExpandedKey, Kalyna256_512, Kalyna256_512ExpandedKey,
    Kalyna512_512, Kalyna512_512ExpandedKey,
};
use dstu_core::hazmat::kalyna_ccm::{
    Kalyna128_128Ccm, Kalyna128_256Ccm, Kalyna256_256Ccm, Kalyna256_512Ccm, Kalyna512_512Ccm,
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
    Random(String),
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
            CliError::Random(message) => write!(f, "failed to generate a random nonce: {message}"),
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

/// The five Kalyna block/key-size variants (`DECISIONS.md` D-13), addressed the same way
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
/// once, reused) - see `DECISIONS.md` D-29 for why both numbers matter.
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
    /// Output path on `encrypt` (a fresh random nonce is generated and written here, `DECISIONS.md`
    /// D-40), input path on `decrypt` (must be the value `encrypt` produced).
    pub nonce_path: PathBuf,
    pub aad_path: Option<PathBuf>,
    pub in_path: PathBuf,
    pub out_path: PathBuf,
    pub tag_path: PathBuf,
}

/// Parses `kalyna-ccm encrypt`/`decrypt`'s flags: `--variant`/`--key`/`--nonce`/`--in`/`--out`/
/// `--tag` required, `--aad` optional (an empty AAD is used if omitted). `--nonce` is always
/// required as a *path* by the parser, but [`run_ccm_command`] treats it as an output on encrypt
/// and an input on decrypt - see [`CcmArgs::nonce_path`].
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
    })
}

/// Runs `kalyna-ccm encrypt`/`decrypt` - see `hazmat::kalyna_ccm`'s module doc comment for the
/// construction's provisional status and sourced 255-byte plaintext/AAD limit. Encrypt writes
/// ciphertext to `--out`, the authentication tag to `--tag`, **and a freshly-generated random
/// nonce to `--nonce`** (separate files - this CLI does not invent its own combined wire format).
/// `--nonce` is an *output* on encrypt, not an input: per `DECISIONS.md` D-40, the nonce is never
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
        getrandom::fill(&mut generated).map_err(|e| CliError::Random(e.to_string()))?;
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

    macro_rules! run_ccm_variant {
        ($cipher:ty, $key_len:literal, $block_len:literal, $tag_len:literal) => {{
            let mut key_arr = [0u8; $key_len];
            key_arr.copy_from_slice(&key);
            let mut nonce_arr = [0u8; $block_len];
            nonce_arr.copy_from_slice(&nonce);
            let cipher = <$cipher>::new(&key_arr);

            let mut buf = input.clone();
            if decrypt {
                let tag = read_exact_file(&args.tag_path, "tag", $tag_len)?;
                let mut tag_arr = [0u8; $tag_len];
                tag_arr.copy_from_slice(&tag);
                cipher.open_in_place(&nonce_arr, &aad, &mut buf, &tag_arr)?;
                (buf, None)
            } else {
                let tag = cipher.seal_in_place(&nonce_arr, &aad, &mut buf)?;
                (buf, Some(tag.to_vec()))
            }
        }};
    }

    let (output, tag) = match args.variant {
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

    Ok(())
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
/// already recorded in `PERFORMANCE.md`.
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
/// negligible. `Strumok::apply_keystream`'s own chunk-invariance (`TASKS.md` T-24) is exactly what
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

/// Top-level dispatch - `args` excludes the program name (`std::env::args().skip(1)`).
///
/// # Errors
///
/// Returns [`CliError::UnknownCommand`] for an unrecognized (sub)command, or whatever the
/// relevant `parse_*_args`/`run_*_command` returns for the matched one.
pub fn run(args: &[String]) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        Some("kalyna-block") => {
            let rest = &args[1..];
            match rest.first().map(String::as_str) {
                Some("encrypt") => run_block_command(false, &parse_block_args(&rest[1..])?),
                Some("decrypt") => run_block_command(true, &parse_block_args(&rest[1..])?),
                Some(other) => Err(CliError::UnknownCommand(format!("kalyna-block {other}"))),
                None => Err(CliError::MissingFlag("encrypt|decrypt")),
            }
        }
        Some("kalyna-ccm") => {
            let rest = &args[1..];
            match rest.first().map(String::as_str) {
                Some("encrypt") => run_ccm_command(false, &parse_ccm_args(&rest[1..])?),
                Some("decrypt") => run_ccm_command(true, &parse_ccm_args(&rest[1..])?),
                Some(other) => Err(CliError::UnknownCommand(format!("kalyna-ccm {other}"))),
                None => Err(CliError::MissingFlag("encrypt|decrypt")),
            }
        }
        Some("kupyna-digest") => run_digest_command(&parse_digest_args(&args[1..])?),
        Some("strumok-crypt") => run_strumok_command(&parse_strumok_args(&args[1..])?),
        Some(other) => Err(CliError::UnknownCommand(other.to_string())),
        None => Err(CliError::UnknownCommand(String::new())),
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
}
