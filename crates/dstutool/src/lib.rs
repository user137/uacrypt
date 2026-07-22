#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `dstutool`'s testable logic - `main.rs` is a thin wrapper that calls [`run`] and maps the
//! result to a process exit code.
//!
//! **`kalyna-block` is deliberately not named `encrypt`/`decrypt`** - those names are reserved for
//! the future file-plus-mode-of-operation CLI (`CLAUDE.md` MVP scope: `dstutool encrypt --key ...
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

/// Top-level dispatch - `args` excludes the program name (`std::env::args().skip(1)`).
///
/// # Errors
///
/// Returns [`CliError::UnknownCommand`] for an unrecognized (sub)command, or whatever
/// [`parse_block_args`]/[`run_block_command`] returns for `kalyna-block encrypt`/`decrypt`.
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
        Some(other) => Err(CliError::UnknownCommand(other.to_string())),
        None => Err(CliError::UnknownCommand(String::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
