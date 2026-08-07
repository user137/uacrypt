//! `cargo xtask bench-compare` (T-187) - one path, one output shape, for every
//! DSTU-standard-level comparison against OpenSSL that `docs/PERFORMANCE.md`'s "vs.
//! international-standard analogs" (D-106) section otherwise documents as five separate,
//! hand-typed shell recipes. Prints markdown tables in the same shape already used there - copy
//! into the doc on a refresh, this command does not edit it (the prose caveats around each table
//! are load-bearing, not decoration - D-34/D-106).
//!
//! Deliberately not in `ci()`'s loop, unlike `book`/`docs_check` in `main.rs`: this project's own
//! stated methodology (`docs/PERFORMANCE.md` "not a rigorous academic benchmark suite... real
//! numbers from a real development machine") means a noisy shared CI runner would produce
//! misleading numbers - no perf comparison has ever run in CI here, and this command doesn't
//! change that.
//!
//! Methodology, one path for both sides:
//! - `uacrypt` side: the CLI's own `--iterations N` benchmarking mode already self-reports
//!   `total_ns`/`per_op_ns`/`ops_per_s`/`mb_per_s` as `key=value` pairs on stderr (confirmed by
//!   running it, not assumed) - this parses that instead of wall-clocking the process itself, the
//!   same "trust the already-validated tool's own timer" choice made for `openssl speed` below.
//! - OpenSSL side (AES/Whirlpool/ChaCha20/ECDSA/ECDH): parses `openssl speed`'s own `Doing ... :
//!   N ... ops in Ts` lines directly (every algorithm family it supports uses this exact shape,
//!   spiked directly) rather than reimplementing its internal timing loop.
//! - OpenSSL CMS (DSTU 9041/`crypto_box`'s same-regime table only): `openssl speed` has no CMS
//!   support, so this is the one case that wall-clocks external `openssl cms` invocations itself,
//!   matching the existing hand-documented "Reproducing (same-regime)" recipe.
//!
//! **Curve substitution, flagged explicitly**: `docs/PERFORMANCE.md`'s existing DSTU 9041 ops/s
//! table reads `brainpoolP256r1`'s line positionally out of the unfiltered `openssl speed ecdh`
//! output (no way to select just that curve by name was found - spiked directly, `ecdh<name>`
//! only resolves NIST-named curves like `ecdhp256`/`ecdhb163`, not brainpool). This command uses
//! `ecdhp256` (NIST P-256) instead - same 256-bit-prime-field class, selectable by name without
//! relying on a fixed, version-dependent line ordering, and already the exact curve this project
//! uses for DSTU 4145's own ECDSA comparison two sections earlier in the same doc.

use crate::require;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const MIB: f64 = 1024.0 * 1024.0;

fn scratch_dir() -> PathBuf {
    std::env::temp_dir().join("uacrypt-bench-compare")
}

fn uacrypt_binary() -> PathBuf {
    let name = if cfg!(windows) {
        "uacrypt.exe"
    } else {
        "uacrypt"
    };
    Path::new("target/release").join(name)
}

fn write_zeros(path: &Path, len: usize) -> bool {
    fs::write(path, vec![0u8; len]).is_ok()
}

/// `uacrypt <args> --iterations N` already prints `key=value` benchmark fields to stderr - this
/// parses that line instead of timing the process itself.
fn run_uacrypt(args: &[&str]) -> Option<HashMap<String, f64>> {
    let bin = uacrypt_binary();
    println!("+ {} {}", bin.display(), args.join(" "));
    let output = Command::new(&bin).args(args).output().ok()?;
    if !output.status.success() {
        eprintln!(
            "xtask: bench-compare: uacrypt {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Some(
        stderr
            .split_whitespace()
            .filter_map(|tok| tok.split_once('='))
            .filter_map(|(k, v)| Some((k.to_string(), v.parse::<f64>().ok()?)))
            .collect(),
    )
}

/// Parses every `Doing ... : N ... ops in Ts` line from `openssl speed`'s stdout, in order.
fn parse_openssl_speed(stdout: &str) -> Vec<(u64, f64)> {
    stdout
        .lines()
        .filter(|line| line.starts_with("Doing"))
        .filter_map(|line| {
            let after_colon = line.split_once(": ")?.1;
            let n: u64 = after_colon.split_whitespace().next()?.parse().ok()?;
            let (_, after_ops_in) = after_colon.split_once("ops in ")?;
            let t: f64 = after_ops_in.trim().trim_end_matches('s').parse().ok()?;
            Some((n, t))
        })
        .collect()
}

fn run_openssl_speed(args: &[&str], extra_env: &[(&str, &str)]) -> Vec<(u64, f64)> {
    println!("+ openssl speed {}", args.join(" "));
    let mut cmd = Command::new("openssl");
    cmd.arg("speed").args(args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    match cmd.output() {
        // The "Doing ... ops in Ts" progress line is on stderr, not stdout (only the final
        // summary table - "type / AES-128-ECB  1012371.39k" - goes to stdout) - confirmed by
        // running it for real, not assumed from the manual `2>&1`-merged spike earlier.
        Ok(out) => parse_openssl_speed(&String::from_utf8_lossy(&out.stderr)),
        Err(e) => {
            eprintln!(
                "xtask: bench-compare: 'openssl speed {}' failed: {e}",
                args.join(" ")
            );
            Vec::new()
        }
    }
}

fn ops_per_sec((n, t): (u64, f64)) -> f64 {
    n as f64 / t
}

fn mib_per_sec((n, t): (u64, f64), bytes_per_op: u64) -> f64 {
    (n * bytes_per_op) as f64 / t / MIB
}

fn table_header(unit: &str) {
    println!("| Metric | uacrypt | OpenSSL analog | Ratio |");
    println!("|---|---|---|---|");
    let _ = unit;
}

fn print_row(metric: &str, ours: f64, analog_label: &str, analog: f64, unit: &str) {
    let verdict = if ours <= 0.0 || analog <= 0.0 {
        "n/a".to_string()
    } else if analog >= ours {
        format!("{:.2}x faster ({analog_label})", analog / ours)
    } else {
        format!("{:.2}x slower ({analog_label})", ours / analog)
    };
    println!("| {metric} | {ours:.2} {unit} | {analog:.2} {unit} | {verdict} |");
}

fn bench_kalyna_vs_aes(dir: &Path) {
    println!("\n## Kalyna vs. AES (single block, MB/s)\n");
    table_header("MB/s");

    let cases: &[(&str, &str, usize, &str)] = &[
        ("128-128", "aes-128-ecb", 16, "AES-128-ECB"),
        ("128-256", "aes-256-ecb", 32, "AES-256-ECB"),
    ];

    for (variant, aes_name, key_len, label) in cases {
        let key_path = dir.join(format!("kalyna-key-{key_len}.bin"));
        let block_path = dir.join("kalyna-block.bin");
        let out_path = dir.join("kalyna-block.out");
        if !write_zeros(&key_path, *key_len) || !write_zeros(&block_path, 16) {
            continue;
        }
        let Some(fields) = run_uacrypt(&[
            "kalyna-block",
            "encrypt",
            "--variant",
            variant,
            "--key",
            &key_path.to_string_lossy(),
            "--in",
            &block_path.to_string_lossy(),
            "--out",
            &out_path.to_string_lossy(),
            "--iterations",
            "500000",
        ]) else {
            continue;
        };
        let Some(&per_op_ns) = fields.get("per_op_ns") else {
            continue;
        };
        let ours_mib_s = (16.0 / (per_op_ns / 1e9)) / MIB;

        let openssl_out = run_openssl_speed(
            &[
                "-elapsed", "-evp", aes_name, "-bytes", "16", "-seconds", "2",
            ],
            &[],
        );
        let Some(&result) = openssl_out.first() else {
            continue;
        };
        let analog_mib_s = mib_per_sec(result, 16);
        print_row(variant, ours_mib_s, label, analog_mib_s, "MB/s");
    }
}

fn bench_kupyna_vs_whirlpool(dir: &Path) {
    println!("\n## Kupyna vs. Whirlpool (digest, MB/s)\n");
    table_header("MB/s");

    let sizes: &[(&str, usize, u64)] = &[
        ("16 KiB", 16 * 1024, 2000),
        ("10 MiB", 10 * 1024 * 1024, 20),
    ];

    for (size_label, size_bytes, iterations) in sizes {
        let in_path = dir.join(format!("kupyna-in-{size_bytes}.bin"));
        if !write_zeros(&in_path, *size_bytes) {
            continue;
        }
        let openssl_out = run_openssl_speed(
            &[
                "-provider",
                "legacy",
                "-provider",
                "default",
                "-elapsed",
                "-evp",
                "whirlpool",
                "-bytes",
                &size_bytes.to_string(),
                "-seconds",
                "2",
            ],
            &[],
        );
        let Some(&whirlpool_result) = openssl_out.first() else {
            continue;
        };
        let analog_mib_s = mib_per_sec(whirlpool_result, *size_bytes as u64);

        for variant in ["256", "512"] {
            let out_path = dir.join("kupyna-out.bin");
            let Some(fields) = run_uacrypt(&[
                "kupyna-digest",
                "--variant",
                variant,
                "--in",
                &in_path.to_string_lossy(),
                "--out",
                &out_path.to_string_lossy(),
                "--iterations",
                &iterations.to_string(),
            ]) else {
                continue;
            };
            let Some(&ours_mib_s) = fields.get("mb_per_s") else {
                continue;
            };
            print_row(
                &format!("Kupyna-{variant}, {size_label}"),
                ours_mib_s,
                "Whirlpool",
                analog_mib_s,
                "MB/s",
            );
        }
    }
}

fn bench_strumok_vs_chacha20(dir: &Path) {
    println!("\n## Strumok vs. ChaCha20 (keystream, MB/s)\n");
    table_header("MB/s");

    let iv_path = dir.join("strumok-iv.bin");
    if !write_zeros(&iv_path, 32) {
        return;
    }

    let sizes: &[(&str, usize, u64)] = &[
        ("16 KiB", 16 * 1024, 3000),
        ("10 MiB", 10 * 1024 * 1024, 30),
    ];

    for (size_label, size_bytes, iterations) in sizes {
        let in_path = dir.join(format!("strumok-in-{size_bytes}.bin"));
        if !write_zeros(&in_path, *size_bytes) {
            continue;
        }
        let openssl_out = run_openssl_speed(
            &[
                "-elapsed",
                "-evp",
                "chacha20",
                "-bytes",
                &size_bytes.to_string(),
                "-seconds",
                "2",
            ],
            &[],
        );
        let Some(&chacha_result) = openssl_out.first() else {
            continue;
        };
        let analog_mib_s = mib_per_sec(chacha_result, *size_bytes as u64);

        for (variant, key_len) in [("256", 32usize), ("512", 64usize)] {
            let key_path = dir.join(format!("strumok-key-{key_len}.bin"));
            let out_path = dir.join("strumok-out.bin");
            if !write_zeros(&key_path, key_len) {
                continue;
            }
            let Some(fields) = run_uacrypt(&[
                "strumok-crypt",
                "--variant",
                variant,
                "--key",
                &key_path.to_string_lossy(),
                "--iv",
                &iv_path.to_string_lossy(),
                "--in",
                &in_path.to_string_lossy(),
                "--out",
                &out_path.to_string_lossy(),
                "--iterations",
                &iterations.to_string(),
            ]) else {
                continue;
            };
            let Some(&ours_mib_s) = fields.get("mb_per_s") else {
                continue;
            };
            print_row(
                &format!("Strumok-{variant}, {size_label}"),
                ours_mib_s,
                "ChaCha20 (AVX2)",
                analog_mib_s,
                "MB/s",
            );
        }
    }
}

fn bench_dstu4145_vs_ecdsa(dir: &Path) {
    println!("\n## DSTU 4145 vs. ECDSA (sign/verify, ops/s)\n");
    table_header("ops/s");

    let sk_path = dir.join("sign.key");
    let vk_path = dir.join("verify.key");
    let msg_path = dir.join("sign-msg.bin");
    let sig_path = dir.join("sign.sig");
    if !write_zeros(&msg_path, 64) {
        return;
    }
    if run_uacrypt(&["sign-keygen", "--out", &sk_path.to_string_lossy()]).is_none() {
        return;
    }
    if run_uacrypt(&[
        "sign-pubkey",
        "--key",
        &sk_path.to_string_lossy(),
        "--out",
        &vk_path.to_string_lossy(),
    ])
    .is_none()
    {
        return;
    }

    let Some(sign_fields) = run_uacrypt(&[
        "sign",
        "--key",
        &sk_path.to_string_lossy(),
        "--in",
        &msg_path.to_string_lossy(),
        "--out",
        &sig_path.to_string_lossy(),
        "--iterations",
        "1000",
    ]) else {
        return;
    };
    let Some(&ours_sign) = sign_fields.get("ops_per_s") else {
        return;
    };

    let Some(verify_fields) = run_uacrypt(&[
        "verify",
        "--key",
        &vk_path.to_string_lossy(),
        "--in",
        &msg_path.to_string_lossy(),
        "--sig",
        &sig_path.to_string_lossy(),
        "--iterations",
        "1000",
    ]) else {
        return;
    };
    let Some(&ours_verify) = verify_fields.get("ops_per_s") else {
        return;
    };

    for (curve, label) in [("ecdsab163", "nistb163"), ("ecdsap256", "nistp256")] {
        let out = run_openssl_speed(&["-elapsed", "-seconds", "2", curve], &[]);
        let (Some(&sign_result), Some(&verify_result)) = (out.first(), out.get(1)) else {
            continue;
        };
        print_row(
            "sign/s",
            ours_sign,
            label,
            ops_per_sec(sign_result),
            "ops/s",
        );
        print_row(
            "verify/s",
            ours_verify,
            label,
            ops_per_sec(verify_result),
            "ops/s",
        );
    }
}

fn bench_dstu9041_vs_ecdh_cms(dir: &Path) -> bool {
    println!("\n## DSTU 9041 / crypto_box vs. ECDH (primitive-level, ops/s)\n");
    table_header("ops/s");

    let box_sk = dir.join("box.key");
    let box_pk = dir.join("box.pub");
    let small_msg = dir.join("box-msg.bin");
    let small_box = dir.join("box-msg.box");
    let small_out = dir.join("box-msg.out");
    if !write_zeros(&small_msg, 32) {
        return false;
    }
    if run_uacrypt(&["box-keygen", "--out", &box_sk.to_string_lossy()]).is_none() {
        return false;
    }
    if run_uacrypt(&[
        "box-pubkey",
        "--key",
        &box_sk.to_string_lossy(),
        "--out",
        &box_pk.to_string_lossy(),
    ])
    .is_none()
    {
        return false;
    }

    let Some(seal_fields) = run_uacrypt(&[
        "box-seal",
        "--key",
        &box_pk.to_string_lossy(),
        "--in",
        &small_msg.to_string_lossy(),
        "--out",
        &small_box.to_string_lossy(),
        "--iterations",
        "1000",
    ]) else {
        return false;
    };
    let Some(&ours_seal) = seal_fields.get("ops_per_s") else {
        return false;
    };

    let Some(open_fields) = run_uacrypt(&[
        "box-open",
        "--key",
        &box_sk.to_string_lossy(),
        "--in",
        &small_box.to_string_lossy(),
        "--out",
        &small_out.to_string_lossy(),
        "--iterations",
        "1000",
    ]) else {
        return false;
    };
    let Some(&ours_open) = open_fields.get("ops_per_s") else {
        return false;
    };

    // Curve substitution: `ecdhp256` (NIST P-256), see this module's own doc comment for why -
    // `brainpoolP256r1` has no clean name filter under `openssl speed`, `ecdhp256` does.
    for (curve, label) in [
        ("ecdhp256", "OpenSSL ECDH nistp256"),
        ("ecdhx25519", "OpenSSL ECDH X25519"),
    ] {
        let out = run_openssl_speed(&["-elapsed", "-seconds", "2", curve], &[]);
        let Some(&result) = out.first() else {
            continue;
        };
        let analog = ops_per_sec(result);
        print_row("box-seal", ours_seal, label, analog, "ops/s");
        print_row("box-open", ours_open, label, analog, "ops/s");
    }

    true
}

/// Same-regime table (D-34's "match the regime" rule): a full 10 MiB seal/open against OpenSSL's
/// own hybrid envelope (CMS), not the bare-scalar-multiplication `ecdh` comparison above. `openssl
/// cms` has no `-iterations`/self-timing support, so this is the one case in this module that
/// wall-clocks external invocations itself.
fn bench_dstu9041_vs_cms(dir: &Path) {
    println!("\n## DSTU 9041 / crypto_box vs. OpenSSL CMS (10 MiB, same-regime, MB/s)\n");
    table_header("MB/s");

    let ec_key = dir.join("cms-ec.key");
    let ec_crt = dir.join("cms-ec.crt");
    let payload = dir.join("cms-payload.bin");
    let payload_size: u64 = 10 * 1024 * 1024;
    if !write_zeros(&payload, payload_size as usize) {
        return;
    }

    let genkey_ok = Command::new("openssl")
        .args([
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
        ])
        .arg(&ec_key)
        .status()
        .is_ok_and(|s| s.success());
    let cert_ok = genkey_ok
        && Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&ec_key)
            .args(["-out"])
            .arg(&ec_crt)
            .args(["-days", "1", "-subj", "/CN=uacrypt-bench-compare"])
            .status()
            .is_ok_and(|s| s.success());
    if !cert_ok {
        eprintln!("xtask: bench-compare: couldn't generate the CMS test certificate - skipping");
        return;
    }

    let box_sk = dir.join("cms-box.key");
    let box_pk = dir.join("cms-box.pub");
    let sealed = dir.join("cms-payload.box");
    if run_uacrypt(&["box-keygen", "--out", &box_sk.to_string_lossy()]).is_none() {
        return;
    }
    if run_uacrypt(&[
        "box-pubkey",
        "--key",
        &box_sk.to_string_lossy(),
        "--out",
        &box_pk.to_string_lossy(),
    ])
    .is_none()
    {
        return;
    }

    const N: u64 = 10;

    let Some(seal_fields) = run_uacrypt(&[
        "box-seal",
        "--key",
        &box_pk.to_string_lossy(),
        "--in",
        &payload.to_string_lossy(),
        "--out",
        &sealed.to_string_lossy(),
        "--iterations",
        &N.to_string(),
    ]) else {
        return;
    };
    let Some(&seal_ops) = seal_fields.get("ops_per_s") else {
        return;
    };
    let ours_seal_mib_s = mib_per_sec((1, 1.0 / seal_ops), payload_size);

    let unsealed = dir.join("cms-payload.out");
    let Some(open_fields) = run_uacrypt(&[
        "box-open",
        "--key",
        &box_sk.to_string_lossy(),
        "--in",
        &sealed.to_string_lossy(),
        "--out",
        &unsealed.to_string_lossy(),
        "--iterations",
        &N.to_string(),
    ]) else {
        return;
    };
    let Some(&open_ops) = open_fields.get("ops_per_s") else {
        return;
    };
    let ours_open_mib_s = mib_per_sec((1, 1.0 / open_ops), payload_size);

    let cms_p7 = dir.join("cms-payload.p7");
    let cms_out = dir.join("cms-payload.dec");

    let encrypt_start = Instant::now();
    let mut encrypt_ok = true;
    for _ in 0..N {
        encrypt_ok &= Command::new("openssl")
            .args(["cms", "-encrypt", "-binary", "-recip"])
            .arg(&ec_crt)
            .args(["-aes-256-cbc", "-in"])
            .arg(&payload)
            .args(["-out"])
            .arg(&cms_p7)
            .args(["-outform", "DER"])
            .status()
            .is_ok_and(|s| s.success());
    }
    let encrypt_elapsed = encrypt_start.elapsed().as_secs_f64();

    let decrypt_start = Instant::now();
    let mut decrypt_ok = true;
    for _ in 0..N {
        decrypt_ok &= Command::new("openssl")
            .args(["cms", "-decrypt", "-binary", "-inkey"])
            .arg(&ec_key)
            .args(["-recip"])
            .arg(&ec_crt)
            .args(["-in"])
            .arg(&cms_p7)
            .args(["-inform", "DER", "-out"])
            .arg(&cms_out)
            .status()
            .is_ok_and(|s| s.success());
    }
    let decrypt_elapsed = decrypt_start.elapsed().as_secs_f64();

    if !encrypt_ok || !decrypt_ok {
        eprintln!("xtask: bench-compare: an 'openssl cms' invocation failed - skipping this row");
        return;
    }

    let analog_seal_mib_s = mib_per_sec((N, encrypt_elapsed), payload_size);
    let analog_open_mib_s = mib_per_sec((N, decrypt_elapsed), payload_size);
    print_row(
        "seal/encrypt",
        ours_seal_mib_s,
        "OpenSSL CMS (prime256v1+AES-256-CBC)",
        analog_seal_mib_s,
        "MB/s",
    );
    print_row(
        "open/decrypt",
        ours_open_mib_s,
        "OpenSSL CMS (prime256v1+AES-256-CBC)",
        analog_open_mib_s,
        "MB/s",
    );
}

pub fn run() -> bool {
    if !require(
        "openssl",
        "https://openssl.org (or your distro's openssl package)",
    ) {
        return false;
    }
    if !Command::new("cargo")
        .args(["build", "-p", "uacrypt", "--release"])
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("xtask: bench-compare: 'cargo build -p uacrypt --release' failed");
        return false;
    }

    let dir = scratch_dir();
    let _ = fs::remove_dir_all(&dir);
    if fs::create_dir_all(&dir).is_err() {
        eprintln!(
            "xtask: bench-compare: couldn't create scratch dir {}",
            dir.display()
        );
        return false;
    }

    println!("# uacrypt vs. OpenSSL - unified comparison (T-187)\n");
    println!(
        "Not a rigorous academic benchmark suite (`docs/PERFORMANCE.md`'s own standing caveat) -\n\
         relative ratios are far more robust than any single absolute number here."
    );

    bench_kalyna_vs_aes(&dir);
    bench_kupyna_vs_whirlpool(&dir);
    bench_strumok_vs_chacha20(&dir);
    bench_dstu4145_vs_ecdsa(&dir);
    bench_dstu9041_vs_ecdh_cms(&dir);
    bench_dstu9041_vs_cms(&dir);

    let _ = fs::remove_dir_all(&dir);
    true
}
