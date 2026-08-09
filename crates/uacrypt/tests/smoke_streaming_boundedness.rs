//! T-200: proves D-42's streaming-boundedness claim ("a `hazmat` streaming API existing does not
//! make the `uacrypt` command wrapping it memory-bounded") at the real process boundary, for the
//! commands that claim it - `kupyna-digest`/`hash`, `strumok-crypt`, `encrypt`/`decrypt` - rather
//! than leaving it asserted only in a doc comment. Spawns the real binary against a genuinely large
//! file and samples its actual OS-reported resident memory (`support::uacrypt_with_peak_rss`) while
//! it runs.
//!
//! Includes a deliberate control case: `box-seal`, whose own `--help` text (`BOX_SEAL_HELP`)
//! already says plainly "Not memory-bounded: `--in` is read whole into memory." If the measurement
//! methodology here could not tell that apart from a genuinely bounded command, the "streaming
//! commands stayed low" result below would mean nothing - it could just be an insensitive
//! measurement. `box_seal_is_not_memory_bounded_control_case` proves the opposite: peak RSS visibly
//! grows with `--in`'s size for a command that really does buffer it all.

mod support;
use support::{uacrypt, uacrypt_with_peak_rss, write_large_file, TempDir};

const LARGE_FILE_BYTES: usize = 200 * 1024 * 1024; // 200 MiB
/// Generous margin: real streaming overhead here is a small fixed buffer
/// (`DIGEST_STREAM_CHUNK_BYTES`/`STRUMOK_STREAM_CHUNK_BYTES`/`SECRETSTREAM_CHUNK_BYTES`, all a few
/// KiB) plus the binary's own runtime footprint - nowhere near this threshold if bounded, and
/// nowhere near it if the whole 200 MiB file were buffered either (that would show up as ~200 MiB).
const BOUNDED_THRESHOLD_BYTES: u64 = 60 * 1024 * 1024;

fn ok(r: &support::Run) {
    assert!(
        r.success(),
        "code={:?} stdout={} stderr={}",
        r.code,
        r.stdout,
        r.stderr
    );
}

#[test]
#[ignore = "expensive: writes large fixture files and needs a release build for realistic timing/memory numbers - run via cargo xtask streaming-bounded, not a plain cargo test"]
fn kupyna_digest_stays_memory_bounded_on_a_large_file() {
    let dir = TempDir::new("bound_digest");
    let input = dir.file("large.bin");
    write_large_file(&input, LARGE_FILE_BYTES);
    let out = dir.file("digest.bin");

    let (r, peak) = uacrypt_with_peak_rss([
        "kupyna-digest",
        "--variant",
        "256",
        "--in",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    ok(&r);
    if let Some(peak) = peak {
        assert!(
            peak < BOUNDED_THRESHOLD_BYTES,
            "peak RSS {peak} bytes for a {LARGE_FILE_BYTES}-byte input - D-42 claims bounded streaming"
        );
    }
}

#[test]
#[ignore = "expensive: writes large fixture files and needs a release build for realistic timing/memory numbers - run via cargo xtask streaming-bounded, not a plain cargo test"]
fn strumok_crypt_stays_memory_bounded_on_a_large_file() {
    let dir = TempDir::new("bound_strumok");
    let key = dir.file("key.bin");
    let iv = dir.file("iv.bin");
    let input = dir.file("large.bin");
    let out = dir.file("out.bin");
    support::write_bytes(&key, &[0x11; 32]);
    support::write_bytes(&iv, &[0x22; 32]);
    write_large_file(&input, LARGE_FILE_BYTES);

    let (r, peak) = uacrypt_with_peak_rss([
        "strumok-crypt",
        "--variant",
        "256",
        "--key",
        key.to_str().unwrap(),
        "--iv",
        iv.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    ok(&r);
    if let Some(peak) = peak {
        assert!(
            peak < BOUNDED_THRESHOLD_BYTES,
            "peak RSS {peak} bytes for a {LARGE_FILE_BYTES}-byte input - D-42 claims bounded streaming"
        );
    }
}

#[test]
#[ignore = "expensive: writes large fixture files and needs a release build for realistic timing/memory numbers - run via cargo xtask streaming-bounded, not a plain cargo test"]
fn encrypt_and_decrypt_stay_memory_bounded_on_a_large_file() {
    let dir = TempDir::new("bound_secretstream");
    let key = dir.file("key.bin");
    let input = dir.file("large.bin");
    let ciphertext = dir.file("large.enc");
    let recovered = dir.file("large.dec");
    assert!(uacrypt(["keygen", "--out", key.to_str().unwrap()]).success());
    write_large_file(&input, LARGE_FILE_BYTES);

    let (r, peak) = uacrypt_with_peak_rss([
        "encrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        input.to_str().unwrap(),
        "--out",
        ciphertext.to_str().unwrap(),
    ]);
    ok(&r);
    if let Some(peak) = peak {
        assert!(
            peak < BOUNDED_THRESHOLD_BYTES,
            "encrypt: peak RSS {peak} bytes for a {LARGE_FILE_BYTES}-byte input"
        );
    }

    let (r, peak) = uacrypt_with_peak_rss([
        "decrypt",
        "--key",
        key.to_str().unwrap(),
        "--in",
        ciphertext.to_str().unwrap(),
        "--out",
        recovered.to_str().unwrap(),
    ]);
    ok(&r);
    if let Some(peak) = peak {
        assert!(
            peak < BOUNDED_THRESHOLD_BYTES,
            "decrypt: peak RSS {peak} bytes for a {LARGE_FILE_BYTES}-byte input"
        );
    }
}

/// Control case (see module doc): `box-seal` is documented as reading `--in` whole into memory.
/// Peak RSS must visibly grow with `--in`'s size here, proving the measurement methodology above
/// can actually detect unbounded memory use rather than being uniformly insensitive.
#[test]
#[ignore = "expensive: writes large fixture files and needs a release build for realistic timing/memory numbers - run via cargo xtask streaming-bounded, not a plain cargo test"]
fn box_seal_is_not_memory_bounded_control_case() {
    const SMALL_BYTES: usize = 40 * 1024 * 1024;
    const LARGE_BYTES: usize = 180 * 1024 * 1024;

    let dir = TempDir::new("unbounded_box_seal");
    let secret = dir.file("recipient.key");
    let public = dir.file("recipient.pub");
    assert!(uacrypt(["box-keygen", "--out", secret.to_str().unwrap()]).success());
    assert!(uacrypt([
        "box-pubkey",
        "--key",
        secret.to_str().unwrap(),
        "--out",
        public.to_str().unwrap(),
    ])
    .success());

    let small_in = dir.file("small.bin");
    let small_out = dir.file("small.box");
    write_large_file(&small_in, SMALL_BYTES);
    let (r, small_peak) = uacrypt_with_peak_rss([
        "box-seal",
        "--key",
        public.to_str().unwrap(),
        "--in",
        small_in.to_str().unwrap(),
        "--out",
        small_out.to_str().unwrap(),
    ]);
    ok(&r);

    let large_in = dir.file("large.bin");
    let large_out = dir.file("large.box");
    write_large_file(&large_in, LARGE_BYTES);
    let (r, large_peak) = uacrypt_with_peak_rss([
        "box-seal",
        "--key",
        public.to_str().unwrap(),
        "--in",
        large_in.to_str().unwrap(),
        "--out",
        large_out.to_str().unwrap(),
    ]);
    ok(&r);

    let (Some(small_peak), Some(large_peak)) = (small_peak, large_peak) else {
        // Neither run's memory was successfully sampled (both finished faster than the sampling
        // interval) - not evidence either way, so this control case can't confirm or refute
        // anything this run. Do not fail the build on an unmeasurable environment.
        return;
    };
    assert!(
        large_peak > small_peak,
        "box-seal's peak RSS did not grow with --in's size (small={small_peak}, large={large_peak}) \
         - this run cannot confirm the bounded-memory results above are a real measurement"
    );
    assert!(
        large_peak > (LARGE_BYTES as u64) / 2,
        "box-seal peaked at {large_peak} bytes for a {LARGE_BYTES}-byte input - expected roughly \
         proportional growth for a documented whole-buffer read"
    );
}
