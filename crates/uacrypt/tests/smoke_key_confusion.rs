//! T-200 Phase 3/4 (active-attack category): cross-key-type confusion. `keygen` (a
//! `crypto_secretstream` symmetric key), `box-keygen`/`box-pubkey` (a `crypto_box` secret/public
//! key pair), and `box-keygen512`/`box-pubkey512` (their `crypto_box512` siblings) all produce
//! same-length, byte-for-byte-indistinguishable-by-format files (32 bytes for the first three,
//! 64 for the last two) - D-47's "no `--type` flag" design (`docs/dstu-crypto-project.md`) means
//! there is no tag to catch a caller pointing the wrong file at the wrong flag; only each type's
//! own validity check (a magnitude/range check for a secret scalar, an on-curve check for a
//! public-key x-coordinate) incidentally catches *some* of the misuse, never all of it.
//!
//! Every byte pattern used here was picked by **running the real binary first and observing what
//! actually happens**, not by assuming a rejection - `docs/TASKS.md` T-200's own explicit
//! instruction, since the two validity checks have genuinely different (and non-obvious) rejection
//! rates: a secret key's check is magnitude-only (`0 < e < n`), a public key's check requires the
//! x-coordinate to actually decode a point on the curve (roughly a coin flip for an arbitrary
//! value). Fixed, deterministic byte patterns are used throughout (never a real `keygen`/
//! `box-keygen` output) specifically so these results are reproducible on every run, not
//! dependent on that run's random key material landing on the right side of a coin flip.

mod support;
use support::{uacrypt, write_bytes, TempDir};

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
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_all_zero_key_is_rejected_in_both_secret_and_public_slots() {
    let dir = TempDir::new("keyconf_box_zero");
    let key = dir.file("zero32.bin");
    let msg = dir.file("msg.bin");
    write_bytes(&key, &[0x00; 32]);
    write_bytes(&msg, b"irrelevant");

    let as_secret = uacrypt([
        "box-open",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        dir.file("o1").to_str().unwrap(),
    ]);
    assert!(as_secret.failure());
    assert!(as_secret.stderr.contains("not a valid crypto_box key"));

    let as_public = uacrypt([
        "box-seal",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        dir.file("o2").to_str().unwrap(),
    ]);
    assert!(as_public.failure());
    assert!(as_public.stderr.contains("not a valid crypto_box key"));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box_all_ff_key_is_rejected_in_both_secret_and_public_slots() {
    let dir = TempDir::new("keyconf_box_ff");
    let key = dir.file("ff32.bin");
    let msg = dir.file("msg.bin");
    write_bytes(&key, &[0xFF; 32]);
    write_bytes(&msg, b"irrelevant");

    let as_secret = uacrypt([
        "box-open",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        dir.file("o1").to_str().unwrap(),
    ]);
    assert!(as_secret.failure());
    assert!(as_secret.stderr.contains("not a valid crypto_box key"));

    let as_public = uacrypt([
        "box-seal",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        dir.file("o2").to_str().unwrap(),
    ]);
    assert!(as_public.failure());
    assert!(as_public.stderr.contains("not a valid crypto_box key"));
}

/// `[0x11; 32]`: a small-magnitude value, empirically confirmed to pass `SecretKey::from_bytes`'s
/// range check (`0 < e < n`) but fail `PublicKey::from_bytes`'s on-curve check. Demonstrates the
/// asymmetry directly - this is not "any 32 bytes work as a secret key", it is "this specific
/// value does, and does not also work as a public key".
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn low_magnitude_key_parses_as_secret_but_not_as_public() {
    let dir = TempDir::new("keyconf_box_low");
    let key = dir.file("low32.bin");
    let sealed_stub = dir.file("sealed_stub.bin");
    write_bytes(&key, &[0x11; 32]);
    write_bytes(
        &sealed_stub,
        b"not real box-seal output, just needs to exist",
    );

    // Accepted as a secret key: fails later (not real box-seal output), not at key-parsing.
    let as_secret = uacrypt([
        "box-open",
        "--key",
        key.to_str().unwrap(),
        "--in",
        sealed_stub.to_str().unwrap(),
        "--out",
        dir.file("o1").to_str().unwrap(),
    ]);
    assert!(as_secret.failure());
    assert!(
        !as_secret.stderr.contains("not a valid crypto_box key"),
        "expected key-parsing to succeed and fail later instead; stderr={}",
        as_secret.stderr
    );

    // Rejected as a public key: fails at key-parsing itself.
    let as_public = uacrypt([
        "box-seal",
        "--key",
        key.to_str().unwrap(),
        "--in",
        sealed_stub.to_str().unwrap(),
        "--out",
        dir.file("o2").to_str().unwrap(),
    ]);
    assert!(as_public.failure());
    assert!(as_public.stderr.contains("not a valid crypto_box key"));
}

/// `[0x55; 32]`: the mirror image of the above - empirically confirmed to decode as a valid
/// curve point (accepted as a public key, `box-seal` genuinely succeeds and produces real
/// ciphertext) but rejected as a secret key (magnitude `>= n`). The interesting, silent case:
/// nothing in `box-seal`'s own output signals that the "recipient" this sealed to isn't a real
/// key pair anyone actually holds - D-47's "no `--type` flag" tradeoff in its most visible form.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn mid_magnitude_key_parses_as_public_but_not_as_secret() {
    let dir = TempDir::new("keyconf_box_mid");
    let key = dir.file("mid32.bin");
    let msg = dir.file("msg.bin");
    let sealed = dir.file("sealed.bin");
    write_bytes(&key, &[0x55; 32]);
    write_bytes(&msg, b"sealed to a key nobody can prove they hold");

    let as_public = uacrypt([
        "box-seal",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sealed.to_str().unwrap(),
    ]);
    ok(&as_public); // silent success - no warning that this "public key" was never derived via box-pubkey
    assert!(sealed.exists());

    let as_secret = uacrypt([
        "box-open",
        "--key",
        key.to_str().unwrap(),
        "--in",
        sealed.to_str().unwrap(),
        "--out",
        dir.file("o").to_str().unwrap(),
    ]);
    assert!(as_secret.failure());
    assert!(as_secret.stderr.contains("not a valid crypto_box key"));
}

/// A `keygen` symmetric key and a `crypto_box` secret key are both 32 bytes with no distinguishing
/// tag. `box-open` cannot tell the difference at parse time (the low-magnitude case above already
/// shows most "generic-looking" 32-byte values parse as a valid secret key) - it only fails once
/// it actually tries to authenticate against real `box-seal` output, at the AEAD layer, not the
/// type layer.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn secretstream_style_key_is_accepted_as_box_secret_key_then_fails_at_auth() {
    let dir = TempDir::new("keyconf_symmetric_as_box");
    let real_sk = dir.file("real_sk.bin");
    let real_pk = dir.file("real_pk.bin");
    let wrong_key = dir.file("wrong_key.bin"); // stands in for a `keygen`-produced symmetric key
    let msg = dir.file("msg.bin");
    let sealed = dir.file("sealed.bin");

    ok(&uacrypt(["box-keygen", "--out", real_sk.to_str().unwrap()]));
    ok(&uacrypt([
        "box-pubkey",
        "--key",
        real_sk.to_str().unwrap(),
        "--out",
        real_pk.to_str().unwrap(),
    ]));
    write_bytes(&msg, b"only the real recipient should open this");
    ok(&uacrypt([
        "box-seal",
        "--key",
        real_pk.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        sealed.to_str().unwrap(),
    ]));

    write_bytes(&wrong_key, &[0x11; 32]); // confirmed above: parses as a valid secret key
    let r = uacrypt([
        "box-open",
        "--key",
        wrong_key.to_str().unwrap(),
        "--in",
        sealed.to_str().unwrap(),
        "--out",
        dir.file("o").to_str().unwrap(),
    ]);
    assert!(r.failure());
    assert!(
        r.stderr.contains("authentication failed"),
        "expected an AEAD-layer failure, not a type-layer one; stderr={}",
        r.stderr
    );
}

/// `crypto_box512`'s pair, at 64 bytes: `[0x02; 64]` is the stronger version of the finding above,
/// empirically confirmed to parse as a **valid secret key AND a valid public key simultaneously**
/// (l(p)=512's own subgroup order is close enough to the field size, `docs/DECISIONS.md` D-182,
/// that this specific low-magnitude value clears both the secret key's range check and the public
/// key's on-curve check). The same 64 bytes silently mean two different things depending only on
/// which flag receives them - no error at all in either direction.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box512_low_magnitude_key_parses_as_both_secret_and_public() {
    let dir = TempDir::new("keyconf_box512_dual");
    let key = dir.file("dual64.bin");
    let msg = dir.file("msg.bin");
    write_bytes(&key, &[0x02; 64]);
    write_bytes(&msg, b"irrelevant for the parsing check itself");

    let as_public = uacrypt([
        "box-seal512",
        "--key",
        key.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        dir.file("sealed").to_str().unwrap(),
    ]);
    ok(&as_public);

    let sealed_stub = dir.file("sealed_stub.bin");
    write_bytes(&sealed_stub, b"not real box-seal512 output, just needs to exist and be long enough to reach the auth stage rather than the truncation check 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    let as_secret = uacrypt([
        "box-open512",
        "--key",
        key.to_str().unwrap(),
        "--in",
        sealed_stub.to_str().unwrap(),
        "--out",
        dir.file("o").to_str().unwrap(),
    ]);
    assert!(as_secret.failure());
    assert!(
        !as_secret.stderr.contains("not a valid crypto_box512 key"),
        "expected key-parsing to succeed and fail later instead; stderr={}",
        as_secret.stderr
    );
}

/// `box-keygen`/`box-keygen512` output lengths (32 vs. 64 bytes) are the one case in this family
/// that *is* caught cleanly - `read_exact_file`'s own length check fires before any curve/scalar
/// validation runs at all, so this specific cross-size confusion cannot silently succeed. Recorded
/// here as the contrast case: the failure mode this whole file is about is same-length,
/// different-semantics, not different-length.
#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn box512_key_fed_to_box256_command_is_wrong_length_not_misparsed() {
    let dir = TempDir::new("keyconf_cross_size");
    let key64 = dir.file("key64.bin");
    let msg = dir.file("msg.bin");
    write_bytes(&key64, &[0x11; 64]);
    write_bytes(&msg, b"irrelevant");

    let r = uacrypt([
        "box-seal",
        "--key",
        key64.to_str().unwrap(),
        "--in",
        msg.to_str().unwrap(),
        "--out",
        dir.file("o").to_str().unwrap(),
    ]);
    assert!(r.failure());
    assert!(
        r.stderr.contains("must be exactly 32 bytes, got 64"),
        "stderr={}",
        r.stderr
    );
}
