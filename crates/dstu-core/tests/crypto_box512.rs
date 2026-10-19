//! Tests for `dstu_core::crypto_box512` (`docs/TASKS.md` T-193) - direct sibling of
//! `tests/crypto_box.rs` at `l(p)=512`'s widths. No DSTU standard or reference implementation
//! defines this composite - verified by property/tamper/misuse tests only, never citable as
//! vector-verified (same posture as `crypto_box`, D-68/T-178).

#![cfg(feature = "std")]

use dstu_core::crypto_box512::{
    open, open_stream, open_v2_legacy, seal, seal_stream, sealed_len, OpenError, PublicKey,
    SecretKey, OPEN_STREAM_PREFIX_BYTES, SEAL_STREAM_PREFIX_BYTES,
};
use dstu_core::crypto_secretstream::{FileDecryptor, FileError, CHUNK_BYTES, MAX_RECORD_BYTES};
use dstu_core::hazmat::dstu9041::curve512::order;
use proptest::prelude::*;

const KEM_CIPHERTEXT_LEN: usize = 256;
const HEADER_LEN: usize = 32;
const TAG_LEN: usize = 16;
const VERSION: u8 = 3;
/// The pre-T-265 one-chunk format (0.4-0.6), read only by `open_v2_legacy`.
const LEGACY_VERSION: u8 = 2;
/// `version (1) || kem_ciphertext` - the box's own prefix; a D-208 stream file follows.
const PREFIX_LEN: usize = 1 + KEM_CIPHERTEXT_LEN;
/// The stream file's header, after its own version byte.
const STREAM_HEADER_START: usize = PREFIX_LEN + 1;
/// The first record: `tag (1) || len (u32 LE) || ciphertext || auth tag (16)`.
const RECORD_START: usize = STREAM_HEADER_START + HEADER_LEN;
const CIPHERTEXT_START: usize = RECORD_START + 1 + 4;
const MIN_SEALED_LEN: usize = CIPHERTEXT_START + TAG_LEN;
const BLOCK_LEN: usize = 32;

#[test]
fn round_trip() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let message = b"hello dstu box 512";
    let sealed = seal(message, &public).expect("OS CSPRNG available in test environment");
    let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
    assert_eq!(opened, message);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "same full seal/open scalar-multiply cost as round_trip (kept live under Miri) - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn zero_length_message_round_trips() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let sealed = seal(&[], &public).expect("OS CSPRNG available in test environment");
    assert_eq!(sealed.len(), MIN_SEALED_LEN);
    let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
    assert_eq!(opened, Vec::<u8>::new());
}

/// The bulk layer is `crypto_secretstream`, which has no message-length cap - only the
/// *asymmetric* half is capped (D-182: the seed uses a fixed 32-byte/256-bit width, well under
/// `l(p)=512`'s own 424-bit KEM capacity), and that cap is invisible to `seal`'s own caller since
/// it only ever wraps a fresh random seed, never the message itself.
#[test]
#[cfg_attr(
    miri,
    ignore = "same full seal/open scalar-multiply cost as round_trip (kept live under Miri) - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn message_far_larger_than_the_seed_kem_payload_round_trips() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let message = vec![0x42u8; 4096];
    let sealed = seal(&message, &public).expect("OS CSPRNG available in test environment");
    let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
    assert_eq!(opened, message);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "two seal calls cost ~2x round_trip's already-covered scalar-multiply path - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn two_calls_use_different_ephemeral_material() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let a = seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    let b = seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    assert_ne!(
        &a[1..PREFIX_LEN],
        &b[1..PREFIX_LEN],
        "a fresh random seed/epsilon must be drawn per call"
    );
    assert_ne!(a, b);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "same full seal/open scalar-multiply cost as round_trip (kept live under Miri) - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn public_key_round_trips_through_bytes() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let bytes = public.to_bytes();
    let reparsed = PublicKey::from_bytes(&bytes).expect("a freshly generated public key is valid");
    // Sealing under the reparsed key must produce something the original secret key can open -
    // the real invariant (equality on the compressed bytes is necessary but not sufficient, since
    // `PublicKey` may internally hold either of {Q, -Q} - see `curve512::point_from_x`'s doc).
    let sealed =
        seal(b"round trip via bytes", &reparsed).expect("OS CSPRNG available in test environment");
    let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
    assert_eq!(opened, b"round trip via bytes");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "SecretKey::generate costs a full l(p)=512 scalar multiplication since T-287; crypto_box's own truncated-input test stays live under Miri"
)]
fn truncated_input_is_rejected_not_a_panic() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    for len in [0usize, 1, 20, KEM_CIPHERTEXT_LEN, MIN_SEALED_LEN - 1] {
        let mut short = vec![0u8; len];
        if let Some(version) = short.first_mut() {
            *version = VERSION;
        }
        let err =
            open(&short, &secret).expect_err("input shorter than the minimum must be rejected");
        assert!(matches!(err, OpenError::Truncated), "len = {len}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "same full seal/open scalar-multiply cost as tampered_ciphertext_is_rejected (kept live as the representative rejection path under Miri) - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn wrong_secret_key_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let other = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    let err = open(&sealed, &other).expect_err("wrong secret key must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

/// Regression guard: the 256-byte KEM prefix is not covered by the secretstream's own tag by any
/// accident of layout, but tampering it must still fail closed - `docs/DECISIONS.md` D-63's own
/// nonce/prefix-binding concern, re-derived for this construction rather than assumed.
#[test]
#[cfg_attr(
    miri,
    ignore = "same full seal/open scalar-multiply cost as tampered_ciphertext_is_rejected (kept live as the representative rejection path under Miri) - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn tampered_kem_prefix_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    sealed[1] ^= 0xFF;
    let err = open(&sealed, &secret).expect_err("tampered KEM prefix must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "same full seal/open scalar-multiply cost as tampered_ciphertext_is_rejected (kept live as the representative rejection path under Miri) - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn tampered_secretstream_header_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    sealed[STREAM_HEADER_START] ^= 0xFF;
    let err = open(&sealed, &secret).expect_err("tampered header must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    let idx = CIPHERTEXT_START;
    sealed[idx] ^= 0xFF;
    let err = open(&sealed, &secret).expect_err("tampered ciphertext must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "same full seal/open scalar-multiply cost as tampered_ciphertext_is_rejected (kept live as the representative rejection path under Miri) - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn tampered_tag_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    let err = open(&sealed, &secret).expect_err("tampered tag must fail");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

/// `docs/TASKS.md` T-183 Group 3 (mirrors `crypto_box.rs`'s own
/// `kem_failure_and_secretstream_failure_are_indistinguishable`): a KEM-level failure and a
/// secretstream-level failure must reach `OpenError::InvalidCiphertext` through different code
/// paths but be identically observable to an external caller - the CCA-oracle-avoidance property.
#[test]
#[cfg_attr(
    miri,
    ignore = "two full seal/open pairs, ~2x round_trip's already-covered scalar-multiply path - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn kem_failure_and_secretstream_failure_are_indistinguishable() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let other = SecretKey::generate().expect("OS CSPRNG available in test environment");

    let sealed_a = seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    let kem_level_err = open(&sealed_a, &other).expect_err("wrong key must fail");

    let mut sealed_b =
        seal(b"same message", &public).expect("OS CSPRNG available in test environment");
    let last = sealed_b.len() - 1;
    sealed_b[last] ^= 0xFF;
    let secretstream_level_err = open(&sealed_b, &secret).expect_err("tampered tag must fail");

    assert!(matches!(kem_level_err, OpenError::InvalidCiphertext));
    assert!(matches!(
        secretstream_level_err,
        OpenError::InvalidCiphertext
    ));
    assert_eq!(
        format!("{kem_level_err:?}"),
        format!("{secretstream_level_err:?}"),
        "a KEM-level failure and a secretstream-level failure must be identically observable"
    );
}

#[test]
fn secret_key_rejects_out_of_range_bytes() {
    assert!(
        SecretKey::from_bytes(&[0u8; 64]).is_none(),
        "e=0 must be invalid"
    );
    let mut one = [0u8; 64];
    one[63] = 1;
    assert!(SecretKey::from_bytes(&one).is_none(), "e=1 must be invalid");
}

/// `docs/TASKS.md` T-183 Group 1 (mirrors `crypto_box.rs`'s own
/// `secret_key_rejects_out_of_range_bytes_upper_boundary`): confirms `SecretKey::from_bytes`
/// actually wires up to `curve512::is_valid_scalar`, not a hazmat-level guarantee that happens
/// not to reach this wrapper.
#[test]
fn secret_key_rejects_out_of_range_bytes_upper_boundary() {
    let n = order();
    let mut n_minus_1 = n;
    n_minus_1[63] -= 1;
    let mut n_plus_1 = n;
    n_plus_1[63] += 1;

    assert!(
        SecretKey::from_bytes(&n_minus_1).is_none(),
        "e=n-1 must be invalid (strict upper bound)"
    );
    assert!(SecretKey::from_bytes(&n).is_none(), "e=n must be invalid");
    assert!(
        SecretKey::from_bytes(&n_plus_1).is_none(),
        "e=n+1 must be invalid"
    );
    assert!(
        SecretKey::from_bytes(&[0xFFu8; 64]).is_none(),
        "e=all-0xFF (far above n) must be invalid"
    );
}

/// `docs/TASKS.md` T-183 Group 1: reject trailing garbage appended after an otherwise-valid sealed
/// message, distinct from truncation.
#[test]
#[cfg_attr(
    miri,
    ignore = "same full seal/open scalar-multiply cost as tampered_ciphertext_is_rejected (kept live as the representative rejection path under Miri) - functional coverage stays in cargo test, see docs/TASKS.md T-206"
)]
fn trailing_garbage_after_valid_ciphertext_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let public = secret.public_key();
    let mut sealed = seal(b"secret", &public).expect("OS CSPRNG available in test environment");
    sealed.push(0x00);
    let err = open(&sealed, &secret).expect_err("trailing garbage must be rejected, not ignored");
    assert!(matches!(
        err,
        OpenError::InvalidCiphertext | OpenError::Truncated
    ));
}

/// `docs/TASKS.md` T-183 fourth ("active-attack") category: invalid-curve-shaped inputs -
/// `PublicKey::from_bytes` must reuse `curve512::point_from_x`'s own rejection gauntlet (reject
/// `x in {0,1,p-1}`, non-residues, out-of-subgroup reconstructions), not a second copy.
#[test]
fn public_key_rejects_degenerate_x_values() {
    assert!(
        PublicKey::from_bytes(&[0u8; 64]).is_none(),
        "x=0 must be invalid"
    );
    let mut one = [0u8; 64];
    one[63] = 1;
    assert!(PublicKey::from_bytes(&one).is_none(), "x=1 must be invalid");
    assert!(
        PublicKey::from_bytes(&[0xFFu8; 64]).is_none(),
        "all-0xFF is not even a valid field element (>= p)"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn unknown_version_byte_is_rejected_with_its_own_error() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed =
        seal(b"secret", &secret.public_key()).expect("OS CSPRNG available in test environment");
    assert_eq!(sealed[0], VERSION);
    for version in [0u8, 1, LEGACY_VERSION, 0xFF] {
        let mut other = sealed.clone();
        other[0] = version;
        let err = open(&other, &secret).expect_err("only the current format version is accepted");
        assert!(
            matches!(err, OpenError::UnsupportedVersion),
            "version = {version}"
        );
    }
}

/// T-232/F-01 on the box's own secretstream chunk: `80 00..` appended to the ciphertext up to the
/// next 32-byte block boundary must not open.
#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn appended_gcm_padding_is_rejected() {
    let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
    let sealed = seal(b"PAY 100 UAH TO ALICE", &secret.public_key())
        .expect("OS CSPRNG available in test environment");
    let tag_start = sealed.len() - TAG_LEN;
    let mut forged = sealed[..tag_start].to_vec();
    forged.push(0x80);
    forged.resize(CIPHERTEXT_START + BLOCK_LEN, 0);
    // The record's length field must agree, or the framing rejects it before authentication.
    forged[RECORD_START + 1..CIPHERTEXT_START]
        .copy_from_slice(&u32::try_from(BLOCK_LEN).unwrap().to_le_bytes());
    forged.extend_from_slice(&sealed[tag_start..]);
    let err = open(&forged, &secret).expect_err("an extended ciphertext must fail authentication");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    #[cfg_attr(miri, ignore)] // each case drives multiple full 512-iteration scalar
                              // multiplications (keygen x2, encrypt, decrypt) - too slow to
                              // interpret under Miri, same posture as `crypto_box.rs`'s own
                              // `round_trip_property`.
    fn round_trip_property(message in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let secret = SecretKey::generate().expect("OS CSPRNG available in test environment");
        let public = secret.public_key();
        let sealed = seal(&message, &public).expect("OS CSPRNG available in test environment");
        let opened = open(&sealed, &secret).expect("valid ciphertext under the right key");
        prop_assert_eq!(opened, message);
    }
}

const LEGACY_VECTORS: &str = include_str!("vectors/box/legacy_v2.json");

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + 7) % 256).unwrap())
        .collect()
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn field<'a>(text: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\": \"");
    let start = text.find(&pattern).unwrap() + pattern.len();
    let end = start + text[start..].find('"').unwrap();
    &text[start..end]
}

fn fresh_key() -> SecretKey {
    SecretKey::generate().expect("OS CSPRNG available in test environment")
}

/// The writer contract over `seal_stream`'s encryptor (full chunks, then `Final`).
fn seal_streamed(message: &[u8], recipient: &PublicKey) -> Vec<u8> {
    let (mut enc, prefix) = seal_stream(recipient).expect("OS CSPRNG available");
    let mut out = prefix.to_vec();
    let mut record = [0u8; MAX_RECORD_BYTES];
    let mut rest = message;
    while rest.len() > CHUNK_BYTES {
        let (chunk, tail) = rest.split_at(CHUNK_BYTES);
        enc.seal_chunk(chunk.try_into().unwrap(), &mut record)
            .unwrap();
        out.extend_from_slice(&record);
        rest = tail;
    }
    let n = enc.seal_final(rest, &mut record).unwrap();
    out.extend_from_slice(&record[..n]);
    out
}

/// The reader contract over `open_stream`'s decryptor.
fn open_streamed(sealed: &[u8], secret: &SecretKey) -> Result<Vec<u8>, FileError> {
    let prefix: &[u8; OPEN_STREAM_PREFIX_BYTES] =
        sealed[..OPEN_STREAM_PREFIX_BYTES].try_into().unwrap();
    let mut dec: FileDecryptor = open_stream(prefix, secret).expect("prefix opens");
    let file = &sealed[OPEN_STREAM_PREFIX_BYTES..];
    let mut out = vec![0u8; CHUNK_BYTES];
    let mut plaintext = Vec::new();
    let mut pos = 0;
    loop {
        let want = dec.next_len();
        if file.len() - pos < want {
            let n = dec.finish(&mut out)?;
            plaintext.extend_from_slice(&out[..n]);
            return Ok(plaintext);
        }
        let n = dec.feed(&file[pos..pos + want], &mut out)?;
        pos += want;
        plaintext.extend_from_slice(&out[..n]);
    }
}

#[test]
fn stream_constants_match_the_wire_format() {
    assert_eq!(OPEN_STREAM_PREFIX_BYTES, PREFIX_LEN);
    assert_eq!(SEAL_STREAM_PREFIX_BYTES, PREFIX_LEN + 1 + HEADER_LEN);
    assert_eq!(sealed_len(0), Some(MIN_SEALED_LEN));
    assert_eq!(sealed_len(CHUNK_BYTES), Some(MIN_SEALED_LEN + CHUNK_BYTES));
    assert_eq!(
        sealed_len(CHUNK_BYTES + 1),
        Some(MIN_SEALED_LEN + CHUNK_BYTES + 1 + 1 + 4 + TAG_LEN)
    );
    assert_eq!(sealed_len(usize::MAX), None);
}

/// T-265: every chunk boundary of the D-208 framing, with `sealed_len` matching the real output.
#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn round_trips_across_chunk_boundaries() {
    let secret = fresh_key();
    let public = secret.public_key();
    for len in [
        0,
        1,
        CHUNK_BYTES - 1,
        CHUNK_BYTES,
        CHUNK_BYTES + 1,
        3 * CHUNK_BYTES,
    ] {
        let message = pattern(len);
        let sealed = seal(&message, &public).expect("OS CSPRNG available");
        assert_eq!(sealed[0], VERSION);
        assert_eq!(Some(sealed.len()), sealed_len(len), "len = {len}");
        assert_eq!(
            open(&sealed, &secret).expect("authentic"),
            message,
            "len = {len}"
        );
    }
}

/// The one-shot and streaming halves write and read the same format.
#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn streaming_and_one_shot_interoperate() {
    let secret = fresh_key();
    let public = secret.public_key();
    let message = pattern(2 * CHUNK_BYTES + 5);

    let streamed = seal_streamed(&message, &public);
    assert_eq!(Some(streamed.len()), sealed_len(message.len()));
    assert_eq!(open(&streamed, &secret).expect("authentic"), message);

    let one_shot = seal(&message, &public).expect("OS CSPRNG available");
    assert_eq!(
        open_streamed(&one_shot, &secret).expect("authentic"),
        message
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn a_flipped_byte_in_any_region_is_rejected() {
    let secret = fresh_key();
    let message = pattern(CHUNK_BYTES + 10);
    let sealed = seal(&message, &secret.public_key()).expect("OS CSPRNG available");
    let first_auth_tag = CIPHERTEXT_START + CHUNK_BYTES;
    for idx in [
        1,
        PREFIX_LEN - 1,
        PREFIX_LEN,
        STREAM_HEADER_START,
        RECORD_START,
        RECORD_START + 1,
        CIPHERTEXT_START,
        first_auth_tag,
        sealed.len() - 1,
    ] {
        let mut tampered = sealed.clone();
        tampered[idx] ^= 0x01;
        let err = open(&tampered, &secret).expect_err("a tampered byte must not open");
        assert!(
            matches!(err, OpenError::InvalidCiphertext | OpenError::Truncated),
            "idx = {idx}: {err:?}"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn a_cut_at_any_region_boundary_is_truncated() {
    let secret = fresh_key();
    let sealed = seal(&pattern(CHUNK_BYTES + 10), &secret.public_key()).expect("OS CSPRNG");
    let first_record_end = CIPHERTEXT_START + CHUNK_BYTES + TAG_LEN;
    for cut in [
        1,
        PREFIX_LEN,
        STREAM_HEADER_START,
        RECORD_START,
        CIPHERTEXT_START,
        first_record_end,
        first_record_end + 3,
        sealed.len() - 1,
    ] {
        let err = open(&sealed[..cut], &secret).expect_err("a cut file must not open");
        assert!(matches!(err, OpenError::Truncated), "cut = {cut}: {err:?}");
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn reordered_records_are_rejected() {
    let secret = fresh_key();
    let sealed = seal(&pattern(3 * CHUNK_BYTES + 1), &secret.public_key()).expect("OS CSPRNG");
    let record = 1 + 4 + CHUNK_BYTES + TAG_LEN;
    let mut swapped = sealed.clone();
    swapped[RECORD_START..RECORD_START + record]
        .copy_from_slice(&sealed[RECORD_START + record..RECORD_START + 2 * record]);
    swapped[RECORD_START + record..RECORD_START + 2 * record]
        .copy_from_slice(&sealed[RECORD_START..RECORD_START + record]);
    let err = open(&swapped, &secret).expect_err("reordered records must not open");
    assert!(matches!(err, OpenError::InvalidCiphertext));
}

/// Active attack on the KEM half through the streaming entry point: a forged or degenerate KEM
/// ciphertext never yields a decryptor, and a version other than 3 is refused before any secret
/// is used.
#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn open_stream_rejects_a_wrong_version_and_a_forged_kem_ciphertext() {
    let secret = fresh_key();
    let sealed = seal(b"x", &secret.public_key()).expect("OS CSPRNG available");
    let prefix: [u8; OPEN_STREAM_PREFIX_BYTES] =
        sealed[..OPEN_STREAM_PREFIX_BYTES].try_into().unwrap();
    assert!(open_stream(&prefix, &secret).is_ok());

    for version in [0u8, LEGACY_VERSION, 4, 0xFF] {
        let mut p = prefix;
        p[0] = version;
        assert!(matches!(
            open_stream(&p, &secret),
            Err(OpenError::UnsupportedVersion)
        ));
    }
    for fill in [0x00u8, 0xFF] {
        let mut p = prefix;
        p[1..].fill(fill);
        assert!(matches!(
            open_stream(&p, &secret),
            Err(OpenError::InvalidCiphertext)
        ));
    }
    let mut p = prefix;
    p[1] ^= 0x01;
    assert!(matches!(
        open_stream(&p, &secret),
        Err(OpenError::InvalidCiphertext)
    ));
}

/// Owner decision 2026-10-15 (D-239): `open` reads v3 only; the 0.4-0.6 format opens only through
/// `open_v2_legacy`, which in turn refuses v3.
#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn legacy_v2_fixtures_open_only_through_open_v2_legacy() {
    let secret = SecretKey::from_bytes(
        &decode_hex(field(LEGACY_VECTORS, "box512_secret_key_hex"))
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut seen = 0;
    for line in LEGACY_VECTORS
        .lines()
        .filter(|l| l.contains("\"curve\": 512"))
    {
        let len: usize = line
            .split("\"plaintext_len\": ")
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let sealed = decode_hex(field(line, "sealed_hex"));
        assert_eq!(sealed[0], LEGACY_VERSION);
        assert_eq!(
            open_v2_legacy(&sealed, &secret).expect("legacy blob"),
            pattern(len)
        );
        assert!(matches!(
            open(&sealed, &secret),
            Err(OpenError::UnsupportedVersion)
        ));
        let mut relabelled = sealed.clone();
        relabelled[0] = VERSION;
        assert!(open(&relabelled, &secret).is_err(), "len = {len}");
        seen += 1;
    }
    assert_eq!(seen, 4);
}

/// The file the real `uacrypt` 0.6.0 release binary wrote (key file line, sealed bytes).
#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn a_uacrypt_0_6_0_file_opens_through_open_v2_legacy() {
    let section = &LEGACY_VECTORS[LEGACY_VECTORS.find("\"uacrypt_0_6_0\"").unwrap()..];
    let key_line = field(section, "box512_secret_key_file");
    let key_hex = key_line.split(':').nth(1).unwrap();
    let secret = SecretKey::from_bytes(&decode_hex(key_hex).try_into().unwrap()).unwrap();
    let sealed = decode_hex(field(section, "box512_sealed_hex"));
    assert_eq!(
        open_v2_legacy(&sealed, &secret).expect("0.6.0 file"),
        pattern(20000)
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn open_v2_legacy_refuses_the_current_format() {
    let secret = fresh_key();
    let sealed = seal(b"v3", &secret.public_key()).expect("OS CSPRNG available");
    assert!(matches!(
        open_v2_legacy(&sealed, &secret),
        Err(OpenError::UnsupportedVersion)
    ));
}

/// A blob sealed to the other curve size never opens (it may also be too short for this one).
#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn a_blob_for_the_other_curve_is_rejected() {
    let secret = fresh_key();
    let other = dstu_core::crypto_box::SecretKey::generate().expect("OS CSPRNG available");
    let sealed = dstu_core::crypto_box::seal(b"x", &other.public_key()).expect("OS CSPRNG");
    assert!(open(&sealed, &secret).is_err());
}

const V3_VECTORS: &str = include_str!("vectors/box/v3.json");

/// The shared v3 vectors (D-239) every binding's reader runs: `open` gives each case's expected
/// outcome, and the full plaintext for a valid one.
#[test]
#[cfg_attr(
    miri,
    ignore = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206"
)]
fn shared_v3_vectors_give_their_expected_outcome() {
    let secret = SecretKey::from_bytes(
        &decode_hex(field(V3_VECTORS, "box512_secret_key_hex"))
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut seen = 0;
    for line in V3_VECTORS.lines().filter(|l| l.contains("\"curve\": 512")) {
        let name = field(line, "name");
        let len: usize = line
            .split("\"plaintext_len\": ")
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let result = open(&decode_hex(field(line, "sealed_hex")), &secret);
        match field(line, "expect") {
            "ok" => assert_eq!(result.expect(name), pattern(len), "{name}"),
            "invalid_ciphertext" => {
                assert!(
                    matches!(result, Err(OpenError::InvalidCiphertext)),
                    "{name}"
                );
            }
            "truncated" => assert!(matches!(result, Err(OpenError::Truncated)), "{name}"),
            "unsupported_version" => {
                assert!(
                    matches!(result, Err(OpenError::UnsupportedVersion)),
                    "{name}"
                );
            }
            other => panic!("unknown expect {other}"),
        }
        seen += 1;
    }
    assert_eq!(seen, 8);
}
