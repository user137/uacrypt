//! Tests for `dstu_core::crypto_secretstream` (`TASKS.md` T-40/T-70, `DECISIONS.md` D-68) - a
//! from-scratch chunked/streaming AEAD construction over `hazmat::kalyna_gcm::Kalyna256_256Gcm` +
//! `hazmat::kupyna_kmac::Kupyna256Kmac`, no DSTU streaming-AEAD standard exists so there is no
//! oracle vector for this construction, ever - verification here is round-trip, tamper (D-64), and
//! misuse (D-65) coverage plus a property test, the same posture `crypto_kdf` (D-45) already
//! established for a from-scratch construction with nothing to check against.

#![cfg(feature = "std")]

use dstu_core::crypto_secretstream::{Key, PullState, PushState, SecretstreamError, Tag};
use proptest::prelude::*;

const TAG_LEN: usize = 16;

fn push_one(key: &Key, tag: Tag, plaintext: &[u8]) -> ([u8; 32], Vec<u8>, [u8; TAG_LEN]) {
    let (mut state, header) =
        PushState::init(key).expect("OS CSPRNG available in test environment");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let auth_tag = state
        .push(tag, plaintext, &mut ciphertext)
        .expect("first push on a fresh state cannot fail");
    (header, ciphertext, auth_tag)
}

#[test]
fn single_chunk_round_trips() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let plaintext = b"hello dstu secretstream";
    let (header, ciphertext, tag) = push_one(&key, Tag::Final, plaintext);

    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; plaintext.len()];
    let read_tag = pull
        .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect("valid chunk under the right key/header");
    assert_eq!(read_tag, Tag::Final);
    assert_eq!(out, plaintext);
}

#[test]
fn zero_length_final_chunk_round_trips() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (header, ciphertext, tag) = push_one(&key, Tag::Final, &[]);
    assert!(ciphertext.is_empty());

    let mut pull = PullState::init(&key, &header);
    let mut out: [u8; 0] = [];
    let read_tag = pull
        .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect("an empty final chunk is a legal, complete stream");
    assert_eq!(read_tag, Tag::Final);
}

#[test]
fn multi_chunk_round_trips() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let chunks: [&[u8]; 3] = [b"chunk one", b"chunk two is longer", b"three"];

    let (mut push, header) =
        PushState::init(&key).expect("OS CSPRNG available in test environment");
    let mut records = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let tag = if i == chunks.len() - 1 {
            Tag::Final
        } else {
            Tag::Message
        };
        let mut ciphertext = vec![0u8; chunk.len()];
        let auth_tag = push
            .push(tag, chunk, &mut ciphertext)
            .expect("sequential push on a live state");
        records.push((tag, ciphertext, auth_tag));
    }

    let mut pull = PullState::init(&key, &header);
    for (i, (tag, ciphertext, auth_tag)) in records.iter().enumerate() {
        let mut out = vec![0u8; chunks[i].len()];
        let read_tag = pull
            .pull(tag.to_byte(), ciphertext, auth_tag, &mut out)
            .expect("sequential pull in order");
        assert_eq!(read_tag, *tag);
        assert_eq!(out, chunks[i]);
    }
}

#[test]
fn push_tag_marks_a_boundary_and_is_reported_back() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (mut push, header) =
        PushState::init(&key).expect("OS CSPRNG available in test environment");

    let mut ct1 = vec![0u8; 5];
    let tag1 = push
        .push(Tag::Push, b"first", &mut ct1)
        .expect("push tag is a normal chunk, just with boundary semantics");
    let mut ct2 = vec![0u8; 6];
    let tag2 = push
        .push(Tag::Final, b"second", &mut ct2)
        .expect("sequential push");

    let mut pull = PullState::init(&key, &header);
    let mut out1 = vec![0u8; 5];
    let read1 = pull
        .pull(Tag::Push.to_byte(), &ct1, &tag1, &mut out1)
        .expect("valid chunk");
    assert_eq!(read1, Tag::Push);
    assert_eq!(out1, b"first");

    let mut out2 = vec![0u8; 6];
    let read2 = pull
        .pull(Tag::Final.to_byte(), &ct2, &tag2, &mut out2)
        .expect("valid chunk");
    assert_eq!(read2, Tag::Final);
    assert_eq!(out2, b"second");
}

#[test]
fn rekey_changes_the_subkey_and_old_subkey_no_longer_decrypts() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (mut push, header) =
        PushState::init(&key).expect("OS CSPRNG available in test environment");

    let mut ct_before = vec![0u8; 6];
    let tag_before = push
        .push(Tag::Rekey, b"before", &mut ct_before)
        .expect("rekey-tagged push succeeds like any other");
    let mut ct_after = vec![0u8; 5];
    let tag_after = push
        .push(Tag::Final, b"after", &mut ct_after)
        .expect("push after rekey uses the new subkey");

    // A correctly-tracking pull state (rekeys itself after seeing the Rekey tag) decrypts both.
    let mut pull = PullState::init(&key, &header);
    let mut out_before = vec![0u8; 6];
    let read_before = pull
        .pull(
            Tag::Rekey.to_byte(),
            &ct_before,
            &tag_before,
            &mut out_before,
        )
        .expect("valid chunk under the pre-rekey subkey");
    assert_eq!(read_before, Tag::Rekey);
    assert_eq!(out_before, b"before");

    let mut out_after = vec![0u8; 5];
    let read_after = pull
        .pull(Tag::Final.to_byte(), &ct_after, &tag_after, &mut out_after)
        .expect("valid chunk under the post-rekey subkey");
    assert_eq!(read_after, Tag::Final);
    assert_eq!(out_after, b"after");

    // Forward secrecy: a pull state that never processed the Rekey chunk (still on the initial,
    // pre-rekey subkey and counter) must NOT be able to decrypt the post-rekey chunk.
    let mut fresh_pull = PullState::init(&key, &header);
    let mut out = vec![0u8; 5];
    let err = fresh_pull
        .pull(Tag::Final.to_byte(), &ct_after, &tag_after, &mut out)
        .expect_err("counter 0 was never rekeyed - wrong counter and wrong subkey for this chunk");
    assert!(matches!(err, SecretstreamError::TagMismatch));
}

#[test]
fn wrong_key_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let other = Key::generate().expect("OS CSPRNG available in test environment");
    let (header, ciphertext, tag) = push_one(&key, Tag::Final, b"secret");

    let mut pull = PullState::init(&other, &header);
    let mut out = vec![0u8; 6];
    let err = pull
        .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect_err("wrong key must fail authentication");
    assert!(matches!(err, SecretstreamError::TagMismatch));
    assert_eq!(out, [0u8; 6], "plaintext_out must stay all-zero on failure");
}

#[test]
fn tampered_header_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (mut header, ciphertext, tag) = push_one(&key, Tag::Final, b"secret");
    header[0] ^= 0xFF;

    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; 6];
    let err = pull
        .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect_err("a tampered header derives the wrong subkey, must fail the first chunk");
    assert!(matches!(err, SecretstreamError::TagMismatch));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (header, mut ciphertext, tag) = push_one(&key, Tag::Final, b"secret");
    ciphertext[0] ^= 0xFF;

    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; 6];
    let err = pull
        .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect_err("tampered ciphertext must fail authentication");
    assert!(matches!(err, SecretstreamError::TagMismatch));
}

#[test]
fn tampered_tag_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (header, ciphertext, mut tag) = push_one(&key, Tag::Final, b"secret");
    tag[0] ^= 0xFF;

    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; 6];
    let err = pull
        .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect_err("tampered auth tag must fail authentication");
    assert!(matches!(err, SecretstreamError::TagMismatch));
}

#[test]
fn flipped_tag_byte_is_rejected() {
    // Flipping FINAL -> MESSAGE (to try to hide truncation from a caller) changes the AAD the
    // tag was computed over, so it must fail the tag check, not silently succeed with the wrong
    // (attacker-chosen) Tag returned.
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (header, ciphertext, tag) = push_one(&key, Tag::Final, b"secret");

    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; 6];
    let err = pull
        .pull(Tag::Message.to_byte(), &ciphertext, &tag, &mut out)
        .expect_err("a flipped tag byte must fail authentication, not be silently accepted");
    assert!(matches!(err, SecretstreamError::TagMismatch));
}

#[test]
fn dropped_interior_chunk_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let chunks: [&[u8]; 3] = [b"one", b"two", b"three"];

    let (mut push, header) =
        PushState::init(&key).expect("OS CSPRNG available in test environment");
    let mut records = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let tag = if i == chunks.len() - 1 {
            Tag::Final
        } else {
            Tag::Message
        };
        let mut ciphertext = vec![0u8; chunk.len()];
        let auth_tag = push
            .push(tag, chunk, &mut ciphertext)
            .expect("sequential push");
        records.push((tag, ciphertext, auth_tag));
    }

    // Drop record 1 (the interior "two" chunk) - receiver sees records 0, 2 back to back.
    let mut pull = PullState::init(&key, &header);
    let mut out0 = vec![0u8; chunks[0].len()];
    pull.pull(
        records[0].0.to_byte(),
        &records[0].1,
        &records[0].2,
        &mut out0,
    )
    .expect("first chunk is untouched");

    let mut out2 = vec![0u8; chunks[2].len()];
    let err = pull
        .pull(
            records[2].0.to_byte(),
            &records[2].1,
            &records[2].2,
            &mut out2,
        )
        .expect_err("counter mismatch after a dropped interior chunk must fail authentication");
    assert!(matches!(err, SecretstreamError::TagMismatch));
}

#[test]
fn swapped_chunks_are_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let chunks: [&[u8]; 2] = [b"first ", b"second"];

    let (mut push, header) =
        PushState::init(&key).expect("OS CSPRNG available in test environment");
    let mut records = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let tag = if i == chunks.len() - 1 {
            Tag::Final
        } else {
            Tag::Message
        };
        let mut ciphertext = vec![0u8; chunk.len()];
        let auth_tag = push
            .push(tag, chunk, &mut ciphertext)
            .expect("sequential push");
        records.push((tag, ciphertext, auth_tag));
    }
    records.swap(0, 1);

    let mut pull = PullState::init(&key, &header);
    let mut out0 = vec![0u8; records[0].1.len()];
    let err = pull
        .pull(
            records[0].0.to_byte(),
            &records[0].1,
            &records[0].2,
            &mut out0,
        )
        .expect_err("swapped chunk order must fail authentication (wrong counter)");
    assert!(matches!(err, SecretstreamError::TagMismatch));
}

#[test]
fn spliced_chunk_from_a_different_stream_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (_header_a, ciphertext_a, tag_a) = push_one(&key, Tag::Final, b"stream a");
    let (header_b, _ciphertext_b, _tag_b) = push_one(&key, Tag::Final, b"stream b");

    // Splice stream A's chunk into stream B's header/subkey context.
    let mut pull = PullState::init(&key, &header_b);
    let mut out = vec![0u8; ciphertext_a.len()];
    let err = pull
        .pull(Tag::Final.to_byte(), &ciphertext_a, &tag_a, &mut out)
        .expect_err("a chunk from a different stream (different header-derived subkey) must fail");
    assert!(matches!(err, SecretstreamError::TagMismatch));
}

#[test]
fn truncation_is_detectable_via_finalized_state() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (mut push, header) =
        PushState::init(&key).expect("OS CSPRNG available in test environment");
    let mut ciphertext = vec![0u8; 5];
    let tag = push
        .push(Tag::Message, b"never", &mut ciphertext)
        .expect("a Message-tagged chunk, deliberately never followed by Final");

    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; 5];
    let read_tag = pull
        .pull(Tag::Message.to_byte(), &ciphertext, &tag, &mut out)
        .expect("the chunk itself is valid");
    assert_eq!(read_tag, Tag::Message);
    assert!(
        !pull.is_finalized(),
        "a caller reaching EOF here must be able to detect the stream was never finalized"
    );
}

#[test]
fn push_after_finalized_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (mut push, _header) =
        PushState::init(&key).expect("OS CSPRNG available in test environment");
    let mut ciphertext = vec![0u8; 5];
    push.push(Tag::Final, b"final", &mut ciphertext)
        .expect("first push finalizes the state");

    let mut ciphertext2 = vec![0u8; 3];
    let err = push
        .push(Tag::Message, b"any", &mut ciphertext2)
        .expect_err("pushing again after Final must be rejected");
    assert!(matches!(err, SecretstreamError::StreamFinalized));
}

#[test]
fn pull_after_finalized_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (header, ciphertext, tag) = push_one(&key, Tag::Final, b"final");

    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; 5];
    pull.pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect("first pull finalizes the state");

    let err = pull
        .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect_err("pulling again after Final must be rejected, even with the same valid record");
    assert!(matches!(err, SecretstreamError::StreamFinalized));
}

#[test]
fn all_zero_key_round_trips_like_any_other_key() {
    let key = Key::from_bytes([0u8; 32]);
    let (header, ciphertext, tag) = push_one(&key, Tag::Final, b"degenerate key");
    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; ciphertext.len()];
    pull.pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut out)
        .expect("an all-zero key is legal, degenerate-but-legal input");
    assert_eq!(out, b"degenerate key");
}

#[test]
fn mismatched_ciphertext_out_length_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (mut push, _header) =
        PushState::init(&key).expect("OS CSPRNG available in test environment");
    let mut wrong_len = vec![0u8; 3];
    let err = push
        .push(Tag::Final, b"12345", &mut wrong_len)
        .expect_err("ciphertext_out.len() != plaintext.len() must be rejected");
    assert!(matches!(err, SecretstreamError::InvalidLength));
}

#[test]
fn mismatched_plaintext_out_length_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (header, ciphertext, tag) = push_one(&key, Tag::Final, b"12345");
    let mut pull = PullState::init(&key, &header);
    let mut wrong_len = vec![0u8; 2];
    let err = pull
        .pull(Tag::Final.to_byte(), &ciphertext, &tag, &mut wrong_len)
        .expect_err("plaintext_out.len() != ciphertext.len() must be rejected");
    assert!(matches!(err, SecretstreamError::InvalidLength));
}

#[test]
fn unknown_tag_byte_is_rejected() {
    let key = Key::generate().expect("OS CSPRNG available in test environment");
    let (header, ciphertext, tag) = push_one(&key, Tag::Final, b"secret");
    let mut pull = PullState::init(&key, &header);
    let mut out = vec![0u8; ciphertext.len()];
    let err = pull
        .pull(0x04, &ciphertext, &tag, &mut out)
        .expect_err("tag_byte outside 0..=3 must be rejected");
    assert!(matches!(err, SecretstreamError::UnknownTag));
}

#[test]
fn tag_byte_round_trips_through_to_from_byte() {
    for tag in [Tag::Message, Tag::Push, Tag::Rekey, Tag::Final] {
        assert_eq!(Tag::from_byte(tag.to_byte()), Some(tag));
    }
    assert_eq!(Tag::from_byte(0x04), None);
    assert_eq!(Tag::from_byte(0xFF), None);
}

fn non_final_tag(byte: u8) -> Tag {
    match byte % 3 {
        0 => Tag::Message,
        1 => Tag::Push,
        _ => Tag::Rekey,
    }
}

proptest! {
    #[test]
    fn round_trip_property(
        chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..=512), 1..=8),
        tag_bytes in proptest::collection::vec(any::<u8>(), 8)
    ) {
        let key = Key::generate().expect("OS CSPRNG available in test environment");
        let (mut push, header) = PushState::init(&key).expect("OS CSPRNG available in test environment");

        let mut records = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let tag = if i == chunks.len() - 1 {
                Tag::Final
            } else {
                non_final_tag(tag_bytes[i])
            };
            let mut ciphertext = vec![0u8; chunk.len()];
            let auth_tag = push.push(tag, chunk, &mut ciphertext)
                .expect("sequential push on a live state");
            records.push((tag, ciphertext, auth_tag));
        }

        let mut pull = PullState::init(&key, &header);
        for (i, (tag, ciphertext, auth_tag)) in records.iter().enumerate() {
            let mut out = vec![0u8; chunks[i].len()];
            let read_tag = pull.pull(tag.to_byte(), ciphertext, auth_tag, &mut out)
                .expect("sequential pull in order");
            prop_assert_eq!(read_tag, *tag);
            prop_assert_eq!(&out, &chunks[i]);
        }
        prop_assert!(pull.is_finalized());
    }
}
