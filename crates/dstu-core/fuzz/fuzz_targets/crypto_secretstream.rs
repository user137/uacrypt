#![no_main]

#[path = "../common/negative.rs"]
mod negative;

use dstu_core::crypto_secretstream::{Key, PullState, PushState, Tag};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const VECTORS: &str = include_str!("../../tests/vectors/secretstream-file/v2.json");
const AUTH_TAG_LEN: usize = 16;

/// `secretstream-file/v2.json`'s `valid` file: its key, header and first record as
/// `tag || ciphertext || auth tag` (the length field is the file codec's, not `pull`'s).
struct Fixture {
    key: [u8; 32],
    header: [u8; 32],
    record: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let key = negative::decode_hex(negative::field(VECTORS, "key_hex"));
        let line = VECTORS
            .lines()
            .find(|l| l.contains("\"name\": \"valid\""))
            .expect("valid case");
        let file = negative::decode_hex(negative::field(line, "file_hex"));
        let len = u32::from_le_bytes(file[34..38].try_into().expect("length field")) as usize;
        let mut record = vec![file[33]];
        record.extend_from_slice(&file[38..38 + len + AUTH_TAG_LEN]);
        Fixture {
            key: key.try_into().expect("32-byte key"),
            header: file[1..33].try_into().expect("32-byte header"),
            record,
        }
    })
}

/// T-225: `pull` on a fresh state accepts the pinned record and nothing derived from it.
fn check_record(candidate: &[u8]) {
    let f = fixture();
    let accepted = candidate.len() > AUTH_TAG_LEN && {
        let mut pull = PullState::init(&Key::from_bytes(f.key), &f.header);
        let (body, auth_tag) = candidate.split_at(candidate.len() - AUTH_TAG_LEN);
        let mut out = vec![0u8; body.len() - 1];
        pull.pull(body[0], &body[1..], auth_tag, &mut out).is_ok()
    };
    assert_eq!(
        accepted,
        candidate == f.record.as_slice(),
        "pull = {accepted} for a {}-byte record",
        candidate.len()
    );
}

// Required by docs/SECURITY.md ("cargo fuzz is required ... not optional"). `PullState::pull` makes an
// authentication decision on fully attacker-controlled input (tag byte, ciphertext, tag, and
// length fields) the same way `kalyna_gcm::decrypt` does (D-56/D-68's fuzz precedent) - it must
// never panic/crash regardless of content or length, including tag bytes outside 0..=3 and
// mismatched buffer lengths that must hit a typed `SecretstreamError` rather than panic.
fuzz_target!(|data: &[u8]| {
    check_record(data);
    if let Some(candidate) = negative::mutate(&fixture().record, data) {
        check_record(&candidate);
    }

    if data.len() < 32 + 32 {
        return;
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&data[..32]);
    let key = Key::from_bytes(key_bytes);

    let mut header = [0u8; 32];
    header.copy_from_slice(&data[32..64]);
    let rest = &data[64..];

    // Round-trip: push a few chunks with attacker-influenced (but well-formed) tags derived from
    // `rest`, always ending in Final, then pull them back through a state built from the same
    // header a real caller would have transmitted.
    if let Ok((mut push, real_header)) = PushState::init(&key) {
        let mut records = Vec::new();
        let chunk_len = rest.len().min(64);
        if chunk_len > 0 {
            for (i, byte) in rest[..chunk_len.min(8)].iter().enumerate() {
                let is_last = i == chunk_len.min(8) - 1;
                let tag = if is_last {
                    Tag::Final
                } else {
                    match byte % 4 {
                        0 => Tag::Message,
                        1 => Tag::Push,
                        2 => Tag::Rekey,
                        _ => Tag::Message,
                    }
                };
                let plaintext = &[*byte];
                let mut ciphertext = [0u8; 1];
                if let Ok(auth_tag) = push.push(tag, plaintext, &mut ciphertext) {
                    records.push((tag, ciphertext, auth_tag));
                } else {
                    break;
                }
            }
        }

        let mut pull = PullState::init(&key, &real_header);
        for (tag, ciphertext, auth_tag) in &records {
            let mut out = [0u8; 1];
            let _ = pull.pull(tag.to_byte(), ciphertext, auth_tag, &mut out);
        }
    }

    // Direct attack surface: arbitrary tag byte/ciphertext/tag/plaintext_out straight into `pull`
    // against a state derived from `header` - never anything a real `push` produced.
    let mut pull = PullState::init(&key, &header);
    if !rest.is_empty() {
        let tag_byte = rest[0];
        let body = &rest[1..];
        let cap = body.len().min(128);
        let ciphertext = &body[..cap];
        let tag_cap = body.len().saturating_sub(cap).min(32);
        let auth_tag = &body[cap..cap + tag_cap];
        let mut out = vec![0u8; cap];
        let _ = pull.pull(tag_byte, ciphertext, auth_tag, &mut out);

        // Also exercise mismatched plaintext_out lengths directly.
        let mut short_out = vec![0u8; cap.saturating_sub(1)];
        let _ = pull.pull(tag_byte, ciphertext, auth_tag, &mut short_out);
    }
});
