#![no_main]

use dstu_core::crypto_secretstream::{Key, PullState, PushState, Tag};
use libfuzzer_sys::fuzz_target;

// Required by SECURITY.md ("cargo fuzz is required ... not optional"). `PullState::pull` makes an
// authentication decision on fully attacker-controlled input (tag byte, ciphertext, tag, and
// length fields) the same way `kalyna_gcm::decrypt` does (D-56/D-68's fuzz precedent) - it must
// never panic/crash regardless of content or length, including tag bytes outside 0..=3 and
// mismatched buffer lengths that must hit a typed `SecretstreamError` rather than panic.
fuzz_target!(|data: &[u8]| {
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
