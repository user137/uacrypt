//! Generator for `crates/dstu-core/tests/vectors/secretstream-file/v2.json` (D-208), the shared
//! stream-file vectors every reader (`uacrypt decrypt` and the 8 language bindings) is tested
//! against. Run once, by hand; the JSON is committed data:
//!
//! ```text
//! UACRYPT_V038_FILE=<a file `uacrypt` 0.3.8 encrypted under key 00 01 .. 1f> \
//!     cargo test -p uacrypt --test gen_secretstream_file_vectors -- --ignored
//! ```
//!
//! The framing is written here directly over `crypto_secretstream::PushState`, not through
//! `uacrypt`'s own writer, so the file is a second, independent encoder of the format. It is a
//! self-generated interop pin, not an oracle: no external reference exists for this construction
//! (D-68).

use dstu_core::crypto_secretstream::{Key, PushState, Tag, FORMAT_VERSION};
use std::fmt::Write as _;

const CHUNK_BYTES: usize = 8192;

fn key() -> Key {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    Key::from_bytes(bytes)
}

/// `(i * 31 + 7) mod 256`, the same pattern the 0.3.8 fixture was encrypted from.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + 7) % 256).unwrap())
        .collect()
}

/// `version || header || records`, one record per `(tag, chunk)`.
fn frame(chunks: &[(Tag, &[u8])]) -> Vec<u8> {
    let (mut push, header) = PushState::init(&key()).unwrap();
    let mut file = vec![FORMAT_VERSION];
    file.extend_from_slice(&header);
    for (tag, chunk) in chunks {
        let mut ciphertext = vec![0u8; chunk.len()];
        let auth_tag = push.push(*tag, chunk, &mut ciphertext).unwrap();
        file.push(tag.to_byte());
        file.extend_from_slice(&u32::try_from(chunk.len()).unwrap().to_le_bytes());
        file.extend_from_slice(&ciphertext);
        file.extend_from_slice(&auth_tag);
    }
    file
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

#[test]
#[ignore = "generator - run by hand, see the module doc"]
fn generate() {
    let legacy_path = std::env::var("UACRYPT_V038_FILE").expect("UACRYPT_V038_FILE must be set");
    let legacy = std::fs::read(legacy_path).unwrap();
    let legacy_expect = if legacy[0] == FORMAT_VERSION {
        "auth"
    } else {
        "unsupported_version"
    };

    let valid_pt = pattern(2 * CHUNK_BYTES + 100);
    let valid = frame(&[
        (Tag::Message, &valid_pt[..CHUNK_BYTES]),
        (Tag::Message, &valid_pt[CHUNK_BYTES..2 * CHUNK_BYTES]),
        (Tag::Final, &valid_pt[2 * CHUNK_BYTES..]),
    ]);
    let exact_pt = pattern(CHUNK_BYTES);
    let short_pt = pattern(150);
    let mut bad_version = valid.clone();
    bad_version[0] = 3;

    // T-277: the rejections every reader hand-rolls. Offsets into `valid`: version (1) + header,
    // then the first record `tag (1) || len (4) || ct (8192) || auth tag (16)`.
    let empty = frame(&[(Tag::Final, &[])]);
    let header_end = empty.len() - (1 + 4 + 16);
    let first_record_end = header_end + 1 + 4 + CHUNK_BYTES + 16;
    let mut trailing = empty.clone();
    trailing.push(0);
    let mut len_8193_final = empty[..header_end].to_vec();
    len_8193_final.push(Tag::Final.to_byte());
    len_8193_final.extend_from_slice(&8193u32.to_le_bytes());
    len_8193_final.extend_from_slice(&[0u8; 8193 + 16]);
    let mut len_max_message = empty[..header_end].to_vec();
    len_max_message.push(Tag::Message.to_byte());
    len_max_message.extend_from_slice(&u32::MAX.to_le_bytes());
    let mut unknown_tag = valid.clone();
    unknown_tag[header_end] = 0x04;
    let mut tampered_tag = valid.clone();
    *tampered_tag.last_mut().unwrap() ^= 1;

    let cases: [(&str, &str, Vec<u8>, Vec<u8>); 15] = [
        ("valid", "ok", valid.clone(), valid_pt),
        ("valid_empty", "ok", frame(&[(Tag::Final, &[])]), Vec::new()),
        (
            "valid_exact_multiple",
            "ok",
            frame(&[(Tag::Final, &exact_pt)]),
            exact_pt.clone(),
        ),
        (
            "bad_version",
            "unsupported_version",
            bad_version,
            Vec::new(),
        ),
        (
            "short_non_final",
            "bad_chunk_length",
            frame(&[
                (Tag::Message, &short_pt[..100]),
                (Tag::Final, &short_pt[100..]),
            ]),
            Vec::new(),
        ),
        ("v1_0_3_8", legacy_expect, legacy, Vec::new()),
        (
            "version_only",
            "truncated",
            vec![FORMAT_VERSION],
            Vec::new(),
        ),
        (
            "trailing_after_final",
            "trailing_data",
            trailing,
            Vec::new(),
        ),
        (
            "len_8193_final",
            "oversized_chunk",
            len_8193_final,
            Vec::new(),
        ),
        (
            "len_ffffffff_message",
            "oversized_chunk",
            len_max_message,
            Vec::new(),
        ),
        (
            "missing_final",
            "truncated",
            valid[..first_record_end].to_vec(),
            Vec::new(),
        ),
        (
            "truncated_in_ciphertext",
            "truncated",
            valid[..header_end + 1 + 4 + 100].to_vec(),
            Vec::new(),
        ),
        (
            "truncated_in_tag",
            "truncated",
            valid[..first_record_end - 8].to_vec(),
            Vec::new(),
        ),
        ("unknown_tag_byte", "unknown_tag", unknown_tag, Vec::new()),
        ("tampered_auth_tag", "auth", tampered_tag, Vec::new()),
    ];

    let mut json = String::from("{\n");
    json.push_str(
        "  \"source\": \"Self-generated interop pin, not an oracle (D-68, D-208). Written by \
         crates/uacrypt/tests/gen_secretstream_file_vectors.rs over crypto_secretstream::PushState. \
         v1_0_3_8 is a real file from uacrypt 0.3.8 (tag v0.3.8) under the same key and the same \
         (i*31+7) mod 256 plaintext as valid; short_non_final carries genuinely valid tags, so \
         rejecting it proves the exact-8192 rule, not authentication. The cases after version_only \
         (T-277) pin the other rejections: data after Final, a length above 8192, no Final, a cut \
         inside a record, an unknown tag byte, a tampered auth tag. expect: ok | \
         unsupported_version | bad_chunk_length | truncated | auth | trailing_data | \
         oversized_chunk | unknown_tag.\",\n",
    );
    let _ = writeln!(json, "  \"format_version\": {FORMAT_VERSION},");
    let _ = writeln!(json, "  \"chunk_bytes\": {CHUNK_BYTES},");
    let _ = writeln!(json, "  \"key_hex\": \"{}\",", hex(key().as_bytes()));
    json.push_str("  \"cases\": [\n");
    for (i, (name, expect, file, plaintext)) in cases.iter().enumerate() {
        let comma = if i + 1 < cases.len() { "," } else { "" };
        let _ = writeln!(
            json,
            "    {{\"name\": \"{name}\", \"expect\": \"{expect}\", \"file_hex\": \"{}\", \
             \"plaintext_hex\": \"{}\"}}{comma}",
            hex(file),
            hex(plaintext)
        );
    }
    json.push_str("  ]\n}\n");

    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dstu-core/tests/vectors/secretstream-file/v2.json");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(out, json).unwrap();
}
