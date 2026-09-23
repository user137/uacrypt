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

    let cases: [(&str, &str, Vec<u8>, Vec<u8>); 7] = [
        ("valid", "ok", valid, valid_pt),
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
    ];

    let mut json = String::from("{\n");
    json.push_str(
        "  \"source\": \"Self-generated interop pin, not an oracle (D-68, D-208). Written by \
         crates/uacrypt/tests/gen_secretstream_file_vectors.rs over crypto_secretstream::PushState. \
         v1_0_3_8 is a real file from uacrypt 0.3.8 (tag v0.3.8) under the same key and the same \
         (i*31+7) mod 256 plaintext as valid; short_non_final carries genuinely valid tags, so \
         rejecting it proves the exact-8192 rule, not authentication. expect: ok | \
         unsupported_version | bad_chunk_length | truncated | auth.\",\n",
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
