//! D-208: `uacrypt decrypt` against the shared stream-file vectors
//! (`crates/dstu-core/tests/vectors/secretstream-file/v2.json`) that every language binding's reader
//! is tested against too. `ok` cases must decrypt to the given plaintext; every other case must fail
//! with its own named error and leave no `--out`.

mod support;
use support::{uacrypt, write_bytes, TempDir};

const VECTORS: &str = include_str!("../../dstu-core/tests/vectors/secretstream-file/v2.json");

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

struct Case {
    name: String,
    expect: String,
    file: Vec<u8>,
    plaintext: Vec<u8>,
}

fn cases() -> Vec<Case> {
    VECTORS
        .lines()
        .filter(|line| line.trim_start().starts_with("{\"name\""))
        .map(|line| Case {
            name: field(line, "name").to_string(),
            expect: field(line, "expect").to_string(),
            file: decode_hex(field(line, "file_hex")),
            plaintext: decode_hex(field(line, "plaintext_hex")),
        })
        .collect()
}

fn expected_message(expect: &str) -> &'static str {
    match expect {
        "unsupported_version" => "unsupported stream format version",
        "bad_chunk_length" => "non-final chunk",
        "truncated" => "truncated",
        "auth" => "authentication failed",
        other => panic!("unknown expect value {other}"),
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "spawns the real uacrypt binary - Miri cannot run a subprocess"
)]
fn every_shared_vector_decrypts_or_fails_as_specified() {
    let dir = TempDir::new("ss_golden");
    let key = dir.file("key.bin");
    write_bytes(&key, &decode_hex(field(VECTORS, "key_hex")));
    let all = cases();
    assert_eq!(all.len(), 7, "fixture is incomplete");
    for case in all {
        let in_path = dir.file(&format!("{}.enc", case.name));
        let out_path = dir.file(&format!("{}.out", case.name));
        write_bytes(&in_path, &case.file);
        let r = uacrypt([
            "decrypt",
            "--key",
            key.to_str().unwrap(),
            "--in",
            in_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
        ]);
        if case.expect == "ok" {
            assert!(r.success(), "{}: stderr={}", case.name, r.stderr);
            assert_eq!(
                support::read_bytes(&out_path),
                case.plaintext,
                "{}",
                case.name
            );
        } else {
            assert!(r.failure(), "{} must be rejected", case.name);
            let wanted = expected_message(&case.expect);
            assert!(
                r.stderr.contains(wanted),
                "{}: expected '{wanted}', stderr={}",
                case.name,
                r.stderr
            );
            assert!(!out_path.exists(), "{} left an --out behind", case.name);
        }
    }
}
