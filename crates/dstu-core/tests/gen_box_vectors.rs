//! Generator for `tests/vectors/box/v3.json` (T-265, D-239), the shared `crypto_box`/
//! `crypto_box384`/`crypto_box512` vectors every reader (`uacrypt box-open` and the 8 language
//! bindings) is tested against. Run once, by hand; the JSON is committed data:
//!
//! ```text
//! cargo test -p dstu-core --test gen_box_vectors -- --ignored
//! ```
//!
//! `seal` draws fresh randomness, so a rerun writes different (equally valid) bytes. A
//! self-generated interop pin, not an oracle: no external reference exists for this construction
//! (D-68).

#![cfg(feature = "std")]

use std::fmt::Write as _;

const CHUNK_BYTES: usize = 8192;

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + 7) % 256).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

fn counting_key<const N: usize>() -> [u8; N] {
    let mut key = [0u8; N];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::try_from(i + 1).unwrap();
    }
    key
}

/// `(name, expect, sealed, plaintext_len)` for one curve, from its `seal`.
fn cases(curve: u32, seal: impl Fn(&[u8]) -> Vec<u8>) -> Vec<String> {
    let mut rows = Vec::new();
    let mut row = |name: &str, expect: &str, sealed: &[u8], len: usize| {
        rows.push(format!(
            "    {{\"curve\": {curve}, \"name\": \"{name}\", \"expect\": \"{expect}\", \"plaintext_len\": {len}, \"sealed_hex\": \"{}\"}}",
            hex(sealed)
        ));
    };
    for len in [0, 1, CHUNK_BYTES, CHUNK_BYTES + 1] {
        row(&format!("valid_{len}"), "ok", &seal(&pattern(len)), len);
    }
    let valid = seal(&pattern(100));
    let mut tampered = valid.clone();
    *tampered.last_mut().unwrap() ^= 1;
    row("tampered_auth_tag", "invalid_ciphertext", &tampered, 0);
    row("cut_last_byte", "truncated", &valid[..valid.len() - 1], 0);
    let mut trailing = valid.clone();
    trailing.push(0);
    row("trailing_byte", "invalid_ciphertext", &trailing, 0);
    let mut version = valid.clone();
    version[0] = 4;
    row("unknown_version", "unsupported_version", &version, 0);
    rows
}

#[test]
#[ignore = "generator - run by hand, see the module doc"]
fn generate() {
    let sk256 = dstu_core::crypto_box::SecretKey::from_bytes(&counting_key::<32>()).unwrap();
    let sk384 = dstu_core::crypto_box384::SecretKey::from_bytes(&counting_key::<48>()).unwrap();
    let sk512 = dstu_core::crypto_box512::SecretKey::from_bytes(&counting_key::<64>()).unwrap();
    let pk256 = sk256.public_key();
    let pk384 = sk384.public_key();
    let pk512 = sk512.public_key();
    let mut rows = cases(256, |m| dstu_core::crypto_box::seal(m, &pk256).unwrap());
    rows.extend(cases(384, |m| {
        dstu_core::crypto_box384::seal(m, &pk384).unwrap()
    }));
    rows.extend(cases(512, |m| {
        dstu_core::crypto_box512::seal(m, &pk512).unwrap()
    }));

    let mut out = String::new();
    out.push_str("{\n  \"source\": \"Self-generated interop pin, not an oracle (D-68, D-239). Written by crates/dstu-core/tests/gen_box_vectors.rs over crypto_box{,384,512}::seal (format v3, T-265; 384 added T-297). Secret keys are the counting bytes 01 02 ..; plaintext of a valid case is (i*31+7) mod 256 of plaintext_len bytes. expect: ok | invalid_ciphertext | truncated | unsupported_version. The 0.4-0.6 format is in legacy_v2.json, refused by every open (core, uacrypt, C ABI, bindings) as unsupported_version since T-310. There is no 384 legacy file.\",\n");
    let _ = writeln!(out, "  \"format_version\": 3,");
    let _ = writeln!(
        out,
        "  \"box256_secret_key_hex\": \"{}\",",
        hex(&sk256.to_bytes())
    );
    let _ = writeln!(
        out,
        "  \"box384_secret_key_hex\": \"{}\",",
        hex(&sk384.to_bytes())
    );
    let _ = writeln!(
        out,
        "  \"box512_secret_key_hex\": \"{}\",",
        hex(&sk512.to_bytes())
    );
    out.push_str("  \"cases\": [\n");
    out.push_str(&rows.join(",\n"));
    out.push_str("\n  ]\n}\n");
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/box/v3.json"),
        out,
    )
    .unwrap();
}
