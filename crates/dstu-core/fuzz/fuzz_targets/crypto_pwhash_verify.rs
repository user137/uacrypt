#![no_main]

use dstu_core::crypto_pwhash::verify_password;
use libfuzzer_sys::fuzz_target;
use password_hash::{Output, SaltString};

// T-272/T-225: `verify_password` reads an untrusted PHC string and must return a bool for any of
// them - no panic, no abort, no allocation above its 1 GiB bound (libFuzzer's default
// `-malloc_limit_mb` of 2048 reports the 2 TiB allocation the unfixed code made as a crash).
// Random bytes rarely get past the PHC parser, so odd selector bytes build a well-formed string
// from the input: algorithm, version, extra parameter, m/t/p and salt/tag lengths all come from
// the fuzzer. Even selector bytes feed the rest to the parser as-is.
fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        if let Ok(s) = core::str::from_utf8(rest) {
            let _ = verify_password(b"pw", s);
        }
        return;
    }
    if rest.len() < 14 {
        return;
    }
    let (costs, rest) = rest.split_at(12);
    let word = |i: usize| u32::from_le_bytes([costs[i], costs[i + 1], costs[i + 2], costs[i + 3]]);
    let (m, t, p) = (word(0), word(4), word(8));
    let salt_len = usize::from(rest[0]) % 49;
    let tag_len = usize::from(rest[1]) % 65;
    let bytes = &rest[2..];
    let salt = &bytes[..salt_len.min(bytes.len())];
    let tag = &bytes[salt.len()..][..tag_len.min(bytes.len() - salt.len())];
    let (Ok(salt), Ok(tag)) = (SaltString::encode_b64(salt), Output::new(tag)) else {
        return;
    };

    let algorithm = ["argon2id", "argon2i", "argon2d", "argon2x"][usize::from(selector >> 1) & 3];
    let version = ["v=19$", "v=16$", "", "v=19$"][usize::from(selector >> 3) & 3];
    let extra = ["", ",keyid=AAAAAAAA", ",data=AAAAAAAA", ",m=8"][usize::from(selector >> 5) & 3];
    let hash = format!(
        "${algorithm}${version}m={m},t={t},p={p}{extra}${}${tag}",
        salt.as_str()
    );
    let _ = verify_password(b"pw", &hash);
});
