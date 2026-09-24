//! Typed key files (`docs/TASKS.md` T-256, `docs/DECISIONS.md` D-212): every key `uacrypt` writes
//! is one text line `<prefix>:<hex key>:<hex check>` that says what it is, so a key of the wrong
//! kind is rejected by name before any work (rule R1) instead of failing later, or worse, not
//! failing at all (`box-seal` accepted a box secret key as a public key and wrote a file nobody
//! could open). The format is specified in `docs/CLI.md` "Key files".
//!
//! Secret key bytes are hex-coded and compared without secret-dependent branches or table
//! lookups (rule R6): the only branches are on the file length, the prefix and the fixed
//! separator positions, all of which are public.

use crate::CliError;
use dstu_core::hazmat::kupyna::Kupyna256Hasher;
use std::fmt::Write as _;
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Domain separation for the check value; the `-v1` is the key file format version.
const CHECK_DOMAIN: &[u8] = b"uacrypt-key-v1";
const CHECK_LEN: usize = 4;
/// Longer than any valid key line (the longest is a box-512 key, ~160 bytes), so a big file
/// passed as `--key` by mistake is rejected without reading it whole.
const MAX_KEY_FILE_BYTES: u64 = 256;

/// What a key file holds. `uacrypt`'s own key vocabulary, not part of `dstu-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Symmetric,
    Sign163Secret,
    Sign163Public,
    Sign257Secret,
    Sign257Public,
    Box256Secret,
    Box256Public,
    Box512Secret,
    Box512Public,
}

const ALL_KINDS: [KeyKind; 9] = [
    KeyKind::Symmetric,
    KeyKind::Sign163Secret,
    KeyKind::Sign163Public,
    KeyKind::Sign257Secret,
    KeyKind::Sign257Public,
    KeyKind::Box256Secret,
    KeyKind::Box256Public,
    KeyKind::Box512Secret,
    KeyKind::Box512Public,
];

impl KeyKind {
    /// The first field of the key line. Secret kinds are upper case, like age's
    /// `AGE-SECRET-KEY-`, so a secret key is hard to mistake for something to share.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            KeyKind::Symmetric => "UACRYPT-SECRET-SYMMETRIC",
            KeyKind::Sign163Secret => "UACRYPT-SECRET-SIGN163",
            KeyKind::Sign163Public => "uacrypt-sign163-public",
            KeyKind::Sign257Secret => "UACRYPT-SECRET-SIGN257",
            KeyKind::Sign257Public => "uacrypt-sign257-public",
            KeyKind::Box256Secret => "UACRYPT-SECRET-BOX256",
            KeyKind::Box256Public => "uacrypt-box256-public",
            KeyKind::Box512Secret => "UACRYPT-SECRET-BOX512",
            KeyKind::Box512Public => "uacrypt-box512-public",
        }
    }

    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            KeyKind::Sign163Secret => 21,
            KeyKind::Symmetric | KeyKind::Box256Secret | KeyKind::Box256Public => 32,
            KeyKind::Sign257Secret => 33,
            KeyKind::Sign163Public => 42,
            KeyKind::Sign257Public => 66,
            KeyKind::Box512Secret | KeyKind::Box512Public => 64,
        }
    }

    #[must_use]
    pub fn is_secret(self) -> bool {
        matches!(
            self,
            KeyKind::Symmetric
                | KeyKind::Sign163Secret
                | KeyKind::Sign257Secret
                | KeyKind::Box256Secret
                | KeyKind::Box512Secret
        )
    }

    /// The `key-import --kind` value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            KeyKind::Symmetric => "symmetric",
            KeyKind::Sign163Secret => "sign163-secret",
            KeyKind::Sign163Public => "sign163-public",
            KeyKind::Sign257Secret => "sign257-secret",
            KeyKind::Sign257Public => "sign257-public",
            KeyKind::Box256Secret => "box256-secret",
            KeyKind::Box256Public => "box256-public",
            KeyKind::Box512Secret => "box512-secret",
            KeyKind::Box512Public => "box512-public",
        }
    }

    /// How error messages name the kind.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            KeyKind::Symmetric => "symmetric key (for encrypt/decrypt)",
            KeyKind::Sign163Secret => "signing key (DSTU 4145, m=163)",
            KeyKind::Sign163Public => "verifying key (DSTU 4145, m=163)",
            KeyKind::Sign257Secret => "signing key (DSTU 4145, m=257)",
            KeyKind::Sign257Public => "verifying key (DSTU 4145, m=257)",
            KeyKind::Box256Secret => "box secret key (DSTU 9041, l(p)=256)",
            KeyKind::Box256Public => "box public key (DSTU 9041, l(p)=256)",
            KeyKind::Box512Secret => "box secret key (DSTU 9041, l(p)=512)",
            KeyKind::Box512Public => "box public key (DSTU 9041, l(p)=512)",
        }
    }

    /// The command that produces a key of this kind.
    #[must_use]
    pub fn made_by(self) -> &'static str {
        match self {
            KeyKind::Symmetric => "uacrypt keygen",
            KeyKind::Sign163Secret => "uacrypt sign-keygen",
            KeyKind::Sign257Secret => "uacrypt sign-keygen257",
            KeyKind::Sign163Public | KeyKind::Sign257Public => "uacrypt sign-pubkey",
            KeyKind::Box256Secret => "uacrypt box-keygen",
            KeyKind::Box512Secret => "uacrypt box-keygen512",
            KeyKind::Box256Public | KeyKind::Box512Public => "uacrypt box-pubkey",
        }
    }

    pub(crate) fn parse_name(value: &str) -> Option<KeyKind> {
        ALL_KINDS.into_iter().find(|k| k.name() == value)
    }

    pub(crate) fn names() -> impl Iterator<Item = &'static str> {
        ALL_KINDS.into_iter().map(KeyKind::name)
    }
}

/// The "what to do instead" sentence of a wrong-kind error.
/// Both curves' public kinds are made by the same command, so makers are deduplicated.
pub(crate) fn wrong_kind_hint(expected: &[KeyKind]) -> String {
    let mut makers: Vec<String> = Vec::new();
    for maker in expected.iter().map(|k| format!("`{}`", k.made_by())) {
        if !makers.contains(&maker) {
            makers.push(maker);
        }
    }
    format!("make the right key with {}", makers.join(" or "))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// No known prefix: not a typed key file at all (a raw 0.3.x/0.4.0 key, or another file).
    NotTyped,
    /// A known prefix, but the rest of the line is not `:<hex>:<check>` of the right length.
    Malformed(KeyKind),
    /// Well-formed, but the check value does not match the key.
    CheckMismatch(KeyKind),
}

fn check_value(kind: KeyKind, key: &[u8]) -> [u8; CHECK_LEN] {
    let mut hasher = Kupyna256Hasher::new();
    hasher.update(CHECK_DOMAIN);
    hasher.update(&[0]);
    hasher.update(kind.prefix().as_bytes());
    hasher.update(&[0]);
    hasher.update(key);
    let digest = hasher.finalize();
    let mut check = [0u8; CHECK_LEN];
    check.copy_from_slice(&digest[..CHECK_LEN]);
    check
}

/// Lower-case hex digit of `n` (0..=15) without a branch or a table lookup.
fn hex_digit(n: u8) -> u8 {
    let n = i32::from(n);
    let letter_gap = ((9 - n) >> 31) & i32::from(b'a' - b'0' - 10);
    // `n` is 0..=15, so the sum is at most b'f'.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let digit = (n + i32::from(b'0') + letter_gap) as u8;
    digit
}

/// Value of lower-case hex digit `c` and 1 if `c` is one, else (0, 0); no branch, no table.
fn hex_value(c: u8) -> (u8, u8) {
    let c = i32::from(c);
    let d = c - i32::from(b'0');
    let l = c - i32::from(b'a') + 10;
    let d_ok = !((d | (9 - d)) >> 31) & 1;
    let l_ok = !(((l - 10) | (15 - l)) >> 31) & 1;
    let value = (d & -d_ok) | (l & -l_ok);
    // Both are 0..=15 and 0..=1 by construction.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let out = (value as u8, (d_ok | l_ok) as u8);
    out
}

/// Decodes `hex` into `out` (`hex.len() == 2 * out.len()`); returns 1 if every digit was valid.
pub(crate) fn decode_hex(hex: &[u8], out: &mut [u8]) -> u8 {
    let mut ok = 1u8;
    for (byte, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
        let (hi, hi_ok) = hex_value(pair[0]);
        let (lo, lo_ok) = hex_value(pair[1]);
        *byte = (hi << 4) | lo;
        ok &= hi_ok & lo_ok;
    }
    ok
}

/// The key line for `key`, with a trailing `\n`. Every caller passes a `kind.key_len()`-byte key
/// (a fixed-size library encoding or a length-checked raw file); the `debug_assert` catches a
/// mismatch in tests, and a release build never panics here.
pub(crate) fn encode(kind: KeyKind, key: &[u8]) -> Zeroizing<Vec<u8>> {
    debug_assert_eq!(key.len(), kind.key_len());
    let check = check_value(kind, key);
    let prefix = kind.prefix().as_bytes();
    let mut line = Zeroizing::new(Vec::with_capacity(
        prefix.len() + 2 * key.len() + 2 * CHECK_LEN + 3,
    ));
    line.extend_from_slice(prefix);
    line.push(b':');
    for &byte in key {
        line.push(hex_digit(byte >> 4));
        line.push(hex_digit(byte & 0x0f));
    }
    line.push(b':');
    for byte in check {
        line.push(hex_digit(byte >> 4));
        line.push(hex_digit(byte & 0x0f));
    }
    line.push(b'\n');
    line
}

/// The check value of `key` as 8 hex digits, for `key-import`'s report line. Public data: it is
/// already part of every key file.
pub(crate) fn check_hex(kind: KeyKind, key: &[u8]) -> String {
    check_value(kind, key)
        .iter()
        .fold(String::with_capacity(2 * CHECK_LEN), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Bytes [`sniff_kind`] needs: the longest prefix plus its `:`.
pub(crate) const SNIFF_LEN: usize = 25;

/// The kind of a file starting with `<prefix>:` - the start of a key line, even a damaged one.
/// Looks at no key hex, so a caller only ever reads [`SNIFF_LEN`] bytes of a secret key file.
pub(crate) fn sniff_kind(head: &[u8]) -> Option<KeyKind> {
    ALL_KINDS.into_iter().find(|kind| {
        head.strip_prefix(kind.prefix().as_bytes())
            .is_some_and(|rest| rest.first() == Some(&b':'))
    })
}

/// Parses one key line. Only a single trailing `\n` or `\r\n` is tolerated.
pub(crate) fn decode(text: &[u8]) -> Result<(KeyKind, Zeroizing<Vec<u8>>), DecodeError> {
    let line = text
        .strip_suffix(b"\r\n")
        .or_else(|| text.strip_suffix(b"\n"))
        .unwrap_or(text);
    let kind = ALL_KINDS
        .into_iter()
        .find(|k| {
            let p = k.prefix().as_bytes();
            line.len() > p.len() && line.starts_with(p) && line[p.len()] == b':'
        })
        .ok_or(DecodeError::NotTyped)?;

    let key_start = kind.prefix().len() + 1;
    let key_end = key_start + 2 * kind.key_len();
    if line.len() != key_end + 1 + 2 * CHECK_LEN || line[key_end] != b':' {
        return Err(DecodeError::Malformed(kind));
    }
    let mut key = Zeroizing::new(vec![0u8; kind.key_len()]);
    let mut check = [0u8; CHECK_LEN];
    let ok = decode_hex(&line[key_start..key_end], &mut key)
        & decode_hex(&line[key_end + 1..], &mut check);
    if ok != 1 {
        return Err(DecodeError::Malformed(kind));
    }
    if !bool::from(check_value(kind, &key).ct_eq(&check)) {
        return Err(DecodeError::CheckMismatch(kind));
    }
    Ok((kind, key))
}

/// Reads `--key` for `command`, accepting only the `expected` kinds.
///
/// # Errors
///
/// [`CliError::Io`] if the file can't be read, [`CliError::KeyFileNotTyped`],
/// [`CliError::KeyFileMalformed`], [`CliError::KeyCheckMismatch`], or
/// [`CliError::KeyKindMismatch`] naming what was found and what `command` needs.
pub(crate) fn read_key(
    path: &Path,
    command: &'static str,
    expected: &'static [KeyKind],
) -> Result<(KeyKind, Zeroizing<Vec<u8>>), CliError> {
    use std::io::Read;
    let io_err = |e: std::io::Error| CliError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    };
    let mut text = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_KEY_FILE_BYTES + 1).read_to_end(&mut text))
        .map_err(io_err)?;
    let (kind, key) = decode(&text).map_err(|e| match e {
        DecodeError::NotTyped => CliError::KeyFileNotTyped(path.to_path_buf()),
        DecodeError::Malformed(kind) => CliError::KeyFileMalformed {
            path: path.to_path_buf(),
            kind,
        },
        DecodeError::CheckMismatch(kind) => CliError::KeyCheckMismatch {
            path: path.to_path_buf(),
            kind,
        },
    })?;
    if !expected.contains(&kind) {
        return Err(CliError::KeyKindMismatch {
            path: path.to_path_buf(),
            command,
            found: kind,
            expected,
        });
    }
    Ok((kind, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Computed outside this module (Python builds the check preimage, `uacrypt kupyna-digest`
    /// hashes it), key bytes `00 01 02 ...`, 2026-09-24. Pins the format.
    const GOLDEN: [(KeyKind, &str); 9] = [
        (KeyKind::Symmetric, "UACRYPT-SECRET-SYMMETRIC:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:02348388"),
        (KeyKind::Sign163Secret, "UACRYPT-SECRET-SIGN163:000102030405060708090a0b0c0d0e0f1011121314:d78b26f3"),
        (KeyKind::Sign163Public, "uacrypt-sign163-public:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829:59ff77a2"),
        (KeyKind::Sign257Secret, "UACRYPT-SECRET-SIGN257:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:4aef7638"),
        (KeyKind::Sign257Public, "uacrypt-sign257-public:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041:1ef4eb6f"),
        (KeyKind::Box256Secret, "UACRYPT-SECRET-BOX256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:789b33a5"),
        (KeyKind::Box256Public, "uacrypt-box256-public:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:4614d28c"),
        (KeyKind::Box512Secret, "UACRYPT-SECRET-BOX512:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f:52b7ab4d"),
        (KeyKind::Box512Public, "uacrypt-box512-public:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f:89fd9e66"),
    ];

    fn counting_key(kind: KeyKind) -> Vec<u8> {
        (0..kind.key_len())
            .map(|i| u8::try_from(i).unwrap_or(u8::MAX))
            .collect()
    }

    fn golden(kind: KeyKind) -> &'static str {
        GOLDEN
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, l)| *l)
            .unwrap_or_default()
    }

    #[test]
    fn encode_matches_the_golden_lines() {
        for (kind, line) in GOLDEN {
            let encoded = encode(kind, &counting_key(kind));
            assert_eq!(
                encoded.as_slice(),
                format!("{line}\n").as_bytes(),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn decode_accepts_the_golden_lines_with_lf_crlf_or_no_newline() {
        for (kind, line) in GOLDEN {
            for text in [line.to_string(), format!("{line}\n"), format!("{line}\r\n")] {
                let (k, key) =
                    decode(text.as_bytes()).unwrap_or_else(|e| panic!("{kind:?}: {e:?}"));
                assert_eq!(k, kind);
                assert_eq!(key.as_slice(), counting_key(kind).as_slice());
            }
        }
    }

    #[test]
    fn every_kind_has_a_distinct_prefix_name_and_lengths() {
        for (i, a) in ALL_KINDS.iter().enumerate() {
            assert_eq!(KeyKind::parse_name(a.name()), Some(*a));
            assert_eq!(a.is_secret(), a.prefix().starts_with("UACRYPT-SECRET-"));
            for b in &ALL_KINDS[i + 1..] {
                assert_ne!(a.prefix(), b.prefix());
                assert_ne!(a.name(), b.name());
            }
        }
        let lens: Vec<usize> = ALL_KINDS.iter().map(|k| k.key_len()).collect();
        assert_eq!(lens, [32, 21, 42, 33, 66, 32, 32, 64, 64]);
    }

    #[test]
    fn sniff_kind_matches_only_prefix_colon_at_offset_zero() {
        for kind in ALL_KINDS {
            let prefix = kind.prefix().as_bytes();
            assert!(prefix.len() < SNIFF_LEN, "{kind:?}");
            let mut head = prefix.to_vec();
            head.push(b':');
            assert_eq!(sniff_kind(&head), Some(kind));
            head.extend_from_slice(b"not hex at all");
            assert_eq!(sniff_kind(&head), Some(kind));
            assert_eq!(sniff_kind(prefix), None, "{kind:?}: no colon");
            assert_eq!(sniff_kind(&prefix[..prefix.len() - 1]), None);
            let mut shifted = b" ".to_vec();
            shifted.extend_from_slice(&head);
            assert_eq!(sniff_kind(&shifted), None);
            let mut bom = b"\xef\xbb\xbf".to_vec();
            bom.extend_from_slice(&head);
            assert_eq!(sniff_kind(&bom), None);
            let swapped: Vec<u8> = head
                .iter()
                .map(|b| {
                    if b.is_ascii_uppercase() {
                        b.to_ascii_lowercase()
                    } else {
                        b.to_ascii_uppercase()
                    }
                })
                .collect();
            assert_eq!(sniff_kind(&swapped), None, "{kind:?}: case swapped");
        }
        assert_eq!(
            ALL_KINDS.iter().map(|k| k.prefix().len() + 1).max(),
            Some(SNIFF_LEN)
        );
        assert_eq!(sniff_kind(b""), None);
    }

    #[test]
    fn hex_digit_and_value_cover_every_nibble_and_byte() {
        for n in 0..16u8 {
            assert_eq!(hex_digit(n), b"0123456789abcdef"[usize::from(n)]);
        }
        for c in 0..=255u8 {
            let expected = match c {
                b'0'..=b'9' => (c - b'0', 1),
                b'a'..=b'f' => (c - b'a' + 10, 1),
                _ => (0, 0),
            };
            assert_eq!(hex_value(c), expected, "byte {c:#04x}");
        }
    }

    fn with(line: &str, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut bytes = line.as_bytes().to_vec();
        f(&mut bytes);
        bytes
    }

    #[test]
    fn decode_rejects_anything_but_the_exact_line() {
        let line = golden(KeyKind::Box256Public);
        let colon = line.rfind(':').unwrap_or_default();
        let malformed = KeyKind::Box256Public;
        let cases: Vec<(&str, Vec<u8>, DecodeError)> = vec![
            ("empty", Vec::new(), DecodeError::NotTyped),
            ("raw 32 bytes", vec![7u8; 32], DecodeError::NotTyped),
            (
                "bom",
                with(line, |b| b.splice(0..0, [0xef, 0xbb, 0xbf]).for_each(drop)),
                DecodeError::NotTyped,
            ),
            (
                "prefix case",
                line.replacen("uacrypt", "UACRYPT", 1).into_bytes(),
                DecodeError::NotTyped,
            ),
            (
                "leading space",
                format!(" {line}").into_bytes(),
                DecodeError::NotTyped,
            ),
            (
                "prefix only",
                b"uacrypt-box256-public:".to_vec(),
                DecodeError::Malformed(malformed),
            ),
            (
                "trailing space",
                format!("{line} ").into_bytes(),
                DecodeError::Malformed(malformed),
            ),
            (
                "two newlines",
                format!("{line}\n\n").into_bytes(),
                DecodeError::Malformed(malformed),
            ),
            (
                "lone cr",
                format!("{line}\r").into_bytes(),
                DecodeError::Malformed(malformed),
            ),
            (
                "second line",
                format!("{line}\n{line}\n").into_bytes(),
                DecodeError::Malformed(malformed),
            ),
            (
                "missing check",
                line.as_bytes()[..colon].to_vec(),
                DecodeError::Malformed(malformed),
            ),
            (
                "short key",
                line.replacen(":00", ":", 1).into_bytes(),
                DecodeError::Malformed(malformed),
            ),
            (
                "upper-case hex",
                line.replacen("0a0b", "0A0B", 1).into_bytes(),
                DecodeError::Malformed(malformed),
            ),
            (
                "non-hex digit",
                line.replacen("0a0b", "0g0b", 1).into_bytes(),
                DecodeError::Malformed(malformed),
            ),
            (
                "separator moved",
                with(line, |b| b.swap(colon, colon - 1)),
                DecodeError::Malformed(malformed),
            ),
            (
                "flipped key digit",
                line.replacen("0a0b", "0a0c", 1).into_bytes(),
                DecodeError::CheckMismatch(malformed),
            ),
            (
                "flipped check digit",
                with(line, |b| {
                    let last = b.len() - 1;
                    b[last] = if b[last] == b'0' { b'1' } else { b'0' };
                }),
                DecodeError::CheckMismatch(malformed),
            ),
        ];
        for (name, bytes, expected) in cases {
            assert_eq!(decode(&bytes).err(), Some(expected), "{name}");
        }
    }

    #[test]
    fn a_line_relabelled_to_another_kind_fails_its_check() {
        let line = golden(KeyKind::Box256Public).replacen(
            "uacrypt-box256-public",
            "UACRYPT-SECRET-SYMMETRIC",
            1,
        );
        assert_eq!(
            decode(line.as_bytes()).err(),
            Some(DecodeError::CheckMismatch(KeyKind::Symmetric))
        );
    }

    #[test]
    fn hint_names_each_making_command_once() {
        assert_eq!(
            wrong_kind_hint(&[KeyKind::Box256Public, KeyKind::Box512Public]),
            "make the right key with `uacrypt box-pubkey`"
        );
        assert_eq!(
            wrong_kind_hint(&[KeyKind::Sign163Secret, KeyKind::Sign257Secret]),
            "make the right key with `uacrypt sign-keygen` or `uacrypt sign-keygen257`"
        );
        assert_eq!(
            wrong_kind_hint(&[KeyKind::Sign163Public, KeyKind::Sign257Public]),
            "make the right key with `uacrypt sign-pubkey`"
        );
        assert_eq!(
            wrong_kind_hint(&[KeyKind::Symmetric]),
            "make the right key with `uacrypt keygen`"
        );
    }
}
