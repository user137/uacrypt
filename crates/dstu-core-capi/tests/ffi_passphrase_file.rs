//! T-269: the passphrase-file C ABI (D-240) and `dstu_pwhash_derive_key` - called from Rust as the
//! .NET/Go/C++ bindings call them: the shared vectors by status, a round trip through the codec
//! handles, empty passphrases, unknown strengths and null pointers. Argon2 is 256 MiB, t=3 per
//! run, so only the tests marked for it run it; every header refusal also runs under Miri.

use dstu_core_capi::pwhash::*;
use dstu_core_capi::secretstream::*;
use dstu_core_capi::DstuStatus;
use std::ptr;

const VECTORS: &str = include_str!("../../dstu-core/tests/vectors/pwhash/passphrase_file.json");
const DERIVE_VECTORS: &str = include_str!("../../dstu-core/tests/vectors/pwhash/derive_key.json");

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

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + 7) % 256).unwrap())
        .collect()
}

fn plaintext_len(line: &str) -> usize {
    line.split("\"plaintext_len\": ")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn cases(argon2: bool) -> Vec<&'static str> {
    VECTORS
        .lines()
        .filter(|l| l.contains("\"name\": "))
        .filter(|l| l.contains(&format!("\"argon2\": {argon2}")))
        .collect()
}

/// The reader contract over a codec decryptor handle; frees it.
unsafe fn open_records(dec: *mut DstuFileDecryptor, file: &[u8]) -> Result<Vec<u8>, DstuStatus> {
    let mut out = vec![0u8; DSTU_SECRETSTREAM_CHUNK_BYTES];
    let mut plaintext = Vec::new();
    let mut pos = 0;
    let result = loop {
        let want = unsafe { dstu_secretstream_file_decryptor_next_len(dec) };
        let mut n = 0usize;
        if file.len() - pos < want {
            let status = unsafe {
                dstu_secretstream_file_decryptor_finish(dec, out.as_mut_ptr(), out.len(), &mut n)
            };
            if status != DstuStatus::DSTU_OK {
                break Err(status);
            }
            plaintext.extend_from_slice(&out[..n]);
            break Ok(plaintext);
        }
        let status = unsafe {
            dstu_secretstream_file_decryptor_feed(
                dec,
                file[pos..].as_ptr(),
                want,
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        };
        if status != DstuStatus::DSTU_OK {
            break Err(status);
        }
        pos += want;
        plaintext.extend_from_slice(&out[..n]);
    };
    unsafe { dstu_secretstream_file_decryptor_free(dec) };
    result
}

fn open_file(passphrase: &[u8], file: &[u8]) -> Result<Vec<u8>, DstuStatus> {
    let mut dec = ptr::null_mut();
    let status = unsafe {
        dstu_passphrase_file_open_stream(
            file.as_ptr(),
            passphrase.as_ptr(),
            passphrase.len(),
            &mut dec,
        )
    };
    if status != DstuStatus::DSTU_OK {
        assert!(dec.is_null(), "*out is not written on failure");
        return Err(status);
    }
    unsafe { open_records(dec, &file[DSTU_PASSPHRASE_FILE_HEADER_BYTES..]) }
}

#[test]
fn constants_match_the_core() {
    use dstu_core::crypto_pwhash::passphrase_file as core;
    assert_eq!(DSTU_PASSPHRASE_FILE_HEADER_BYTES, core::HEADER_BYTES);
    assert_eq!(
        DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES,
        core::SEAL_STREAM_PREFIX_BYTES
    );
    assert_eq!(DSTU_PASSPHRASE_FILE_CONTAINER_TYPE, core::CONTAINER_TYPE);
    assert_eq!(DSTU_PWHASH_SALTBYTES, dstu_core::crypto_pwhash::SALT_BYTES);
    assert_eq!(DSTU_PWHASH_KEYBYTES, dstu_core::crypto_pwhash::KEY_BYTES);
}

/// Every header-level case is refused with its status by both entry points, before Argon2.
#[test]
fn shared_header_vectors_are_refused_by_status() {
    let refused = cases(false);
    assert_eq!(refused.len(), 6);
    for line in refused {
        let name = field(line, "name");
        let file = decode_hex(field(line, "sealed_hex"));
        let expected = match field(line, "expect") {
            // A reader with fewer than DSTU_PASSPHRASE_FILE_HEADER_BYTES bytes has a truncated
            // file before calling anything here.
            "truncated" => {
                assert!(file.len() < DSTU_PASSPHRASE_FILE_HEADER_BYTES, "{name}");
                continue;
            }
            "not_passphrase_file" | "unsupported_format" => {
                DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION
            }
            "unsupported_params" => DstuStatus::DSTU_ERR_UNSUPPORTED_PARAMS,
            other => panic!("{name}: unexpected {other}"),
        };
        assert_eq!(
            unsafe { dstu_passphrase_file_check_header(file.as_ptr()) },
            expected,
            "{name}"
        );
        let passphrase = decode_hex(field(line, "passphrase_hex"));
        assert_eq!(open_file(&passphrase, &file), Err(expected), "{name}");
    }
}

#[test]
#[cfg_attr(miri, ignore = "four Argon2id runs at 256 MiB")]
fn shared_vectors_written_by_uacrypt_0_6_0_open_by_status() {
    let argon2 = cases(true);
    assert_eq!(argon2.len(), 4);
    for line in argon2 {
        let name = field(line, "name");
        let file = decode_hex(field(line, "sealed_hex"));
        assert_eq!(
            unsafe { dstu_passphrase_file_check_header(file.as_ptr()) },
            DstuStatus::DSTU_OK,
            "{name}"
        );
        let result = open_file(&decode_hex(field(line, "passphrase_hex")), &file);
        match field(line, "expect") {
            "ok" => assert_eq!(result, Ok(pattern(plaintext_len(line))), "{name}"),
            "invalid_ciphertext" => {
                assert_eq!(result, Err(DstuStatus::DSTU_ERR_TAG_MISMATCH), "{name}");
            }
            other => panic!("{name}: unexpected {other}"),
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "two Argon2id runs at 256 MiB")]
fn seal_stream_round_trips_through_the_codec_handles() {
    let message = pattern(DSTU_SECRETSTREAM_CHUNK_BYTES + 3);
    let mut prefix = vec![0u8; DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES];
    let mut enc = ptr::null_mut();
    assert_eq!(
        unsafe {
            dstu_passphrase_file_seal_stream(b"pw".as_ptr(), 2, prefix.as_mut_ptr(), &mut enc)
        },
        DstuStatus::DSTU_OK
    );
    let mut file = prefix;
    let mut record = vec![0u8; DSTU_SECRETSTREAM_MAX_RECORD_BYTES];
    let (chunk, rest) = message.split_at(DSTU_SECRETSTREAM_CHUNK_BYTES);
    assert_eq!(
        unsafe {
            dstu_secretstream_file_encryptor_seal_chunk(
                enc,
                chunk.as_ptr(),
                chunk.len(),
                record.as_mut_ptr(),
                record.len(),
            )
        },
        DstuStatus::DSTU_OK
    );
    file.extend_from_slice(&record);
    let mut n = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretstream_file_encryptor_seal_final(
                enc,
                rest.as_ptr(),
                rest.len(),
                record.as_mut_ptr(),
                record.len(),
                &mut n,
            )
        },
        DstuStatus::DSTU_OK
    );
    file.extend_from_slice(&record[..n]);
    unsafe { dstu_secretstream_file_encryptor_free(enc) };
    assert_eq!(open_file(b"pw", &file), Ok(message));
}

#[test]
fn an_empty_passphrase_is_refused_on_both_sides() {
    let mut prefix = vec![0u8; DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES];
    let mut enc = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_passphrase_file_seal_stream(ptr::null(), 0, prefix.as_mut_ptr(), &mut enc) },
        DstuStatus::DSTU_ERR_INVALID_LENGTH
    );
    assert!(enc.is_null());
    let file = decode_hex(field(cases(true)[0], "sealed_hex"));
    assert_eq!(
        open_file(b"", &file),
        Err(DstuStatus::DSTU_ERR_INVALID_LENGTH)
    );
}

#[test]
fn null_pointers_are_refused() {
    let file = decode_hex(field(cases(true)[0], "sealed_hex"));
    let mut prefix = vec![0u8; DSTU_PASSPHRASE_FILE_SEAL_STREAM_PREFIX_BYTES];
    let mut enc = ptr::null_mut();
    let mut dec = ptr::null_mut();
    unsafe {
        assert_eq!(
            dstu_passphrase_file_check_header(ptr::null()),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
        assert_eq!(
            dstu_passphrase_file_seal_stream(ptr::null(), 2, prefix.as_mut_ptr(), &mut enc),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
        assert_eq!(
            dstu_passphrase_file_seal_stream(b"pw".as_ptr(), 2, ptr::null_mut(), &mut enc),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
        assert_eq!(
            dstu_passphrase_file_seal_stream(
                b"pw".as_ptr(),
                2,
                prefix.as_mut_ptr(),
                ptr::null_mut()
            ),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
        assert_eq!(
            dstu_passphrase_file_open_stream(ptr::null(), b"pw".as_ptr(), 2, &mut dec),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
        assert_eq!(
            dstu_passphrase_file_open_stream(file.as_ptr(), b"pw".as_ptr(), 2, ptr::null_mut()),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
    }
    assert!(enc.is_null() && dec.is_null());
}

/// `derive_key` equals libsodium `crypto_pwhash` (the shared vectors' oracle) through the C ABI.
#[test]
#[cfg_attr(miri, ignore = "three Argon2id runs at 256 MiB")]
fn derive_key_matches_the_libsodium_vectors() {
    let mut seen = 0;
    // derive_key.json is pretty-printed: one block per case, starting at its "name".
    for line in DERIVE_VECTORS.split("\"name\": ").skip(1) {
        let password = decode_hex(field(line, "password_hex"));
        let salt = decode_hex(field(line, "salt_hex"));
        let mut key = [0u8; DSTU_PWHASH_KEYBYTES];
        assert_eq!(
            unsafe {
                dstu_pwhash_derive_key(
                    password.as_ptr(),
                    password.len(),
                    salt.as_ptr(),
                    DstuPwhashStrength::DSTU_PWHASH_MODERATE as u32,
                    key.as_mut_ptr(),
                )
            },
            DstuStatus::DSTU_OK
        );
        assert_eq!(key.to_vec(), decode_hex(field(line, "key_hex")));
        seen += 1;
    }
    assert_eq!(seen, 3);
}

#[test]
fn derive_key_refuses_bad_arguments_before_argon2() {
    let salt = [0u8; DSTU_PWHASH_SALTBYTES];
    let mut key = [0u8; DSTU_PWHASH_KEYBYTES];
    unsafe {
        assert_eq!(
            dstu_pwhash_derive_key(b"pw".as_ptr(), 2, salt.as_ptr(), 3, key.as_mut_ptr()),
            DstuStatus::DSTU_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            dstu_pwhash_derive_key(b"pw".as_ptr(), 2, ptr::null(), 0, key.as_mut_ptr()),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
        assert_eq!(
            dstu_pwhash_derive_key(b"pw".as_ptr(), 2, salt.as_ptr(), 0, ptr::null_mut()),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
        assert_eq!(
            dstu_pwhash_derive_key(ptr::null(), 2, salt.as_ptr(), 0, key.as_mut_ptr()),
            DstuStatus::DSTU_ERR_NULL_POINTER
        );
        // The key output overlapping the salt is refused (each binding passes separate buffers).
        let mut buf = [0u8; DSTU_PWHASH_KEYBYTES];
        assert_eq!(
            dstu_pwhash_derive_key(b"pw".as_ptr(), 2, buf.as_ptr(), 0, buf.as_mut_ptr()),
            DstuStatus::DSTU_ERR_INVALID_ARGUMENT
        );
    }
    assert_eq!(
        key, [0u8; DSTU_PWHASH_KEYBYTES],
        "nothing written on refusal"
    );
}
