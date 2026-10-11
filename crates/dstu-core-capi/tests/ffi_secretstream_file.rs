//! T-284: the stream-file codec's C ABI (`dstu_secretstream_file_*`), called directly from Rust
//! as the .NET/Go/C++ bindings call it from their languages - the shared vectors by status, a
//! round trip, null pointers, undersized buffers, and the failed-state contract.

use dstu_core_capi::secretstream::*;
use dstu_core_capi::DstuStatus;
use std::ffi::CStr;
use std::ptr;

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

fn key_from(bytes: &[u8]) -> *mut DstuSecretstreamKey {
    let key = unsafe { dstu_secretstream_key_from_bytes(bytes.as_ptr()) };
    assert!(!key.is_null());
    key
}

fn last_error(dec: *const DstuFileDecryptor) -> String {
    let msg = unsafe { dstu_secretstream_file_decryptor_last_error(dec) };
    assert!(!msg.is_null());
    unsafe { CStr::from_ptr(msg) }.to_str().unwrap().to_owned()
}

/// The reader contract through the C ABI. Returns the plaintext, or the failing status and the
/// decryptor's error message.
fn decrypt_all(
    key: *const DstuSecretstreamKey,
    file: &[u8],
) -> Result<Vec<u8>, (DstuStatus, String)> {
    let dec = unsafe { dstu_secretstream_file_decryptor_new(key) };
    assert!(!dec.is_null());
    let mut out = vec![0u8; DSTU_SECRETSTREAM_CHUNK_BYTES];
    let mut plaintext = Vec::new();
    let mut pos = 0;
    let result = loop {
        let want = unsafe { dstu_secretstream_file_decryptor_next_len(dec) };
        let mut n = 0usize;
        let at_eof = file.len() - pos < want;
        let status = if at_eof {
            unsafe {
                dstu_secretstream_file_decryptor_finish(dec, out.as_mut_ptr(), out.len(), &mut n)
            }
        } else {
            let s = unsafe {
                dstu_secretstream_file_decryptor_feed(
                    dec,
                    file[pos..].as_ptr(),
                    want,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut n,
                )
            };
            pos += want;
            s
        };
        if status != DstuStatus::DSTU_OK {
            break Err((status, last_error(dec)));
        }
        plaintext.extend_from_slice(&out[..n]);
        if at_eof {
            break Ok(plaintext);
        }
    };
    unsafe { dstu_secretstream_file_decryptor_free(dec) };
    result
}

fn encrypt_all(key: *const DstuSecretstreamKey, plaintext: &[u8]) -> Vec<u8> {
    let mut enc = ptr::null_mut();
    let mut prefix = [0u8; DSTU_SECRETSTREAM_FILE_PREFIX_BYTES];
    assert_eq!(
        unsafe { dstu_secretstream_file_encryptor_new(key, prefix.as_mut_ptr(), &mut enc) },
        DstuStatus::DSTU_OK
    );
    let mut file = prefix.to_vec();
    let mut record = vec![0u8; DSTU_SECRETSTREAM_MAX_RECORD_BYTES];
    let mut rest = plaintext;
    while rest.len() > DSTU_SECRETSTREAM_CHUNK_BYTES {
        assert_eq!(
            unsafe {
                dstu_secretstream_file_encryptor_seal_chunk(
                    enc,
                    rest.as_ptr(),
                    DSTU_SECRETSTREAM_CHUNK_BYTES,
                    record.as_mut_ptr(),
                    record.len(),
                )
            },
            DstuStatus::DSTU_OK
        );
        file.extend_from_slice(&record);
        rest = &rest[DSTU_SECRETSTREAM_CHUNK_BYTES..];
    }
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
    file
}

#[test]
fn constants_match_the_core() {
    use dstu_core::crypto_secretstream as core;
    assert_eq!(DSTU_SECRETSTREAM_CHUNK_BYTES, core::CHUNK_BYTES);
    assert_eq!(DSTU_SECRETSTREAM_FILE_PREFIX_BYTES, core::FILE_PREFIX_BYTES);
    assert_eq!(
        DSTU_SECRETSTREAM_RECORD_OVERHEAD_BYTES,
        core::RECORD_OVERHEAD_BYTES
    );
    assert_eq!(DSTU_SECRETSTREAM_MAX_RECORD_BYTES, core::MAX_RECORD_BYTES);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "bulk Kalyna-GCM over multi-KiB inputs is hours under Miri; the codec has no unsafe and the small-input tests below still run under it (T-296)"
)]
fn shared_vectors_give_their_status_and_message() {
    let key = key_from(&decode_hex(field(VECTORS, "key_hex")));
    let mut count = 0;
    for line in VECTORS
        .lines()
        .filter(|l| l.trim_start().starts_with("{\"name\""))
    {
        count += 1;
        let name = field(line, "name");
        let result = decrypt_all(key, &decode_hex(field(line, "file_hex")));
        let (status, phrase) = match field(line, "expect") {
            "ok" => {
                assert_eq!(
                    result.unwrap(),
                    decode_hex(field(line, "plaintext_hex")),
                    "{name}"
                );
                continue;
            }
            "unsupported_version" => (
                DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION,
                "unsupported stream format version",
            ),
            "bad_chunk_length" => (DstuStatus::DSTU_ERR_BAD_CHUNK_LENGTH, "non-final chunk"),
            "truncated" => (DstuStatus::DSTU_ERR_TRUNCATED, "truncated"),
            "auth" => (DstuStatus::DSTU_ERR_TAG_MISMATCH, "authentication failed"),
            "trailing_data" => (DstuStatus::DSTU_ERR_TRAILING_DATA, "trailing data"),
            "oversized_chunk" => (DstuStatus::DSTU_ERR_CHUNK_TOO_LARGE, "chunk too large"),
            "unknown_tag" => (DstuStatus::DSTU_ERR_UNKNOWN_TAG, "unrecognized chunk tag"),
            other => panic!("unknown expect value {other}"),
        };
        let (got_status, message) = result.expect_err(name);
        assert_eq!(got_status, status, "{name}");
        assert!(message.contains(phrase), "{name}: {message}");
    }
    assert_eq!(count, 15);
    unsafe { dstu_secretstream_key_free(key) };
}

#[test]
#[cfg_attr(
    miri,
    ignore = "bulk Kalyna-GCM over multi-KiB inputs is hours under Miri; the codec has no unsafe and the small-input tests below still run under it (T-296)"
)]
fn round_trips_across_chunk_boundaries() {
    let mut key = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_secretstream_key_generate(&mut key) },
        DstuStatus::DSTU_OK
    );
    for len in [
        0,
        5,
        DSTU_SECRETSTREAM_CHUNK_BYTES,
        2 * DSTU_SECRETSTREAM_CHUNK_BYTES + 3,
    ] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let file = encrypt_all(key, &plaintext);
        assert_eq!(decrypt_all(key, &file).unwrap(), plaintext, "len {len}");
    }
    unsafe { dstu_secretstream_key_free(key) };
}

#[test]
fn null_pointers_are_rejected() {
    let key = key_from(&[1u8; 32]);
    let mut out = [0u8; DSTU_SECRETSTREAM_MAX_RECORD_BYTES];
    let mut n = 0usize;
    let mut enc = ptr::null_mut();
    let mut prefix = [0u8; DSTU_SECRETSTREAM_FILE_PREFIX_BYTES];

    assert!(unsafe { dstu_secretstream_file_decryptor_new(ptr::null()) }.is_null());
    assert_eq!(
        unsafe { dstu_secretstream_file_decryptor_next_len(ptr::null()) },
        0
    );
    assert!(unsafe { dstu_secretstream_file_decryptor_last_error(ptr::null()) }.is_null());
    assert_eq!(
        unsafe {
            dstu_secretstream_file_decryptor_feed(
                ptr::null_mut(),
                out.as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        },
        DstuStatus::DSTU_ERR_NULL_POINTER
    );
    assert_eq!(
        unsafe { dstu_secretstream_file_encryptor_new(ptr::null(), prefix.as_mut_ptr(), &mut enc) },
        DstuStatus::DSTU_ERR_NULL_POINTER
    );
    assert_eq!(
        unsafe { dstu_secretstream_file_encryptor_new(key, ptr::null_mut(), &mut enc) },
        DstuStatus::DSTU_ERR_NULL_POINTER
    );

    let dec = unsafe { dstu_secretstream_file_decryptor_new(key) };
    assert_eq!(
        unsafe {
            dstu_secretstream_file_decryptor_feed(
                dec,
                ptr::null(),
                1,
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        },
        DstuStatus::DSTU_ERR_NULL_POINTER
    );
    assert_eq!(
        unsafe {
            dstu_secretstream_file_decryptor_feed(
                dec,
                out.as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                ptr::null_mut(),
            )
        },
        DstuStatus::DSTU_ERR_NULL_POINTER
    );
    unsafe { dstu_secretstream_file_decryptor_free(dec) };
    unsafe { dstu_secretstream_file_decryptor_free(ptr::null_mut()) };
    unsafe { dstu_secretstream_file_encryptor_free(ptr::null_mut()) };
    unsafe { dstu_secretstream_key_free(key) };
}

#[test]
fn undersized_buffers_and_wrong_lengths_are_rejected_before_any_work() {
    let key = key_from(&[2u8; 32]);
    let mut enc = ptr::null_mut();
    let mut prefix = [0u8; DSTU_SECRETSTREAM_FILE_PREFIX_BYTES];
    assert_eq!(
        unsafe { dstu_secretstream_file_encryptor_new(key, prefix.as_mut_ptr(), &mut enc) },
        DstuStatus::DSTU_OK
    );
    let chunk = vec![0u8; DSTU_SECRETSTREAM_CHUNK_BYTES];
    let mut record = vec![0u8; DSTU_SECRETSTREAM_MAX_RECORD_BYTES];
    let mut n = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretstream_file_encryptor_seal_chunk(
                enc,
                chunk.as_ptr(),
                chunk.len() - 1,
                record.as_mut_ptr(),
                record.len(),
            )
        },
        DstuStatus::DSTU_ERR_INVALID_LENGTH
    );
    assert_eq!(
        unsafe {
            dstu_secretstream_file_encryptor_seal_chunk(
                enc,
                chunk.as_ptr(),
                chunk.len(),
                record.as_mut_ptr(),
                record.len() - 1,
            )
        },
        DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(
        unsafe {
            dstu_secretstream_file_encryptor_seal_final(
                enc,
                chunk.as_ptr(),
                4,
                record.as_mut_ptr(),
                4 + DSTU_SECRETSTREAM_RECORD_OVERHEAD_BYTES - 1,
                &mut n,
            )
        },
        DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(
        unsafe {
            dstu_secretstream_file_encryptor_seal_final(
                enc,
                vec![0u8; DSTU_SECRETSTREAM_CHUNK_BYTES + 1].as_ptr(),
                DSTU_SECRETSTREAM_CHUNK_BYTES + 1,
                record.as_mut_ptr(),
                record.len(),
                &mut n,
            )
        },
        DstuStatus::DSTU_ERR_INVALID_LENGTH
    );
    unsafe { dstu_secretstream_file_encryptor_free(enc) };

    let dec = unsafe { dstu_secretstream_file_decryptor_new(key) };
    let mut small = vec![0u8; DSTU_SECRETSTREAM_CHUNK_BYTES - 1];
    assert_eq!(
        unsafe {
            dstu_secretstream_file_decryptor_feed(
                dec,
                prefix.as_ptr(),
                1,
                small.as_mut_ptr(),
                small.len(),
                &mut n,
            )
        },
        DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL
    );
    let mut out = vec![0u8; DSTU_SECRETSTREAM_CHUNK_BYTES];
    assert_eq!(
        unsafe {
            dstu_secretstream_file_decryptor_feed(
                dec,
                prefix.as_ptr(),
                2,
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        },
        DstuStatus::DSTU_ERR_INVALID_LENGTH
    );
    assert!(
        unsafe { dstu_secretstream_file_decryptor_last_error(dec) }.is_null(),
        "a caller error does not fail the decryptor"
    );
    unsafe { dstu_secretstream_file_decryptor_free(dec) };
    unsafe { dstu_secretstream_key_free(key) };
}

#[test]
fn a_failed_decryptor_stays_failed() {
    let key = key_from(&[3u8; 32]);
    let dec = unsafe { dstu_secretstream_file_decryptor_new(key) };
    let mut out = vec![0u8; DSTU_SECRETSTREAM_CHUNK_BYTES];
    let mut n = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretstream_file_decryptor_feed(
                dec,
                [9u8].as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        },
        DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION
    );
    assert!(last_error(dec).contains("unsupported stream format version 9"));
    assert_eq!(unsafe { dstu_secretstream_file_decryptor_next_len(dec) }, 0);
    assert_eq!(
        unsafe {
            dstu_secretstream_file_decryptor_finish(dec, out.as_mut_ptr(), out.len(), &mut n)
        },
        DstuStatus::DSTU_ERR_FINALIZED
    );
    unsafe { dstu_secretstream_file_decryptor_free(dec) };
    unsafe { dstu_secretstream_key_free(key) };
}
