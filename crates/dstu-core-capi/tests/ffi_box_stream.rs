//! T-265: the v3 `crypto_box`/`crypto_box512` C ABI (D-239) - `_sealed_len`, the one-shot
//! `_seal`/`_open` over the new format, and `_seal_stream`/`_open_stream`, which hand out the
//! stream-file codec's own handles. Called from Rust as the .NET/Go/C++ bindings call it: the
//! shared v3 vectors by status, the streaming round trip, the legacy format refused, null
//! pointers and undersized buffers.

use dstu_core_capi::box512::*;
use dstu_core_capi::crypto_box::*;
use dstu_core_capi::secretstream::*;
use dstu_core_capi::DstuStatus;
use std::ptr;

const V3_VECTORS: &str = include_str!("../../dstu-core/tests/vectors/box/v3.json");
const LEGACY_VECTORS: &str = include_str!("../../dstu-core/tests/vectors/box/legacy_v2.json");

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

/// The writer contract over a codec encryptor handle.
unsafe fn seal_records(enc: *mut DstuFileEncryptor, message: &[u8], out: &mut Vec<u8>) {
    let mut record = vec![0u8; DSTU_SECRETSTREAM_MAX_RECORD_BYTES];
    let mut rest = message;
    while rest.len() > DSTU_SECRETSTREAM_CHUNK_BYTES {
        let (chunk, tail) = rest.split_at(DSTU_SECRETSTREAM_CHUNK_BYTES);
        let status = unsafe {
            dstu_secretstream_file_encryptor_seal_chunk(
                enc,
                chunk.as_ptr(),
                chunk.len(),
                record.as_mut_ptr(),
                record.len(),
            )
        };
        assert_eq!(status, DstuStatus::DSTU_OK);
        out.extend_from_slice(&record);
        rest = tail;
    }
    let mut n = 0usize;
    let status = unsafe {
        dstu_secretstream_file_encryptor_seal_final(
            enc,
            rest.as_ptr(),
            rest.len(),
            record.as_mut_ptr(),
            record.len(),
            &mut n,
        )
    };
    assert_eq!(status, DstuStatus::DSTU_OK);
    out.extend_from_slice(&record[..n]);
}

/// The reader contract over a codec decryptor handle.
unsafe fn open_records(dec: *mut DstuFileDecryptor, file: &[u8]) -> Result<Vec<u8>, DstuStatus> {
    let mut out = vec![0u8; DSTU_SECRETSTREAM_CHUNK_BYTES];
    let mut plaintext = Vec::new();
    let mut pos = 0;
    loop {
        let want = unsafe { dstu_secretstream_file_decryptor_next_len(dec) };
        let mut n = 0usize;
        if file.len() - pos < want {
            let status = unsafe {
                dstu_secretstream_file_decryptor_finish(dec, out.as_mut_ptr(), out.len(), &mut n)
            };
            if status != DstuStatus::DSTU_OK {
                return Err(status);
            }
            plaintext.extend_from_slice(&out[..n]);
            return Ok(plaintext);
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
            return Err(status);
        }
        pos += want;
        plaintext.extend_from_slice(&out[..n]);
    }
}

macro_rules! box_stream_tests {
    (
        $module:ident,
        core = $core:ident,
        curve = $curve:literal,
        miri = $miri:literal,
        Secret = $Secret:ty,
        secret_generate = $secret_generate:ident,
        secret_from_bytes = $secret_from_bytes:ident,
        secret_public_key = $secret_public_key:ident,
        secret_free = $secret_free:ident,
        public_free = $public_free:ident,
        seal = $seal:ident,
        open = $open:ident,
        sealed_len = $sealed_len:ident,
        seal_stream = $seal_stream:ident,
        open_stream = $open_stream:ident,
        SEAL_PREFIX = $SEAL_PREFIX:ident,
        OPEN_PREFIX = $OPEN_PREFIX:ident,
        MIN_OVERHEAD = $MIN_OVERHEAD:ident,
        secret_field = $secret_field:literal,
    ) => {
        mod $module {
            use super::*;

            const CURVE: &str = concat!("\"curve\": ", $curve);

            fn secret_from_vectors(text: &str) -> *mut $Secret {
                let bytes = decode_hex(field(text, $secret_field));
                let mut secret = ptr::null_mut();
                assert_eq!(
                    unsafe { $secret_from_bytes(bytes.as_ptr(), &mut secret) },
                    DstuStatus::DSTU_OK
                );
                secret
            }

            fn seal(public: *const <$Secret as KeyPair>::Public, message: &[u8]) -> Vec<u8> {
                let mut cap = 0usize;
                assert_eq!(
                    unsafe { $sealed_len(message.len(), &mut cap) },
                    DstuStatus::DSTU_OK
                );
                let mut sealed = vec![0u8; cap];
                let mut len = 0usize;
                assert_eq!(
                    unsafe {
                        $seal(
                            public,
                            message.as_ptr(),
                            message.len(),
                            sealed.as_mut_ptr(),
                            sealed.len(),
                            &mut len,
                        )
                    },
                    DstuStatus::DSTU_OK
                );
                assert_eq!(len, cap, "_sealed_len is exact");
                sealed
            }

            fn open(secret: *const $Secret, sealed: &[u8]) -> Result<Vec<u8>, DstuStatus> {
                let mut out = vec![0u8; sealed.len().saturating_sub($MIN_OVERHEAD)];
                let mut len = 0usize;
                match unsafe {
                    $open(
                        secret,
                        sealed.as_ptr(),
                        sealed.len(),
                        out.as_mut_ptr(),
                        out.len(),
                        &mut len,
                    )
                } {
                    DstuStatus::DSTU_OK => {
                        out.truncate(len);
                        Ok(out)
                    }
                    status => Err(status),
                }
            }

            #[test]
            fn sealed_len_and_prefix_constants() {
                let mut len = 0usize;
                assert_eq!(unsafe { $sealed_len(0, &mut len) }, DstuStatus::DSTU_OK);
                assert_eq!(len, $MIN_OVERHEAD);
                // Hand-maintained for cbindgen; pinned to the core's own values here.
                assert_eq!($SEAL_PREFIX, dstu_core::$core::SEAL_STREAM_PREFIX_BYTES);
                assert_eq!($OPEN_PREFIX, dstu_core::$core::OPEN_STREAM_PREFIX_BYTES);
                assert_eq!(
                    $SEAL_PREFIX,
                    $OPEN_PREFIX + DSTU_SECRETSTREAM_FILE_PREFIX_BYTES
                );
                assert_eq!(
                    $MIN_OVERHEAD,
                    $SEAL_PREFIX + DSTU_SECRETSTREAM_RECORD_OVERHEAD_BYTES
                );
                assert_eq!(
                    unsafe { $sealed_len(usize::MAX, &mut len) },
                    DstuStatus::DSTU_ERR_INVALID_LENGTH
                );
                assert_eq!(
                    unsafe { $sealed_len(0, ptr::null_mut()) },
                    DstuStatus::DSTU_ERR_NULL_POINTER
                );
            }

            /// The shared v3 vectors (D-239) by status, as every C-ABI binding runs them.
            #[test]
            #[cfg_attr(miri, ignore = $miri)]
            fn shared_v3_vectors_by_status() {
                let secret = secret_from_vectors(V3_VECTORS);
                let mut seen = 0;
                for line in V3_VECTORS.lines().filter(|l| l.contains(CURVE)) {
                    let name = field(line, "name");
                    let result = open(secret, &decode_hex(field(line, "sealed_hex")));
                    let expected = match field(line, "expect") {
                        "ok" => {
                            assert_eq!(result, Ok(pattern(plaintext_len(line))), "{name}");
                            seen += 1;
                            continue;
                        }
                        "invalid_ciphertext" => DstuStatus::DSTU_ERR_TAG_MISMATCH,
                        "truncated" => DstuStatus::DSTU_ERR_TRUNCATED,
                        "unsupported_version" => DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION,
                        other => panic!("unknown expect {other}"),
                    };
                    assert_eq!(result, Err(expected), "{name}");
                    seen += 1;
                }
                assert_eq!(seen, 8);
                unsafe { $secret_free(secret) };
            }

            /// Owner decision 2026-10-15 (D-239): the C ABI reads v3 only.
            #[test]
            #[cfg_attr(miri, ignore = $miri)]
            fn a_legacy_v2_blob_is_unsupported_version() {
                let secret = secret_from_vectors(LEGACY_VECTORS);
                for line in LEGACY_VECTORS.lines().filter(|l| l.contains(CURVE)) {
                    let sealed = decode_hex(field(line, "sealed_hex"));
                    assert_eq!(
                        open(secret, &sealed),
                        Err(DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION)
                    );
                }
                unsafe { $secret_free(secret) };
            }

            /// `_seal_stream`'s records open with `_open`, and `_seal`'s with `_open_stream`.
            #[test]
            #[cfg_attr(miri, ignore = $miri)]
            fn streaming_and_one_shot_interoperate() {
                let mut secret = ptr::null_mut();
                assert_eq!(
                    unsafe { $secret_generate(&mut secret) },
                    DstuStatus::DSTU_OK
                );
                let public = unsafe { $secret_public_key(secret) };
                let message = pattern(2 * DSTU_SECRETSTREAM_CHUNK_BYTES + 5);

                let mut prefix = vec![0u8; $SEAL_PREFIX];
                let mut enc = ptr::null_mut();
                assert_eq!(
                    unsafe { $seal_stream(public, prefix.as_mut_ptr(), &mut enc) },
                    DstuStatus::DSTU_OK
                );
                let mut streamed = prefix;
                unsafe { seal_records(enc, &message, &mut streamed) };
                unsafe { dstu_secretstream_file_encryptor_free(enc) };
                assert_eq!(open(secret, &streamed), Ok(message.clone()));

                let one_shot = seal(public, &message);
                let mut dec = ptr::null_mut();
                assert_eq!(
                    unsafe { $open_stream(secret, one_shot.as_ptr(), &mut dec) },
                    DstuStatus::DSTU_OK
                );
                let opened = unsafe { open_records(dec, &one_shot[$OPEN_PREFIX..]) };
                unsafe { dstu_secretstream_file_decryptor_free(dec) };
                assert_eq!(opened, Ok(message.clone()));

                // `_open`'s output bound: one byte short of `sealed_len - MIN_OVERHEAD` is refused.
                let mut short = vec![0u8; one_shot.len() - $MIN_OVERHEAD - 1];
                let mut len = 0usize;
                assert_eq!(
                    unsafe {
                        $open(
                            secret,
                            one_shot.as_ptr(),
                            one_shot.len(),
                            short.as_mut_ptr(),
                            short.len(),
                            &mut len,
                        )
                    },
                    DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL
                );
                // `_seal` with one byte less than `_sealed_len` is refused before any work.
                let mut small = vec![0u8; one_shot.len() - 1];
                assert_eq!(
                    unsafe {
                        $seal(
                            public,
                            message.as_ptr(),
                            message.len(),
                            small.as_mut_ptr(),
                            small.len(),
                            &mut len,
                        )
                    },
                    DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL
                );
                unsafe { $public_free(public) };
                unsafe { $secret_free(secret) };
            }

            #[test]
            #[cfg_attr(miri, ignore = $miri)]
            fn open_stream_rejects_a_wrong_version_a_forged_kem_and_null_pointers() {
                let mut secret = ptr::null_mut();
                assert_eq!(
                    unsafe { $secret_generate(&mut secret) },
                    DstuStatus::DSTU_OK
                );
                let public = unsafe { $secret_public_key(secret) };
                let sealed = seal(public, b"x");
                let prefix = &sealed[..$OPEN_PREFIX];

                let mut dec = ptr::null_mut();
                let mut wrong_version = prefix.to_vec();
                wrong_version[0] = 2;
                assert_eq!(
                    unsafe { $open_stream(secret, wrong_version.as_ptr(), &mut dec) },
                    DstuStatus::DSTU_ERR_UNSUPPORTED_VERSION
                );
                let mut forged = prefix.to_vec();
                forged[1] ^= 1;
                assert_eq!(
                    unsafe { $open_stream(secret, forged.as_ptr(), &mut dec) },
                    DstuStatus::DSTU_ERR_TAG_MISMATCH
                );
                assert!(dec.is_null(), "no handle on failure");

                assert_eq!(
                    unsafe { $open_stream(ptr::null(), prefix.as_ptr(), &mut dec) },
                    DstuStatus::DSTU_ERR_NULL_POINTER
                );
                assert_eq!(
                    unsafe { $open_stream(secret, ptr::null(), &mut dec) },
                    DstuStatus::DSTU_ERR_NULL_POINTER
                );
                assert_eq!(
                    unsafe { $open_stream(secret, prefix.as_ptr(), ptr::null_mut()) },
                    DstuStatus::DSTU_ERR_NULL_POINTER
                );
                let mut enc = ptr::null_mut();
                let mut out = vec![0u8; $SEAL_PREFIX];
                assert_eq!(
                    unsafe { $seal_stream(ptr::null(), out.as_mut_ptr(), &mut enc) },
                    DstuStatus::DSTU_ERR_NULL_POINTER
                );
                assert_eq!(
                    unsafe { $seal_stream(public, ptr::null_mut(), &mut enc) },
                    DstuStatus::DSTU_ERR_NULL_POINTER
                );
                assert_eq!(
                    unsafe { $seal_stream(public, out.as_mut_ptr(), ptr::null_mut()) },
                    DstuStatus::DSTU_ERR_NULL_POINTER
                );
                assert!(enc.is_null());
                unsafe { $public_free(public) };
                unsafe { $secret_free(secret) };
            }
        }
    };
}

/// Ties each secret-key handle to its public-key handle type for the macro's helpers.
trait KeyPair {
    type Public;
}
impl KeyPair for DstuBoxSecretKey {
    type Public = DstuBoxPublicKey;
}
impl KeyPair for DstuBox512SecretKey {
    type Public = DstuBox512PublicKey;
}

box_stream_tests!(
    box256,
    core = crypto_box,
    curve = "256",
    miri = "full seal/open scalar-multiply cost, see docs/TASKS.md T-206",
    Secret = DstuBoxSecretKey,
    secret_generate = dstu_box_secretkey_generate,
    secret_from_bytes = dstu_box_secretkey_from_bytes,
    secret_public_key = dstu_box_secretkey_public_key,
    secret_free = dstu_box_secretkey_free,
    public_free = dstu_box_publickey_free,
    seal = dstu_box_seal,
    open = dstu_box_open,
    sealed_len = dstu_box_sealed_len,
    seal_stream = dstu_box_seal_stream,
    open_stream = dstu_box_open_stream,
    SEAL_PREFIX = DSTU_BOX_SEAL_STREAM_PREFIX_BYTES,
    OPEN_PREFIX = DSTU_BOX_OPEN_STREAM_PREFIX_BYTES,
    MIN_OVERHEAD = DSTU_BOX_OPEN_MIN_OVERHEAD,
    secret_field = "box256_secret_key_hex",
);

box_stream_tests!(
    box512,
    core = crypto_box512,
    curve = "512",
    miri = "l(p)=512 scalar_multiply is too slow to interpret under Miri",
    Secret = DstuBox512SecretKey,
    secret_generate = dstu_box512_secretkey_generate,
    secret_from_bytes = dstu_box512_secretkey_from_bytes,
    secret_public_key = dstu_box512_secretkey_public_key,
    secret_free = dstu_box512_secretkey_free,
    public_free = dstu_box512_publickey_free,
    seal = dstu_box512_seal,
    open = dstu_box512_open,
    sealed_len = dstu_box512_sealed_len,
    seal_stream = dstu_box512_seal_stream,
    open_stream = dstu_box512_open_stream,
    SEAL_PREFIX = DSTU_BOX512_SEAL_STREAM_PREFIX_BYTES,
    OPEN_PREFIX = DSTU_BOX512_OPEN_STREAM_PREFIX_BYTES,
    MIN_OVERHEAD = DSTU_BOX512_OPEN_MIN_OVERHEAD,
    secret_field = "box512_secret_key_hex",
);
