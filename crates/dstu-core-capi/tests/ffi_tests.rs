//! Rust-side FFI boundary tests, calling the `extern "C"` functions directly as a normal
//! dependency (this crate's `rlib` crate-type exists specifically for this, D-148 point 6) - gets
//! Miri coverage for free via `cargo +nightly miri test --workspace` the moment this crate is a
//! workspace member. D-64/D-65's three categories per primitive: correctness (1), rejection (2),
//! misuse (3, including null pointers/undersized buffers/double-finalize). The separate plain-C
//! harness under `c-tests/` proves the *generated header* and a real C compiler round-trip work -
//! this file cannot prove that, only that the underlying `extern "C"` functions behave correctly
//! when called with valid arguments constructed in Rust.

use dstu_core_capi::auth::*;
use dstu_core_capi::generichash::*;
use dstu_core_capi::kdf::*;
use dstu_core_capi::pwhash::*;
use dstu_core_capi::secretbox::*;
use dstu_core_capi::secretstream::*;
use dstu_core_capi::sign::*;
use dstu_core_capi::stream::*;
use dstu_core_capi::{
    dstu_memzero, randombytes::dstu_randombytes_buf, selftest::dstu_selftest, DstuStatus,
};
use std::ptr;

#[test]
fn selftest_passes() {
    assert_eq!(dstu_selftest(), DstuStatus::DSTU_OK);
}

#[test]
fn randombytes_fills_buffer_and_rejects_null_with_nonzero_len() {
    let mut buf = [0u8; 32];
    assert_eq!(
        unsafe { dstu_randombytes_buf(buf.as_mut_ptr(), buf.len()) },
        DstuStatus::DSTU_OK
    );
    assert_ne!(buf, [0u8; 32]);

    // misuse: null pointer with nonzero len
    assert_eq!(
        unsafe { dstu_randombytes_buf(ptr::null_mut(), 32) },
        DstuStatus::DSTU_ERR_NULL_POINTER
    );
    // misuse: null pointer with zero len is a no-op success
    assert_eq!(
        unsafe { dstu_randombytes_buf(ptr::null_mut(), 0) },
        DstuStatus::DSTU_OK
    );
}

#[test]
fn memzero_wipes_buffer() {
    let mut buf = [0xAAu8; 16];
    unsafe { dstu_memzero(buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(buf, [0u8; 16]);

    // misuse: null/zero-length is a documented no-op, not a crash
    unsafe { dstu_memzero(ptr::null_mut(), 0) };
    unsafe { dstu_memzero(ptr::null_mut(), 16) };
}

// ---------------------------------------------------------------------------------------------
// crypto_auth
// ---------------------------------------------------------------------------------------------

#[test]
fn auth_round_trip_and_tamper_rejection() {
    let mut key_ptr: *mut DstuAuthKey = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_auth_key_generate(&mut key_ptr) },
        DstuStatus::DSTU_OK
    );
    assert!(!key_ptr.is_null());

    let message = b"a message both parties want to confirm is unmodified";
    let mut tag = [0u8; DSTU_AUTH_TAG_BYTES];
    unsafe {
        dstu_auth(key_ptr, message.as_ptr(), message.len(), tag.as_mut_ptr());
    }

    // correctness
    assert_eq!(
        unsafe { dstu_auth_verify(key_ptr, message.as_ptr(), message.len(), tag.as_ptr()) },
        DstuStatus::DSTU_OK
    );

    // rejection: tampered message
    let other = b"a different message";
    assert_eq!(
        unsafe { dstu_auth_verify(key_ptr, other.as_ptr(), other.len(), tag.as_ptr()) },
        DstuStatus::DSTU_ERR_TAG_MISMATCH
    );

    // rejection: tampered tag
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert_eq!(
        unsafe { dstu_auth_verify(key_ptr, message.as_ptr(), message.len(), bad_tag.as_ptr()) },
        DstuStatus::DSTU_ERR_TAG_MISMATCH
    );

    unsafe { dstu_auth_key_free(key_ptr) };
    // misuse: double free is not expected to be safe (documented) - not tested.
    unsafe { dstu_auth_key_free(ptr::null_mut()) }; // NULL is a no-op
}

#[test]
fn auth_key_from_bytes_round_trips_and_rejects_null() {
    let bytes = [0x42u8; DSTU_AUTH_KEY_BYTES];
    let key_ptr = unsafe { dstu_auth_key_from_bytes(bytes.as_ptr()) };
    assert!(!key_ptr.is_null());
    let mut out = [0u8; DSTU_AUTH_KEY_BYTES];
    unsafe { dstu_auth_key_bytes(key_ptr, out.as_mut_ptr()) };
    assert_eq!(out, bytes);
    unsafe { dstu_auth_key_free(key_ptr) };

    assert!(unsafe { dstu_auth_key_from_bytes(ptr::null()) }.is_null());
}

// ---------------------------------------------------------------------------------------------
// crypto_kdf
// ---------------------------------------------------------------------------------------------

#[test]
fn kdf_derives_distinct_deterministic_subkeys() {
    let mut key_ptr: *mut DstuKdfMasterKey = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_kdf_master_key_generate(&mut key_ptr) },
        DstuStatus::DSTU_OK
    );

    let ctx = *b"encrypt_";
    let mut sub0 = [0u8; DSTU_KDF_SUBKEY_BYTES];
    let mut sub1 = [0u8; DSTU_KDF_SUBKEY_BYTES];
    let mut sub0_again = [0u8; DSTU_KDF_SUBKEY_BYTES];
    unsafe {
        dstu_kdf_derive_subkey(key_ptr, 0, ctx.as_ptr(), sub0.as_mut_ptr());
        dstu_kdf_derive_subkey(key_ptr, 1, ctx.as_ptr(), sub1.as_mut_ptr());
        dstu_kdf_derive_subkey(key_ptr, 0, ctx.as_ptr(), sub0_again.as_mut_ptr());
    }
    assert_ne!(sub0, sub1);
    assert_eq!(sub0, sub0_again);

    unsafe { dstu_kdf_master_key_free(key_ptr) };
}

// ---------------------------------------------------------------------------------------------
// crypto_generichash
// ---------------------------------------------------------------------------------------------

#[test]
fn generichash_one_shot_matches_streaming() {
    let mut whole = [0u8; DSTU_GENERICHASH_256_BYTES];
    unsafe { dstu_generichash_256(b"hello world".as_ptr(), 11, whole.as_mut_ptr()) };

    let hasher = dstu_kupyna256_hasher_new();
    assert!(!hasher.is_null());
    unsafe {
        dstu_kupyna256_hasher_update(hasher, b"hello ".as_ptr(), 6);
        dstu_kupyna256_hasher_update(hasher, b"world".as_ptr(), 5);
    }
    let mut streamed = [0u8; DSTU_GENERICHASH_256_BYTES];
    assert_eq!(
        unsafe { dstu_kupyna256_hasher_finalize(hasher, streamed.as_mut_ptr()) },
        DstuStatus::DSTU_OK
    );
    assert_eq!(whole, streamed);

    // misuse: finalize twice
    let mut second = [0u8; DSTU_GENERICHASH_256_BYTES];
    assert_eq!(
        unsafe { dstu_kupyna256_hasher_finalize(hasher, second.as_mut_ptr()) },
        DstuStatus::DSTU_ERR_FINALIZED
    );
    unsafe { dstu_kupyna256_hasher_free(hasher) };
}

#[test]
fn generichash_512_one_shot_matches_streaming() {
    let mut whole = [0u8; DSTU_GENERICHASH_512_BYTES];
    unsafe { dstu_generichash_512(b"hello world".as_ptr(), 11, whole.as_mut_ptr()) };

    let hasher = dstu_kupyna512_hasher_new();
    unsafe { dstu_kupyna512_hasher_update(hasher, b"hello world".as_ptr(), 11) };
    let mut streamed = [0u8; DSTU_GENERICHASH_512_BYTES];
    assert_eq!(
        unsafe { dstu_kupyna512_hasher_finalize(hasher, streamed.as_mut_ptr()) },
        DstuStatus::DSTU_OK
    );
    assert_eq!(whole, streamed);
    unsafe { dstu_kupyna512_hasher_free(hasher) };
}

// ---------------------------------------------------------------------------------------------
// crypto_secretbox
// ---------------------------------------------------------------------------------------------

#[test]
fn secretbox_seal_open_round_trip_tamper_rejection_and_undersized_buffers() {
    let mut key_ptr: *mut DstuSecretboxKey = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_secretbox_key_generate(&mut key_ptr) },
        DstuStatus::DSTU_OK
    );

    let plaintext = b"a message worth protecting";
    let mut sealed = vec![0u8; plaintext.len() + DSTU_SECRETBOX_OVERHEAD];
    let mut sealed_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretbox_seal(
                key_ptr,
                plaintext.as_ptr(),
                plaintext.len(),
                sealed.as_mut_ptr(),
                sealed.len(),
                &mut sealed_len,
            )
        },
        DstuStatus::DSTU_OK
    );
    assert_eq!(sealed_len, sealed.len());

    let mut opened = vec![0u8; plaintext.len()];
    let mut opened_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretbox_open(
                key_ptr,
                sealed.as_ptr(),
                sealed_len,
                opened.as_mut_ptr(),
                opened.len(),
                &mut opened_len,
            )
        },
        DstuStatus::DSTU_OK
    );
    assert_eq!(&opened[..opened_len], plaintext);

    // rejection: tampered ciphertext
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut garbage = vec![0u8; plaintext.len()];
    let mut garbage_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretbox_open(
                key_ptr,
                tampered.as_ptr(),
                tampered.len(),
                garbage.as_mut_ptr(),
                garbage.len(),
                &mut garbage_len,
            )
        },
        DstuStatus::DSTU_ERR_TAG_MISMATCH
    );
    assert_eq!(garbage, vec![0u8; plaintext.len()]); // left zeroed, not partially trusted

    // misuse: truncated input
    let mut truncated_out = [0u8; 4];
    let mut truncated_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretbox_open(
                key_ptr,
                sealed.as_ptr(),
                4,
                truncated_out.as_mut_ptr(),
                truncated_out.len(),
                &mut truncated_len,
            )
        },
        DstuStatus::DSTU_ERR_TRUNCATED
    );

    // misuse: undersized output buffer on seal
    let mut small = [0u8; 4];
    let mut small_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretbox_seal(
                key_ptr,
                plaintext.as_ptr(),
                plaintext.len(),
                small.as_mut_ptr(),
                small.len(),
                &mut small_len,
            )
        },
        DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL
    );

    // misuse: undersized output buffer on open
    let mut small_open = [0u8; 4];
    let mut small_open_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_secretbox_open(
                key_ptr,
                sealed.as_ptr(),
                sealed.len(),
                small_open.as_mut_ptr(),
                small_open.len(),
                &mut small_open_len,
            )
        },
        DstuStatus::DSTU_ERR_BUFFER_TOO_SMALL
    );

    unsafe { dstu_secretbox_key_free(key_ptr) };
}

#[test]
fn secretbox_key_from_bytes_round_trips_and_rejects_null() {
    let bytes = [0x11u8; DSTU_SECRETBOX_KEY_BYTES];
    let key_ptr = unsafe { dstu_secretbox_key_from_bytes(bytes.as_ptr()) };
    assert!(!key_ptr.is_null());
    let mut out = [0u8; DSTU_SECRETBOX_KEY_BYTES];
    unsafe { dstu_secretbox_key_bytes(key_ptr, out.as_mut_ptr()) };
    assert_eq!(out, bytes);
    unsafe { dstu_secretbox_key_free(key_ptr) };

    assert!(unsafe { dstu_secretbox_key_from_bytes(ptr::null()) }.is_null());
}

// ---------------------------------------------------------------------------------------------
// crypto_secretstream
// ---------------------------------------------------------------------------------------------

#[test]
fn secretstream_round_trip_tamper_and_finalize_rejection() {
    let mut key_ptr: *mut DstuSecretstreamKey = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_secretstream_key_generate(&mut key_ptr) },
        DstuStatus::DSTU_OK
    );

    let mut push_ptr: *mut DstuPushState = ptr::null_mut();
    let mut header = [0u8; DSTU_SECRETSTREAM_HEADER_BYTES];
    assert_eq!(
        unsafe { dstu_secretstream_push_init(key_ptr, &mut push_ptr, header.as_mut_ptr()) },
        DstuStatus::DSTU_OK
    );
    assert!(!unsafe { dstu_secretstream_push_is_finalized(push_ptr) });

    let plaintext = b"a whole file, conceptually split into chunks";
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; DSTU_SECRETSTREAM_TAG_BYTES];

    // misuse: length mismatch, tested against the still-fresh (not finalized) push state so this
    // actually exercises DSTU_ERR_INVALID_LENGTH rather than being pre-empted by a finalized check.
    let mut dummy_tag = [0u8; DSTU_SECRETSTREAM_TAG_BYTES];
    let mut wrong_len_out = [0u8; 2];
    assert_eq!(
        unsafe {
            dstu_secretstream_push(
                push_ptr,
                DstuTag::DSTU_TAG_MESSAGE,
                plaintext.as_ptr(),
                plaintext.len(),
                wrong_len_out.as_mut_ptr(),
                wrong_len_out.len(),
                dummy_tag.as_mut_ptr(),
            )
        },
        DstuStatus::DSTU_ERR_INVALID_LENGTH
    );

    assert_eq!(
        unsafe {
            dstu_secretstream_push(
                push_ptr,
                DstuTag::DSTU_TAG_FINAL,
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
                tag.as_mut_ptr(),
            )
        },
        DstuStatus::DSTU_OK
    );
    assert!(unsafe { dstu_secretstream_push_is_finalized(push_ptr) });

    // misuse: push after finalize
    let mut dummy_ct = [0u8; 1];
    assert_eq!(
        unsafe {
            dstu_secretstream_push(
                push_ptr,
                DstuTag::DSTU_TAG_MESSAGE,
                b"x".as_ptr(),
                1,
                dummy_ct.as_mut_ptr(),
                1,
                dummy_tag.as_mut_ptr(),
            )
        },
        DstuStatus::DSTU_ERR_FINALIZED
    );

    let pull_ptr = unsafe { dstu_secretstream_pull_init(key_ptr, header.as_ptr()) };
    assert!(!pull_ptr.is_null());
    let mut decrypted = vec![0u8; ciphertext.len()];
    let mut out_tag = DstuTag::DSTU_TAG_MESSAGE;
    assert_eq!(
        unsafe {
            dstu_secretstream_pull(
                pull_ptr,
                DstuTag::DSTU_TAG_FINAL as u8,
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                decrypted.as_mut_ptr(),
                decrypted.len(),
                &mut out_tag,
            )
        },
        DstuStatus::DSTU_OK
    );
    assert_eq!(out_tag, DstuTag::DSTU_TAG_FINAL);
    assert_eq!(decrypted, plaintext);
    assert!(unsafe { dstu_secretstream_pull_is_finalized(pull_ptr) });

    // rejection: tampered ciphertext on a fresh pull state
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;
    let pull2 = unsafe { dstu_secretstream_pull_init(key_ptr, header.as_ptr()) };
    let mut out2 = vec![0u8; tampered.len()];
    let mut out_tag2 = DstuTag::DSTU_TAG_MESSAGE;
    assert_eq!(
        unsafe {
            dstu_secretstream_pull(
                pull2,
                DstuTag::DSTU_TAG_FINAL as u8,
                tampered.as_ptr(),
                tampered.len(),
                tag.as_ptr(),
                out2.as_mut_ptr(),
                out2.len(),
                &mut out_tag2,
            )
        },
        DstuStatus::DSTU_ERR_TAG_MISMATCH
    );
    assert_eq!(out2, vec![0u8; tampered.len()]);

    // misuse: unknown tag byte
    let pull3 = unsafe { dstu_secretstream_pull_init(key_ptr, header.as_ptr()) };
    let mut out3 = vec![0u8; ciphertext.len()];
    let mut out_tag3 = DstuTag::DSTU_TAG_MESSAGE;
    assert_eq!(
        unsafe {
            dstu_secretstream_pull(
                pull3,
                0xFF,
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                out3.as_mut_ptr(),
                out3.len(),
                &mut out_tag3,
            )
        },
        DstuStatus::DSTU_ERR_UNKNOWN_TAG
    );

    unsafe {
        dstu_secretstream_push_free(push_ptr);
        dstu_secretstream_pull_free(pull_ptr);
        dstu_secretstream_pull_free(pull2);
        dstu_secretstream_pull_free(pull3);
        dstu_secretstream_key_free(key_ptr);
    }
}

// ---------------------------------------------------------------------------------------------
// crypto_sign
// ---------------------------------------------------------------------------------------------

#[test]
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
fn sign_verify_round_trip_and_forgery_rejection() {
    let mut key_ptr: *mut DstuSigningKey = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_sign_key_generate(&mut key_ptr) },
        DstuStatus::DSTU_OK
    );
    let verifying_ptr = unsafe { dstu_sign_verifying_key(key_ptr) };
    assert!(!verifying_ptr.is_null());

    let message = b"a message whose origin and integrity matter";
    let mut sig = [0u8; DSTU_SIGN_SIGNATURE_BYTES];
    unsafe { dstu_sign(key_ptr, message.as_ptr(), message.len(), sig.as_mut_ptr()) };

    assert!(unsafe { dstu_verify(verifying_ptr, message.as_ptr(), message.len(), sig.as_ptr()) });

    // rejection: different message
    let other = b"a different message";
    assert!(!unsafe { dstu_verify(verifying_ptr, other.as_ptr(), other.len(), sig.as_ptr()) });

    // rejection: signature from a different key
    let mut other_key_ptr: *mut DstuSigningKey = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_sign_key_generate(&mut other_key_ptr) },
        DstuStatus::DSTU_OK
    );
    let other_verifying_ptr = unsafe { dstu_sign_verifying_key(other_key_ptr) };
    assert!(!unsafe {
        dstu_verify(
            other_verifying_ptr,
            message.as_ptr(),
            message.len(),
            sig.as_ptr(),
        )
    });

    unsafe {
        dstu_sign_key_free(key_ptr);
        dstu_sign_key_free(other_key_ptr);
        dstu_verifying_key_free(verifying_ptr);
        dstu_verifying_key_free(other_verifying_ptr);
    }
}

#[test]
fn sign_key_from_bytes_rejects_zero_scalar() {
    let zero = [0u8; DSTU_SIGN_PRIVATE_KEY_BYTES];
    let mut out: *mut DstuSigningKey = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_sign_key_from_bytes(zero.as_ptr(), &mut out) },
        DstuStatus::DSTU_ERR_INVALID_KEY
    );
    assert!(out.is_null());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
fn sign_digest_matches_sign_of_the_same_hash() {
    let mut key_ptr: *mut DstuSigningKey = ptr::null_mut();
    unsafe { dstu_sign_key_generate(&mut key_ptr) };
    let verifying_ptr = unsafe { dstu_sign_verifying_key(key_ptr) };

    let mut digest = [0u8; DSTU_SIGN_DIGEST_BYTES];
    unsafe { dstu_generichash_256(b"a message".as_ptr(), 9, digest.as_mut_ptr()) };

    let mut sig = [0u8; DSTU_SIGN_SIGNATURE_BYTES];
    unsafe { dstu_sign_digest(key_ptr, digest.as_ptr(), sig.as_mut_ptr()) };
    assert!(unsafe { dstu_verify_digest(verifying_ptr, digest.as_ptr(), sig.as_ptr()) });

    unsafe {
        dstu_sign_key_free(key_ptr);
        dstu_verifying_key_free(verifying_ptr);
    }
}

// ---------------------------------------------------------------------------------------------
// crypto_stream
// ---------------------------------------------------------------------------------------------

#[test]
fn stream_encrypt_decrypt_round_trip_and_silent_tamper() {
    let mut key_ptr: *mut DstuStreamKey = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_stream_key_generate(&mut key_ptr) },
        DstuStatus::DSTU_OK
    );

    let plaintext = b"message";
    let mut sealed = vec![0u8; plaintext.len() + DSTU_STREAM_OVERHEAD];
    let mut sealed_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_stream_encrypt(
                key_ptr,
                plaintext.as_ptr(),
                plaintext.len(),
                sealed.as_mut_ptr(),
                sealed.len(),
                &mut sealed_len,
            )
        },
        DstuStatus::DSTU_OK
    );

    let mut opened = vec![0u8; plaintext.len()];
    let mut opened_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_stream_decrypt(
                key_ptr,
                sealed.as_ptr(),
                sealed_len,
                opened.as_mut_ptr(),
                opened.len(),
                &mut opened_len,
            )
        },
        DstuStatus::DSTU_OK
    );
    assert_eq!(&opened[..opened_len], plaintext);

    // contrast with secretbox: tampering does NOT error, it silently changes the plaintext
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut garbage = vec![0u8; plaintext.len()];
    let mut garbage_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_stream_decrypt(
                key_ptr,
                tampered.as_ptr(),
                tampered.len(),
                garbage.as_mut_ptr(),
                garbage.len(),
                &mut garbage_len,
            )
        },
        DstuStatus::DSTU_OK
    );
    assert_ne!(&garbage[..garbage_len], plaintext);

    // misuse: truncated input
    let mut trunc_out = [0u8; 1];
    let mut trunc_len = 0usize;
    assert_eq!(
        unsafe {
            dstu_stream_decrypt(
                key_ptr,
                sealed.as_ptr(),
                4,
                trunc_out.as_mut_ptr(),
                trunc_out.len(),
                &mut trunc_len,
            )
        },
        DstuStatus::DSTU_ERR_TRUNCATED
    );

    unsafe { dstu_stream_key_free(key_ptr) };
}

// ---------------------------------------------------------------------------------------------
// crypto_pwhash
// ---------------------------------------------------------------------------------------------

#[test]
#[cfg_attr(
    miri,
    ignore = "Argon2id (even Strength::Interactive) is a memory-hard KDF over a 64 MiB buffer - \
              Miri's provenance tracking over that allocation makes this intractably slow to \
              interpret, unrelated to the Point::scalar_multiply ladder issue - see docs/TASKS.md T-175"
)]
fn pwhash_hash_and_verify_round_trip_and_rejects_wrong_password() {
    let password = b"correct horse battery staple";
    // `c_char`, not a hardcoded `i8` - ARM Linux's ABI makes plain `char` unsigned by default
    // (`c_char` resolves to `u8` there), unlike x86-64/macOS/Windows where it's `i8`. A hardcoded
    // `i8` buffer compiled fine on every platform this project developed on until a real aarch64
    // Linux build (the Raspberry Pi check) caught the mismatch against
    // `dstu_pwhash_hash_password`'s own `*mut c_char` parameter.
    let mut out = [0 as std::os::raw::c_char; DSTU_PWHASH_STRBYTES];
    assert_eq!(
        unsafe {
            dstu_pwhash_hash_password(
                password.as_ptr(),
                password.len(),
                DstuPwhashStrength::DSTU_PWHASH_INTERACTIVE,
                out.as_mut_ptr(),
            )
        },
        DstuStatus::DSTU_OK
    );

    assert!(unsafe {
        dstu_pwhash_verify_password(password.as_ptr(), password.len(), out.as_ptr())
    });

    let wrong = b"wrong guess";
    assert!(!unsafe { dstu_pwhash_verify_password(wrong.as_ptr(), wrong.len(), out.as_ptr()) });

    // misuse: malformed hash string
    let garbage = c"not a real phc string";
    assert!(!unsafe {
        dstu_pwhash_verify_password(password.as_ptr(), password.len(), garbage.as_ptr())
    });

    // misuse: null hash
    assert!(!unsafe {
        dstu_pwhash_verify_password(password.as_ptr(), password.len(), ptr::null())
    });
}

// ---------------------------------------------------------------------------------------------
// Cross-cutting misuse: null handles on operations that expect one
// ---------------------------------------------------------------------------------------------

#[test]
fn null_handles_are_rejected_or_return_safe_defaults() {
    assert_eq!(
        unsafe { dstu_auth_key_generate(ptr::null_mut()) },
        DstuStatus::DSTU_ERR_NULL_POINTER
    );
    assert!(unsafe { dstu_sign_verifying_key(ptr::null()) }.is_null());
    assert!(!unsafe { dstu_secretstream_push_is_finalized(ptr::null()) });
    assert!(!unsafe { dstu_secretstream_pull_is_finalized(ptr::null()) });
}
