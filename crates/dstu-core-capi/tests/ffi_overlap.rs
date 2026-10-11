//! T-244(b): an input and an output buffer that share bytes are refused before any slice is formed
//! (a `&[u8]` and a `&mut [u8]` over the same memory is undefined behaviour). Status-returning
//! functions give `DSTU_ERR_INVALID_ARGUMENT`; `void` ones return without writing. Run under Miri:
//! these calls must not form an aliasing pair even on the refused path.

use dstu_core_capi::generichash::*;
use dstu_core_capi::secretbox::*;
use dstu_core_capi::secretstream::*;
use dstu_core_capi::DstuStatus;
use std::ptr;

#[test]
fn in_place_secretbox_seal_is_refused() {
    let mut key = ptr::null_mut();
    assert_eq!(
        unsafe { dstu_secretbox_key_generate(&mut key) },
        DstuStatus::DSTU_OK
    );
    let mut buf = vec![7u8; 256];
    let mut sealed_len = 0usize;
    let status = unsafe {
        dstu_secretbox_seal(
            key,
            buf.as_ptr(),
            16,
            buf.as_mut_ptr(),
            buf.len(),
            &mut sealed_len,
        )
    };
    assert_eq!(status, DstuStatus::DSTU_ERR_INVALID_ARGUMENT);
    assert!(buf.iter().all(|&b| b == 7), "nothing was written");

    // Adjacent, non-overlapping halves of one allocation are fine.
    let (input, output) = buf.split_at_mut(16);
    let status = unsafe {
        dstu_secretbox_seal(
            key,
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut sealed_len,
        )
    };
    assert_eq!(status, DstuStatus::DSTU_OK);
    unsafe { dstu_secretbox_key_free(key) };
}

#[test]
fn overlapping_codec_feed_is_refused() {
    let key = unsafe { dstu_secretstream_key_from_bytes([1u8; 32].as_ptr()) };
    let dec = unsafe { dstu_secretstream_file_decryptor_new(key) };
    let mut buf = vec![2u8; DSTU_SECRETSTREAM_CHUNK_BYTES];
    let mut n = 0usize;
    let status = unsafe {
        dstu_secretstream_file_decryptor_feed(
            dec,
            buf.as_ptr(),
            1,
            buf.as_mut_ptr(),
            buf.len(),
            &mut n,
        )
    };
    assert_eq!(status, DstuStatus::DSTU_ERR_INVALID_ARGUMENT);
    assert_eq!(
        unsafe { dstu_secretstream_file_decryptor_next_len(dec) },
        1,
        "a refused call does not advance the decryptor"
    );
    unsafe { dstu_secretstream_file_decryptor_free(dec) };
    unsafe { dstu_secretstream_key_free(key) };
}

#[test]
fn overlapping_void_hash_leaves_the_output_untouched() {
    let mut buf = vec![9u8; DSTU_GENERICHASH_256_BYTES + 8];
    unsafe { dstu_generichash_256(buf.as_ptr(), 8, buf.as_mut_ptr().add(4)) };
    assert!(buf.iter().all(|&b| b == 9));
}
