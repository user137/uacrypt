#![no_main]

use dstu_core::crypto_secretstream::{
    FileDecryptor, FileEncryptor, FileError, Key, CHUNK_BYTES, MAX_RECORD_BYTES,
};
use libfuzzer_sys::fuzz_target;

// T-284: the stream-file codec parses fully attacker-controlled files for uacrypt and all 8
// bindings. It must never panic, and its framing decisions must hold for any input: a file the
// encryptor wrote decrypts to its plaintext, and one byte flipped anywhere is either rejected or
// (never, for an authenticated format) accepted unchanged.

fn decrypt_all(key: &Key, file: &[u8]) -> Result<Vec<u8>, FileError> {
    let mut dec = FileDecryptor::new(key);
    let mut out = vec![0u8; CHUNK_BYTES];
    let mut plaintext = Vec::new();
    let mut pos = 0;
    loop {
        let want = dec.next_len();
        if file.len() - pos < want {
            let n = dec.finish(&mut out)?;
            plaintext.extend_from_slice(&out[..n]);
            return Ok(plaintext);
        }
        let n = dec.feed(&file[pos..pos + want], &mut out)?;
        pos += want;
        plaintext.extend_from_slice(&out[..n]);
    }
}

fn encrypt_all(key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let (mut enc, prefix) = FileEncryptor::init(key).expect("OS CSPRNG available");
    let mut file = prefix.to_vec();
    let mut rest = plaintext;
    let mut record = [0u8; MAX_RECORD_BYTES];
    while rest.len() > CHUNK_BYTES {
        let (chunk, tail) = rest.split_at(CHUNK_BYTES);
        enc.seal_chunk(chunk.try_into().expect("exact chunk"), &mut record)
            .expect("not finalized");
        file.extend_from_slice(&record);
        rest = tail;
    }
    let n = enc.seal_final(rest, &mut record).expect("not finalized");
    file.extend_from_slice(&record[..n]);
    file
}

fuzz_target!(|data: &[u8]| {
    let key = Key::from_bytes([7u8; 32]);

    // Arbitrary bytes as a file: any result, no panic.
    let _ = decrypt_all(&key, data);

    // A real file built from `data` (stretched past one chunk when `data` is long enough to
    // matter), then one byte flipped at a `data`-derived offset.
    let mut plaintext = data.to_vec();
    if let Some(&first) = data.first() {
        plaintext.resize(data.len() + usize::from(first) * 64, first);
    }
    let file = encrypt_all(&key, &plaintext);
    assert_eq!(
        decrypt_all(&key, &file).expect("own output decrypts"),
        plaintext
    );
    if !data.is_empty() {
        let mut tampered = file.clone();
        let at = (usize::from(data[data.len() - 1]) * 131 + data.len()) % tampered.len();
        tampered[at] ^= 0x01;
        assert!(
            decrypt_all(&key, &tampered).is_err(),
            "a flipped byte at {at} was accepted"
        );
    }
});
