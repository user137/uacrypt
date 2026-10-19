//! Black-box integration test for `dstu_core::hazmat::kalyna_kw_p` (T-253, `docs/DECISIONS.md`
//! D-241/D-243): DSTU 7624 annex В.11.x.3/4 vectors (`tests/vectors/kalyna-kw-p/`, four of five
//! variants - 128/256's example is not whole bytes), the §15.5 integrity rules on forged padding,
//! misuse, and the Додаток Г.2 divergence pinned.

use dstu_core::hazmat::kalyna_kw::{Kalyna256_256Kw, KwError};
use dstu_core::hazmat::kalyna_kw_p::{
    Kalyna128_128KwP, Kalyna128_256KwP, Kalyna256_256KwP, Kalyna256_512KwP, Kalyna512_512KwP,
};
use proptest::prelude::*;

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

fn field(text: &str, key: &str) -> Vec<u8> {
    let pattern = format!("\"{key}\": \"");
    let start = text.find(pattern.as_str()).expect("field present") + pattern.len();
    let end = text[start..].find('"').expect("closing quote");
    decode_hex(&text[start..start + end])
}

macro_rules! official_vector_test {
    ($test_name:ident, $variant:ty, $kw:ty, $key_len:literal, $block:literal, $fixture:literal) => {
        #[test]
        fn $test_name() {
            let json = include_str!($fixture);
            let key: [u8; $key_len] = field(json, "key_hex").try_into().expect("key length");
            let plaintext = field(json, "plaintext_hex");
            let kw_input = field(json, "kw_input_hex");
            let ciphertext = field(json, "ciphertext_hex");

            assert_eq!(
                <$variant>::wrapped_len(plaintext.len()),
                Some(ciphertext.len())
            );
            let mut wrapped = vec![0u8; ciphertext.len()];
            <$variant>::wrap(&key, &plaintext, &mut wrapped).expect("wrap");
            assert_eq!(wrapped, ciphertext, "wrap");

            let mut out = vec![0xAAu8; ciphertext.len() - $block];
            let n = <$variant>::unwrap(&key, &ciphertext, &mut out).expect("unwrap");
            assert_eq!(&out[..n], plaintext.as_slice(), "unwrap");
            assert!(out[n..].iter().all(|&b| b == 0), "tail of out is zeroed");

            // The annex's own `padded` line: plain KW unwrap shows the §15.4 layout.
            let mut padded = vec![0u8; ciphertext.len() - $block];
            <$kw>::unwrap(&key, &ciphertext, &mut padded).expect("plain KW unwrap");
            assert_eq!(padded.as_slice(), &kw_input[..ciphertext.len() - $block]);
        }
    };
}

use dstu_core::hazmat::kalyna_kw::{Kalyna128_128Kw, Kalyna256_512Kw, Kalyna512_512Kw};

official_vector_test!(
    kalyna_128_128_kw_p_annex_vector,
    Kalyna128_128KwP,
    Kalyna128_128Kw,
    16,
    16,
    "vectors/kalyna-kw-p/128-128.json"
);
official_vector_test!(
    kalyna_256_256_kw_p_annex_vector,
    Kalyna256_256KwP,
    Kalyna256_256Kw,
    32,
    32,
    "vectors/kalyna-kw-p/256-256.json"
);
official_vector_test!(
    kalyna_256_512_kw_p_annex_vector,
    Kalyna256_512KwP,
    Kalyna256_512Kw,
    64,
    32,
    "vectors/kalyna-kw-p/256-512.json"
);
official_vector_test!(
    kalyna_512_512_kw_p_annex_vector,
    Kalyna512_512KwP,
    Kalyna512_512Kw,
    64,
    64,
    "vectors/kalyna-kw-p/512-512.json"
);

const KEY: [u8; 32] = [0x42; 32];

/// Wraps an arbitrary `padded` buffer with plain KW, as a key holder forging a KW-p ciphertext
/// whose checksum is valid but whose padding is not would.
fn forge(padded: &[u8]) -> Vec<u8> {
    let mut c = vec![0u8; padded.len() + 32];
    Kalyna256_256Kw::wrap(&KEY, padded, &mut c).expect("aligned forge input");
    c
}

/// The honest §15.4 layout for a message of `len` bytes under a 32-byte block.
fn honest_padded(message: &[u8]) -> Vec<u8> {
    let mut p = message.to_vec();
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&(message.len() as u64 * 8).to_le_bytes());
    p.extend_from_slice(&len);
    p.push(0x80);
    while !p.len().is_multiple_of(32) {
        p.push(0);
    }
    p
}

fn assert_rejected(c: &[u8], what: &str) {
    let mut out = vec![0xAAu8; c.len() - 32];
    assert_eq!(
        Kalyna256_256KwP::unwrap(&KEY, c, &mut out),
        Err(KwError::ChecksumMismatch),
        "{what}"
    );
    assert!(out.iter().all(|&b| b == 0), "{what}: out zeroed on failure");
}

#[test]
fn honest_forge_baseline_unwraps() {
    let message: Vec<u8> = (0..48u8).collect();
    let c = forge(&honest_padded(&message));
    let mut out = vec![0u8; c.len() - 32];
    let n = Kalyna256_256KwP::unwrap(&KEY, &c, &mut out).expect("honest layout");
    assert_eq!(&out[..n], message.as_slice());
}

/// DSTU 7624 §15.5 + Б.3: every way the padded block can disagree with §15.4 is the one integrity
/// error, so no padding oracle exists (D-243).
#[test]
fn malformed_padding_is_one_integrity_error() {
    let message: Vec<u8> = (0..48u8).collect();
    let good = honest_padded(&message);
    let marker = 48 + 16;

    let mut p = good.clone();
    p[marker] = 0x81;
    assert_rejected(&forge(&p), "marker 0x81");
    let mut p = good.clone();
    p[marker] = 0x01;
    assert_rejected(&forge(&p), "marker 0x01 (a 1 bit not at the byte's top)");
    let mut p = good.clone();
    p[marker] = 0x00;
    p[marker - 1] = 0x80;
    assert_rejected(&forge(&p), "marker moved into the length field");
    let mut p = good.clone();
    p[48] ^= 0x08;
    assert_rejected(&forge(&p), "length field off by one byte");
    let mut p = good.clone();
    p[48 + 15] = 0x01;
    assert_rejected(&forge(&p), "nonzero top byte of the length field");
    let mut p = good.clone();
    p[marker + 5] = 0x01;
    assert_rejected(&forge(&p), "nonzero byte after the marker");
    assert_rejected(&forge(&[0u8; 96]), "no 1 bit at all");

    let mut p = good.clone();
    p.extend_from_slice(&[0u8; 32]);
    assert_rejected(&forge(&p), "an extra all-zero block (non-minimal padding)");

    // Recovered lengths `wrap` never produces: aligned (KW's case, §15.1) or not over one block.
    for len in [32usize, 64, 16] {
        let m = vec![0x5Au8; len];
        assert_rejected(&forge(&honest_padded(&m)), "length wrap refuses");
    }
}

#[test]
fn tampered_ciphertext_and_wrong_key_are_rejected() {
    let message = [0x11u8; 40];
    let len = Kalyna256_256KwP::wrapped_len(message.len()).expect("valid length");
    let mut c = vec![0u8; len];
    Kalyna256_256KwP::wrap(&KEY, &message, &mut c).expect("wrap");
    for i in [0, len / 2, len - 1] {
        let mut t = c.clone();
        t[i] ^= 0x01;
        assert_rejected(&t, "tampered byte");
    }
    let mut out = vec![0u8; len - 32];
    assert_eq!(
        Kalyna256_256KwP::unwrap(&[0x43; 32], &c, &mut out),
        Err(KwError::ChecksumMismatch)
    );
}

#[test]
fn wrapped_len_refuses_what_kw_p_does_not_take() {
    // §15.4 needs |M| > l; an aligned |M| is plain KW's case (§15.1).
    for len in [0usize, 1, 31, 32, 64, 96] {
        assert_eq!(Kalyna256_256KwP::wrapped_len(len), None, "len {len}");
    }
}

#[test]
fn wrapped_len_covers_the_always_pad_case() {
    // 48 + 16 = 64 is already a multiple of the block: Б.2 still adds a full block (D-241).
    assert_eq!(Kalyna256_256KwP::wrapped_len(48), Some(128));
    assert_eq!(Kalyna256_256KwP::wrapped_len(33), Some(96));
    assert_eq!(Kalyna256_256KwP::wrapped_len(47), Some(96));
    assert_eq!(Kalyna128_128KwP::wrapped_len(18), Some(48));
    // Largest KW input is 20 blocks (kalyna_kw's MAX_R): 20*32 - 16 - 1 = 623 bytes of message.
    assert_eq!(Kalyna256_256KwP::wrapped_len(623), Some(21 * 32));
    assert_eq!(Kalyna256_256KwP::wrapped_len(624), None);
}

#[test]
fn misuse_lengths_are_invalid_length() {
    let mut out = vec![0u8; 128];
    for bad in [&[0u8; 32][..], &[0u8; 64][..], &[0u8; 16][..], &[][..]] {
        assert_eq!(
            Kalyna256_256KwP::wrap(&KEY, bad, &mut out),
            Err(KwError::InvalidLength),
            "plaintext len {}",
            bad.len()
        );
    }
    assert_eq!(
        Kalyna256_256KwP::wrap(&KEY, &[0u8; 48], &mut out[..96]),
        Err(KwError::InvalidLength),
        "out too short"
    );
    let c = vec![0u8; 128];
    assert_eq!(
        Kalyna256_256KwP::unwrap(&KEY, &c, &mut [0u8; 95]),
        Err(KwError::InvalidLength),
        "out not ciphertext minus a block"
    );
    assert_eq!(
        Kalyna256_256KwP::unwrap(&KEY, &c[..64], &mut [0u8; 32]),
        Err(KwError::InvalidLength),
        "two blocks cannot hold a KW-p message"
    );
    assert_eq!(
        Kalyna256_256KwP::unwrap(&KEY, &c[..100], &mut [0u8; 68]),
        Err(KwError::InvalidLength),
        "not block-aligned"
    );
}

/// Додаток Г.2 of DSTU 9041 prints a `t` that is KW over a layout §15.4 does not produce (D-241).
/// This crate follows DSTU 7624, so KW-p refuses it; plain KW shows the document's layout.
#[test]
fn dstu9041_g2_printed_t_is_not_7624_kw_p() {
    let json = include_str!("vectors/dstu9041/g2-worked-example.json");
    let kappa: [u8; 32] = field(json, "kappa_kw_key_hex").try_into().expect("kappa");
    let t = field(json, "printed_t_hex");
    let mut out = vec![0u8; t.len() - 32];
    assert_eq!(
        Kalyna256_256KwP::unwrap(&kappa, &t, &mut out),
        Err(KwError::ChecksumMismatch)
    );
    Kalyna256_256Kw::unwrap(&kappa, &t, &mut out).expect("valid KW checksum");
    assert_eq!(out, field(json, "printed_t_kw_plaintext_hex"));
}

macro_rules! roundtrip_proptest {
    ($mod_name:ident, $variant:ty, $key_len:literal, $block:literal) => {
        mod $mod_name {
            use super::*;
            proptest! {
                #[test]
                fn roundtrip(
                    key in proptest::collection::vec(any::<u8>(), $key_len),
                    message in proptest::collection::vec(any::<u8>(), ($block + 1)..(20 * $block - $block / 2)),
                ) {
                    prop_assume!(message.len() % $block != 0);
                    let key: [u8; $key_len] = key.try_into().expect("key length");
                    let len = <$variant>::wrapped_len(message.len()).expect("valid length");
                    let mut c = vec![0u8; len];
                    <$variant>::wrap(&key, &message, &mut c).expect("wrap");
                    let mut out = vec![0u8; len - $block];
                    let n = <$variant>::unwrap(&key, &c, &mut out).expect("unwrap");
                    prop_assert_eq!(&out[..n], message.as_slice());
                }
            }
        }
    };
}

roundtrip_proptest!(k128_128, Kalyna128_128KwP, 16, 16);
roundtrip_proptest!(k128_256, Kalyna128_256KwP, 32, 16);
roundtrip_proptest!(k256_256, Kalyna256_256KwP, 32, 32);
roundtrip_proptest!(k256_512, Kalyna256_512KwP, 64, 32);
roundtrip_proptest!(k512_512, Kalyna512_512KwP, 64, 64);
